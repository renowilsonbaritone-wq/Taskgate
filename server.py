#!/usr/bin/env python3
"""TaskGate multi-account sync API. Deploy behind an HTTPS reverse proxy."""
import argparse
from collections import defaultdict, deque
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlsplit


def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def password_hash(password, salt): return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


class Problem(Exception):
    def __init__(self, status, message): self.status, self.message = status, message


def require(condition, message, status=400):
    if not condition: raise Problem(status, message)


def text(value, limit=300):
    require(isinstance(value,str) and 0 < len(value.strip()) <= limit, 'Invalid text field.')
    return value.strip()


class Service:
    def __init__(self, database, join_code, clock=time.time):
        self.clock, self.join_code = clock, join_code
        self.lock = threading.RLock()
        self.attempts = defaultdict(deque)
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL, display TEXT NOT NULL, salt TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, user TEXT REFERENCES users(id), expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, owner TEXT REFERENCES users(id), client_id TEXT NOT NULL, title TEXT NOT NULL, mode TEXT NOT NULL, deadline REAL NOT NULL, updated REAL NOT NULL, synced REAL NOT NULL, UNIQUE(owner,client_id));
        CREATE TABLE IF NOT EXISTS tasks(session TEXT REFERENCES sessions(id), idx INTEGER, text TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT REFERENCES users(id), changed REAL NOT NULL, PRIMARY KEY(session,idx));
        CREATE TABLE IF NOT EXISTS members(session TEXT REFERENCES sessions(id), user TEXT REFERENCES users(id), role TEXT NOT NULL, PRIMARY KEY(session,user));
        CREATE TABLE IF NOT EXISTS invites(hash TEXT PRIMARY KEY, session TEXT REFERENCES sessions(id), recipient TEXT REFERENCES users(id), role TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS members_user ON members(user);
        CREATE INDEX IF NOT EXISTS tasks_session ON tasks(session);
        ''')

    def close(self): self.db.close()
    def one(self, sql, values=()): return self.db.execute(sql,values).fetchone()

    def throttle(self, key, limit):
        now=self.clock()
        # Bounded in-process limits; restart resets them. Proxy should also rate-limit.
        if len(self.attempts)>10000: self.attempts.clear()
        q=self.attempts[key]
        while q and q[0]<now-300: q.popleft()
        require(len(q)<limit,'Too many attempts. Wait five minutes.',429)
        q.append(now)

    def user(self, token):
        row=self.one('SELECT u.* FROM tokens t JOIN users u ON u.id=t.user WHERE t.hash=? AND t.expires>?',(digest(token or ''),self.clock()))
        require(row is not None,'Sign in again.',401)
        return row

    def issue(self, user):
        token=secrets.token_urlsafe(32)
        self.db.execute('DELETE FROM tokens WHERE expires<=?',(self.clock(),))
        self.db.execute('INSERT INTO tokens VALUES(?,?,?)',(digest(token),user['id'],self.clock()+30*86400))
        return {'token':token,'user':{k:user[k] for k in ('id','handle','display')}}

    def access(self, sid, uid, owner=False):
        row=self.one('SELECT s.*,u.handle owner_handle,u.display owner_display FROM sessions s JOIN users u ON u.id=s.owner WHERE s.id=?',(sid,))
        role='owner' if row and row['owner']==uid else None
        if row and role is None:
            membership=self.one('SELECT role FROM members WHERE session=? AND user=?',(sid,uid))
            if membership: role=membership['role']
        require(row is not None and role is not None,'Session not found.',404)
        require(not owner or role=='owner','Only the owner can do that.',403)
        return row,role

    def view(self, sid, uid):
        row,role=self.access(sid,uid)
        tasks=[dict(t) for t in self.db.execute('SELECT t.idx,t.text,t.status,t.changed,u.handle approved_by FROM tasks t LEFT JOIN users u ON u.id=t.approved_by WHERE t.session=? ORDER BY t.idx',(sid,))]
        result={k:row[k] for k in ('id','client_id','title','mode','deadline','updated','synced','owner_handle','owner_display')}
        result.update(role=role,tasks=tasks,active=self.clock()<row['deadline'] and any(t['status']!='done' for t in tasks))
        if role=='owner':
            result['members']=[dict(m) for m in self.db.execute('SELECT u.id,u.handle,u.display,m.role FROM members m JOIN users u ON u.id=m.user WHERE m.session=? ORDER BY u.handle',(sid,))]
            result['pending_invites']=[dict(i) for i in self.db.execute('SELECT u.handle,i.role,i.expires FROM invites i JOIN users u ON u.id=i.recipient WHERE i.session=? AND i.used=0 AND i.expires>?',(sid,self.clock()))]
        return result

    def validate_snapshot(self, body):
        require(isinstance(body,dict),'Expected an object.')
        client_id=text(body.get('client_id'),64)
        require(bool(re.fullmatch(r'[a-f0-9]{32}',client_id)),'Invalid local session identifier.')
        title=text(body.get('title'),150)
        mode=body.get('mode');require(mode in ('self','remote'),'Invalid completion mode.')
        deadline=body.get('deadline')
        require(type(deadline) in (int,float) and math.isfinite(deadline) and 0<deadline<self.clock()+367*86400,'Invalid cutoff.')
        tasks=body.get('tasks')
        require(isinstance(tasks,list) and 1<=len(tasks)<=100,'Enter 1–100 tasks.')
        for task in tasks:
            require(isinstance(task,dict),'Invalid task.')
            text(task.get('text'))
            require(type(task.get('done')) is bool and type(task.get('requested',False)) is bool,'Invalid task status.')
            require(mode!='remote' or not task['done'] or task.get('requested',False),'Remote completion must be reviewed.')
        return client_id,title,mode,float(deadline),tasks

    def sync(self, body, uid):
        client_id,title,mode,deadline,tasks=self.validate_snapshot(body)
        row=self.one('SELECT * FROM sessions WHERE owner=? AND client_id=?',(uid,client_id))
        now=self.clock()
        if row is None:
            require(self.one('SELECT COUNT(*) n FROM sessions WHERE owner=?',(uid,))['n']<1000,'Session limit reached.')
            sid=secrets.token_hex(16)
            self.db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)',(sid,uid,client_id,title,mode,deadline,now,now))
            for idx,t in enumerate(tasks):
                state=('review' if t.get('requested') else 'pending') if mode=='remote' else ('done' if t['done'] else 'pending')
                self.db.execute('INSERT INTO tasks VALUES(?,?,?,?,NULL,?)',(sid,idx,t['text'].strip(),state,now))
        else:
            sid=row['id']
            stored=list(self.db.execute('SELECT * FROM tasks WHERE session=? ORDER BY idx',(sid,)))
            require(mode==row['mode'] and deadline==row['deadline'] and len(tasks)==len(stored) and all(t['text'].strip()==old['text'] for t,old in zip(tasks,stored)),'A shared session’s tasks and cutoff cannot be changed.',409)
            for idx,(t,old) in enumerate(zip(tasks,stored)):
                target='review' if mode=='remote' and t.get('requested') else ('done' if mode=='self' and t['done'] else None)
                if target and old['status']=='pending':
                    self.db.execute('UPDATE tasks SET status=?,changed=? WHERE session=? AND idx=?',(target,now,sid,idx))
                    self.db.execute('UPDATE sessions SET updated=? WHERE id=?',(now,sid))
            self.db.execute('UPDATE sessions SET synced=? WHERE id=?',(now,sid))
        return self.view(sid,uid)

    def dispatch(self, method, path, body=None, token='', ip='local'):
        with self.lock, self.db:
            return self._dispatch(method,path,body or {},token,ip)

    def _dispatch(self, method, path, body, token, ip):
        require(isinstance(body,dict),'Expected an object.')
        if path=='/v1/health' and method=='GET': return {'ok':True,'api':1}
        if path in ('/v1/register','/v1/login') and method=='POST':
            self.throttle(('auth-ip',ip),30)
            handle=text(body.get('handle'),40).lower()
            require(bool(re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,39}',handle)),'Use a username of 3–40 letters, numbers, dots, dashes or underscores.')
            self.throttle(('auth-handle',handle),15)
            password=body.get('password')
            require(isinstance(password,str) and 10<=len(password)<=200,'Passwords must have 10–200 characters.')
            if path=='/v1/register':
                require(hmac.compare_digest(str(body.get('join_code','')),self.join_code),'Invalid server access code.',403)
                require(self.one('SELECT id FROM users WHERE handle=?',(handle,)) is None,'Username unavailable.',409)
                require(self.one('SELECT COUNT(*) n FROM users')['n']<10000,'Account capacity reached.')
                salt=secrets.token_hex(16);uid=secrets.token_hex(16)
                self.db.execute('INSERT INTO users VALUES(?,?,?,?,?)',(uid,handle,text(body.get('display'),80),salt,password_hash(password,salt)))
                return self.issue(self.one('SELECT * FROM users WHERE id=?',(uid,)))
            user=self.one('SELECT * FROM users WHERE handle=?',(handle,))
            candidate=password_hash(password,user['salt'] if user else '00'*16)
            require(user is not None and hmac.compare_digest(candidate,user['password']),'Incorrect username or password.',401)
            return self.issue(user)
        user=self.user(token);uid=user['id']
        self.throttle(('user',uid),1500)
        if path=='/v1/logout' and method=='POST':
            self.db.execute('DELETE FROM tokens WHERE hash=?',(digest(token),));return {'ok':True}
        if path=='/v1/me' and method=='GET': return {k:user[k] for k in ('id','handle','display')}
        if path=='/v1/sessions' and method=='GET':
            rows=self.db.execute('SELECT DISTINCT s.id FROM sessions s LEFT JOIN members m ON m.session=s.id WHERE s.owner=? OR m.user=? ORDER BY s.updated DESC LIMIT 100',(uid,uid)).fetchall()
            summaries=[]
            for r in rows:
                view=self.view(r['id'],uid)
                view['task_count']=len(view['tasks'])
                view['done_count']=sum(t['status']=='done' for t in view['tasks'])
                for field in ('tasks','members','pending_invites'): view.pop(field,None)
                summaries.append(view)
            return {'sessions':summaries}
        if path=='/v1/sync' and method=='POST': return self.sync(body,uid)
        if path=='/v1/invites/accept' and method=='POST':
            code=text(body.get('code'),100)
            invite=self.one('SELECT * FROM invites WHERE hash=?',(digest(code),))
            require(invite is not None and invite['recipient']==uid and not invite['used'] and invite['expires']>self.clock(),'Invitation is invalid, expired, used, or intended for another account.',403)
            require(self.one('SELECT COUNT(*) n FROM members WHERE session=?',(invite['session'],))['n']<100 or self.one('SELECT role FROM members WHERE session=? AND user=?',(invite['session'],uid)) is not None,'Participant limit reached.')
            self.db.execute('INSERT INTO members VALUES(?,?,?) ON CONFLICT(session,user) DO UPDATE SET role=excluded.role',(invite['session'],uid,invite['role']))
            self.db.execute('UPDATE invites SET used=1 WHERE hash=?',(digest(code),))
            return self.view(invite['session'],uid)
        match=re.fullmatch(r'/v1/sessions/([a-f0-9]{32})(?:/(invite|revoke|approve))?',path)
        require(match is not None,'Not found.',404)
        sid,action=match.groups();row,role=self.access(sid,uid)
        if method=='GET' and action is None: return self.view(sid,uid)
        require(method=='POST','Method not allowed.',405)
        if action=='invite':
            require(role=='owner','Only the owner may invite people.',403)
            target=text(body.get('handle'),40).lower()
            recipient=self.one('SELECT id FROM users WHERE handle=?',(target,))
            require(recipient is not None and recipient['id']!=uid,'Invite another registered username.')
            chosen=body.get('role');require(chosen in ('viewer','approver'),'Choose viewer or approver.')
            require(chosen!='approver' or row['mode']=='remote','This session uses owner checkoff. Only viewers can be invited.')
            require(self.one('SELECT COUNT(*) n FROM members WHERE session=?',(sid,))['n']<100,'Participant limit reached.')
            self.db.execute('UPDATE invites SET used=1 WHERE session=? AND recipient=?',(sid,recipient['id']))
            code=secrets.token_urlsafe(32);expires=self.clock()+7*86400
            self.db.execute('INSERT INTO invites VALUES(?,?,?,?,?,0)',(digest(code),sid,recipient['id'],chosen,expires))
            return {'code':code,'expires':expires,'recipient':target,'role':chosen}
        if action=='revoke':
            require(role=='owner','Only the owner may revoke access.',403)
            target=text(body.get('handle'),40).lower()
            recipient=self.one('SELECT id FROM users WHERE handle=?',(target,))
            require(recipient is not None and recipient['id']!=uid,'Invalid participant.')
            self.db.execute('DELETE FROM members WHERE session=? AND user=?',(sid,recipient['id']))
            self.db.execute('UPDATE invites SET used=1 WHERE session=? AND recipient=?',(sid,recipient['id']))
            return self.view(sid,uid)
        if action=='approve':
            require(role=='approver' and row['owner']!=uid and row['mode']=='remote','Only an invited approver may approve tasks.',403)
            require(self.clock()<row['deadline'],'The session cutoff has passed.',409)
            idx=body.get('index');require(type(idx) is int,'Invalid task index.')
            task=self.one('SELECT * FROM tasks WHERE session=? AND idx=?',(sid,idx))
            require(task is not None and task['status'] in ('review','done'),'The owner must submit this task for review first.',409)
            if task['status']!='done':
                self.db.execute('UPDATE tasks SET status=?,approved_by=?,changed=? WHERE session=? AND idx=?',('done',uid,self.clock(),sid,idx))
                self.db.execute('UPDATE sessions SET updated=? WHERE id=?',(self.clock(),sid))
            return self.view(sid,uid)
        raise Problem(404,'Not found.')


class Handler(BaseHTTPRequestHandler):
    server_version='TaskGateSync/1'
    def setup(self): super().setup();self.connection.settimeout(10)
    def log_message(self,*_): pass
    def reply(self, status, value):
        payload=json.dumps(value,separators=(',',':')).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers();self.wfile.write(payload)
    def handle_api(self):
        try:
            require(not urlsplit(self.path).query,'Query parameters are not supported.')
            length=int(self.headers.get('Content-Length','0'))
            require(0<=length<=262144,'Request is too large.',413)
            if self.command=='POST':
                require(self.headers.get('Content-Type','').split(';')[0]=='application/json','Use JSON.',415)
                body=json.loads(self.rfile.read(length))
            else: body={}
            auth=self.headers.get('Authorization','')
            token=auth[7:] if auth.startswith('Bearer ') else ''
            self.reply(200,self.server.service.dispatch(self.command,self.path,body,token,self.client_address[0]))
        except Problem as exc: self.reply(exc.status,{'error':exc.message})
        except (ValueError,TypeError,UnicodeError): self.reply(400,{'error':'Invalid request.'})
        except (sqlite3.Error,OSError): self.reply(503,{'error':'Service unavailable. Retry later.'})
    do_GET=handle_api
    do_POST=handle_api


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8787)
    parser.add_argument('--database',default='taskgate-sync.sqlite3')
    args=parser.parse_args()
    join_code=os.environ.get('TASKGATE_JOIN_CODE','')
    if len(join_code)<16: raise SystemExit('Set TASKGATE_JOIN_CODE to a random access code of at least 16 characters.')
    os.umask(0o077)
    service=Service(args.database,join_code)
    server=ThreadingHTTPServer((args.host,args.port),Handler);server.service=service;server.daemon_threads=True
    try: server.serve_forever()
    finally: server.server_close();service.close()

if __name__=='__main__':main()
