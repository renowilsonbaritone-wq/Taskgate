#!/usr/bin/env python3
"""Host administrator: consistent database backup and password recovery."""
import argparse
import getpass
import os
from pathlib import Path
import secrets
import sqlite3
from server import password_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', default=os.environ.get('TASKGATE_DATABASE', '/var/data/taskgate.sqlite3'))
    sub = parser.add_subparsers(dest='action', required=True)
    backup = sub.add_parser('backup'); backup.add_argument('destination')
    reset = sub.add_parser('reset-password'); reset.add_argument('username')
    args = parser.parse_args()
    os.umask(0o077)
    source = sqlite3.connect('file:' + str(Path(args.database).resolve()) + '?mode=rw', uri=True)
    try:
        if args.action == 'backup':
            destination = Path(args.destination)
            with destination.open('xb'): pass
            try:
                target = sqlite3.connect(destination)
                try: source.backup(target)
                finally: target.close()
            except Exception:
                destination.unlink(missing_ok=True)
                raise
            print('Consistent backup saved. Store it securely off the server.')
        else:
            password = getpass.getpass('New password (10–200 characters): ')
            if not 10 <= len(password) <= 200 or password != getpass.getpass('Repeat password: '):
                raise ValueError('Passwords must match and contain 10–200 characters.')
            row = source.execute('SELECT id FROM users WHERE handle=?', (args.username.lower(),)).fetchone()
            if row is None: raise ValueError('Account not found.')
            salt = secrets.token_hex(16)
            with source:
                source.execute('UPDATE users SET salt=?,password=? WHERE id=?', (salt, password_hash(password, salt), row[0]))
                source.execute('DELETE FROM tokens WHERE user=?', (row[0],))
            print('Password changed and all account sessions revoked. Sign in again on each device.')
    finally:
        source.close()


if __name__ == '__main__': main()
