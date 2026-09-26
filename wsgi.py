"""Production WSGI entry point. Run one Gunicorn worker with multiple threads."""
import atexit
from http import HTTPStatus
import json
import os
from pathlib import Path
import sqlite3
try:
    from .server import Service, Problem, require
except ImportError:
    from server import Service, Problem, require


def make_app(service):
    def app(environ, start_response):
        try:
            method = environ.get('REQUEST_METHOD', '')
            require(method in ('GET', 'POST'), 'Method not allowed.', 405)
            require(not environ.get('QUERY_STRING'), 'Query parameters are not supported.')
            length = int(environ.get('CONTENT_LENGTH') or '0')
            require(0 <= length <= 262144, 'Request is too large.', 413)
            if method == 'POST':
                require(environ.get('CONTENT_TYPE', '').split(';')[0] == 'application/json', 'Use JSON.', 415)
                body = json.loads(environ['wsgi.input'].read(length))
            else:
                body = {}
            auth = environ.get('HTTP_AUTHORIZATION', '')
            # Proxy headers are not trusted for identity or authorization.
            result = service.dispatch(method, environ.get('PATH_INFO', ''), body,
                                      auth[7:] if auth.startswith('Bearer ') else '', environ.get('REMOTE_ADDR', 'unknown'))
            status = 200
        except Problem as exc:
            status, result = exc.status, {'error': exc.message}
        except (ValueError, TypeError, UnicodeError):
            status, result = 400, {'error': 'Invalid request.'}
        except (sqlite3.Error, OSError):
            status, result = 503, {'error': 'Service unavailable. Retry later.'}
        raw = json.dumps(result, separators=(',', ':')).encode()
        start_response(f'{status} {HTTPStatus(status).phrase}', [('Content-Type', 'application/json'),
                       ('Content-Length', str(len(raw))), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')])
        return [raw]
    return app


def application():
    code = os.environ.get('TASKGATE_JOIN_CODE', '')
    if len(code) < 16:
        raise ValueError('TASKGATE_JOIN_CODE must contain at least 16 random characters.')
    os.umask(0o077)
    path = Path(os.environ.get('TASKGATE_DATABASE', '/var/data/taskgate.sqlite3'))
    path.parent.mkdir(parents=True, exist_ok=True)
    service = Service(path, code)
    atexit.register(service.close)
    return make_app(service)
