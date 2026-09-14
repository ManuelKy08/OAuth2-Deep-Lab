import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, 'database', 'lab.db')

FLAG = 'OAUTH2-LAB{Flag_Advanced_OAuth_Takeover_2217}'


@contextmanager
def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          email TEXT,
          email_verified INTEGER DEFAULT 1,
          tenant TEXT,
          flag TEXT
        );
        CREATE TABLE IF NOT EXISTS clients(
          id TEXT PRIMARY KEY,
          secret TEXT,
          name TEXT,
          redirect_uri TEXT,
          use_implicit INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS authcodes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          code TEXT UNIQUE,
          client_id TEXT,
          redirect_uri TEXT,
          user_id INTEGER,
          scope TEXT,
          used INTEGER DEFAULT 0,
          exp REAL
        );
        CREATE TABLE IF NOT EXISTS tokens(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT UNIQUE,
          user_id INTEGER,
          exp REAL,
          note TEXT
        );
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY,
          vulnerable INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          source TEXT,
          msg TEXT
        );
        ''')


def seed():
    init_db()
    with conn() as c:
        if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n'] == 0:
            c.executemany(
                'INSERT INTO users(username,email,email_verified,tenant,flag) VALUES(?,?,?,?,?)',
                [
                    ('victim', 'victim@corp.test', 1, 'corp-test', FLAG),
                    ('attacker', 'attacker@evil.com', 1, 'attackercloud', None),
                    ('atk-dup', 'victim@corp.test', 1, 'attackercloud', None),
                ])
        if c.execute('SELECT COUNT(*) n FROM clients').fetchone()['n'] == 0:
            c.executemany(
                'INSERT INTO clients(id,secret,name,redirect_uri,use_implicit) VALUES(?,?,?,?,?)',
                [
                    ('web-app', 'web-secret', 'Web App (tidak bersalah)', 'http://127.0.0.1:5090/app/cb', 1),
                    ('evil-app', 'evil-secret', 'Evil App (attacker client)', 'http://127.0.0.1:5090/evil/client/cb', 0),
                ])
        if os.environ.get('LAB_RESET') == '1':
            c.execute('DELETE FROM settings')
        for k in ('s1', 's2', 's3', 's4'):
            c.execute('INSERT OR IGNORE INTO settings(key,vulnerable) VALUES(?,1)', (k,))


def setting(key):
    with conn() as c:
        row = c.execute('SELECT vulnerable FROM settings WHERE key=?', (key,)).fetchone()
        return row['vulnerable'] == 1 if row else True


def set_setting(key, vuln):
    with conn() as c:
        cur = c.execute('UPDATE settings SET vulnerable=? WHERE key=?', (1 if vuln else 0, key))
        if cur.rowcount == 0:
            c.execute('INSERT OR REPLACE INTO settings(key,vulnerable) VALUES(?,?)', (key, 1 if vuln else 0))


def all_settings():
    with conn() as c:
        rows = c.execute('SELECT key, vulnerable FROM settings').fetchall()
        return {r['key']: bool(r['vulnerable']) for r in rows}


def log(source, msg):
    with conn() as c:
        c.execute('INSERT INTO logs(ts,source,msg) VALUES(?,?,?)',
                  (time.strftime('%Y-%m-%d %H:%M:%S'), source, msg))


def last_logs(n=80):
    with conn() as c:
        rows = c.execute('SELECT ts,source,msg FROM logs ORDER BY id DESC LIMIT ?', (n,)).fetchall()
        return [{'ts': r['ts'], 'source': r['source'], 'msg': r['msg']} for r in rows]


def user_by_username(name):
    with conn() as c:
        r = c.execute('SELECT * FROM users WHERE username=?', (name,)).fetchone()
        return dict(r) if r else None


def user_by_email(email):
    with conn() as c:
        r = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        return dict(r) if r else None


def client(id):
    with conn() as c:
        r = c.execute('SELECT * FROM clients WHERE id=?', (id,)).fetchone()
        return dict(r) if r else None


def new_code(client_id, redirect_uri, user, scope):
    code = secrets.token_urlsafe(12)
    with conn() as c:
        c.execute('INSERT INTO authcodes(code,client_id,redirect_uri,user_id,scope,used,exp) VALUES(?,?,?,?,?,0,?)',
                  (code, client_id, redirect_uri, user['id'], scope, time.time() + 600))
    return code


def find_code(token):
    with conn() as c:
        r = c.execute('SELECT * FROM authcodes WHERE code=?', (token,)).fetchone()
        return dict(r) if r else None


def mark_used(code):
    with conn() as c:
        c.execute('UPDATE authcodes SET used=1 WHERE code=?', (code,))


def new_token(user, note=''):
    tok = 'atok_' + secrets.token_hex(16)
    with conn() as c:
        c.execute('INSERT INTO tokens(token,user_id,exp,note) VALUES(?,?,?,?)',
                  (tok, user['id'], time.time() + 3600, note))
    return tok


def user_for_token(tok):
    with conn() as c:
        r = c.execute('SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?', (tok,)).fetchone()
        return dict(r) if r else None