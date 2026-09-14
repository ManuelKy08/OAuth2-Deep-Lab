import base64
import hashlib
import hmac
import json

CORP_ISSUER = 'https://id.corp-test.local'
CORP_SECRET = 'corp-test-signing-secret-76a1'   # rahasia milik IdP korban (tenant corp.test)
ATK_SECRET = 'attackercloud-signing-secret-001'  # rahasia milik IdP penyerang (tenant attackercloud.io)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def sign(secret: str, header: dict, payload: dict) -> str:
    h = _b64u(json.dumps(header, separators=(',', ':')).encode())
    p = _b64u(json.dumps(payload, separators=(',', ':')).encode())
    sig = hmac.new(secret.encode(), (h + '.' + p).encode(), hashlib.sha256).digest()
    return h + '.' + p + '.' + _b64u(sig)


def decode(token: str):
    """Mengembalikan (header, payload). Tidak memverifikasi apa-apa."""
    try:
        h, p, _ = token.split('.')
        return json.loads(_b64d(h)), json.loads(_b64d(p))
    except Exception:
        return {}, {}


def verify(token: str, secret: str) -> bool:
    try:
        h, p, s = token.split('.')
        raw = (h + '.' + p).encode()
        expected = _b64u(hmac.new(secret.encode(), raw, hashlib.sha256).digest())
        return hmac.compare_digest(expected, s)
    except Exception:
        return False


def issuer_id_token(secret: str, issuer: str, username: str, email: str,
                    email_verified: bool, audience: str, extra=None) -> str:
    header = {'typ': 'JWT', 'alg': 'HS256'}
    payload = {'iss': issuer, 'sub': username, 'aud': audience,
               'email': email, 'email_verified': 1 if email_verified else 0,
               'name': username, 'iat': 1}
    if extra:
        payload.update(extra)
    return sign(secret, header, payload)


def forged_alg_none(payload: dict) -> str:
    h = _b64u(b'{"alg":"none","typ":"JWT"}')
    p = _b64u(json.dumps(payload, separators=(',', ':')).encode())
    return h + '.' + p + '.'