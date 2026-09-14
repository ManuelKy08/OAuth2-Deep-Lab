# OAuth2 Deep-Dive Lab

Lab Flask yang mengangkat **OAuth 2.0 / OIDC bug yang jarang dibahas di lab umum**, tapi jelas ada di program **Bug Bounty**. Tiap skenario punya toggle **RENTAN / FIXED**.

> 🔬 Lab lokal / Docker-only — jangan pernah di-deploy ke publik.

## 🧨 Kenapa "unik" — 4 real case

| # | Kasus | Akar masalah | Dampak |
|---|-------|--------------|--------|
| 1 | **Cross-client code swap** | Authorization code tidak di-bind ke `client_id` di token endpoint | Code korban ditukar `evil-app` → token victim. Kelas bug yang pernah muncul di SDK login besar |
| 2 | **id_token `alg=none`** | Client app tidak verifikasi signature id_token | JWT forged `{"alg":"none"}` + email korban → ATO |
| 3 | **Issuer / tenant confusion** | App menautkan akun hanya dari `email`, tanpa cek `iss` | Attacker punya IdP `attackercloud.io` sah ber-email korban → **cross-tenant ATO** |
| 4 | **Implicit grant → token di URL** | Access token di URL + di-query string + Referer bocor | Token trauma ke resource pihak ketiga (`/evil/ref`) |

Identitas: `victim@corp.test` (pemilik flag, tenant corp-test) · `attacker` & `atk-dup` (tenant attackercloud). Client: `web-app` vs `evil-app`.
Flag: `OAUTH2-LAB{...}`.

## 🚀 Menjalankan

### Docker (rekomendasi — versi dijamin konsisten)

```bash
git clone https://github.com/ManuelKy08/OAuth2-Deep-Lab.git
cd OAuth2-Deep-Lab
docker compose up -d --build
```

Buka http://127.0.0.1:5090

```bash
docker compose down          # stop
docker compose down -v       # stop + reset database
docker compose logs -f       # lihat log
```

### Lokal

```bash
python -m venv .venv
.venv\Scripts\activate          # bash: source .venv/bin/activate
pip install -r requirements.txt
python -m app.main              # buka http://127.0.0.1:5090
```

## 🧭 Yang dipelajari
- **Binding code**: `code → {client_id, redirect_uri, user}`; token endpoint wajib mencocokkan presenter.
- **JWT**: header `alg` jangan pernah di-trust; verifikasi signature + allowlist `alg`.
- **Trust boundary**: `email` ≠ identity — butuh `iss` + `aud` + verifikasi, bukan sekadar `sub`/`email`.
- **Token hygiene**: token jangan lewat URL; Referrer-Policy; prefer authorization code (+PKCE).

## Isi repo
```
app/        Flask: routes (provider, client, evil) + models (SQLite) + jwt.py (HS256 helper)
docs/       penjelasan + docs/oauth2-cheatsheet.md
payloads/   set request exploit (curl)
templates, static/   UI neon
```
- Manual: `payloads/README.md` · Cheat-sheet: `docs/oauth2-cheatsheet.md`.
- Semua data di SQLite `database/lab.db`; di Docker state di-reset RENTAN tiap start.

## ⚠️ Warning
- Murni edukasi — jangan di-expose ke internet. Semua kredensial & flag 100% dummy.