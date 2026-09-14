# OAuth2 Deep-Dive Lab — real case, versi unik

Lab Flask lokal yang mengangkat **OAuth 2.0 / OIDC bug yang jarang dibahas di lab umum**, tapi jelas di program **Bug Bounty**. Tiap skenario punya toggle **RENTAN / FIXED**.

- Port: `http://127.0.0.1:5090`

## Skenario (kenapa "unik")
1. **Cross-client code swap (s1)** — Authorization code tidak di-bind ke `client_id`.
   Vulnerabilitas ada di sisi *token endpoint*: code milik `web-app` ditukar oleh `evil-app` dan tetap diterbitkan token. Bedanya dengan lab "missing PKCE": di sini flow-nya *lengkap dan normal*, yang rusak hanya verifikasi binding. (Kelas bug yang pernah muncul di SDK login besar.)
2. **id_token `alg=none` (s2)** — Client app menerima id_token tanpa verifikasi signature.
   Attacker bikin JWT header `{"alg":"none"}`, payload email korban → diterima.
3. **Issuer / tenant confusion (s3)** — App menautkan akun hanya dari email, tidak memvalidasi `iss`.
   Attacker punya IdP sendiri (`attackercloud.io`) yang *sah* menerbitkan id_token ber-email korban. ATO cross-tenant tanpa menyentuh kunci target.
4. **Implicit grant → token di URL → bocor lewat Referer (s4)** — Access token ada di URL, direpost ke query string, lalu Referer ke resource pihak ketiga membocorkannya.

## Yang dipelajari
- **Binding code**: `code → {client_id, redirect_uri, user}`; token endpoint wajib mencocokkan presenter.
- **JWT**: header `alg` jangan pernah di-trust; verifikasi signature + allowlist `alg`.
- **Trust boundary**: `email` ≠ identity. Butuh `iss` + `aud` + verifikasi, bukan sekadar `sub`/`email`.
- **Token hygiene**: token jangan lewat URL; Referrer-Policy; prefer authorization code (+PKCE).
- Menyusun PoC berbasis *raw HTTP request* (lihat `payloads/README.md`).

## Identitas
Provider (`id.corp-test.local`): `victim` (punya flag, tenant corp-test) · `attacker` (attackercloud) · `atk-dup` (email/nama duplikat korban di tenant attackercloud).
Client: `web-app` (korban) vs `evil-app`, **Evil App** di `/evil/*`, webhook penangkap `/evil/ref`.

## Cara jalankan
```
python -m app.main      # dari folder lab — port 5090, browser auto terbuka
```

### Docker (rekomendasi — versi library dijamin konsisten)
```bash
docker compose up -d --build     # buka http://127.0.0.1:5090
docker compose down              # stop
docker compose down -v           # stop + reset database
```
State selalu di-reset ke RENTAN saat container start.