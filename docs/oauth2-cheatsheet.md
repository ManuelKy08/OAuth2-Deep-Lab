# OAuth 2.0 / OIDC — cheat-sheet bug bounty (fokus kasus "aneh")

## Saat audit, jangan cuma cek: state, redirect_uri, PKCE.
Periksa juga:
- **Treekat code ke client?** Coba tukar code A dgn credential client B.
  ```http
  POST /oauth/token
  grant_type=authorization_code&code=<code_dari_clientA>&client_id=clientB&client_secret=...&redirect_uri=cbB
  ```
- **id_token diverifikasi?** Ubah header jadi `alg:none`, payload email korban.
- **`iss` / `aud` divalidasi?** Coba token dari tenant/IdP lain dengan email yang sama.
- **nonce** dijaga? (state analog di OIDC)
- **Access token keluar dari URL?** `response_type=token`, RejectedReferrer-Policy, log server.

## RSS bounds
- Selalu verifikasi: `alg ∈ {RS256, PS256, ES256}` + signature + `iss`+`aud` + `exp`/`nbf`.
- Jangan ever trust `email` tanpa verifikasi + ikat dengan `sub` yang tetap.
- Authorization code: bind ke (client_id, redirect_uri, PKCE challenge), single-use.
- Token: https, POST body, tidak di log/Rereferer.

## Flow berbahaya yang masih dipakai produksi
- Implicit (token di URL) — ganti ke code flow+PKCE.
- Refresh token scope escalation — validasi scope tidak melebar saat refresh.

## Sources of truth / referensi
- RFC 6749, 8252, 7636 (PKCE), OIDC Core 1.0
- OAuth 2.0 Security BCP (RFC 9700)