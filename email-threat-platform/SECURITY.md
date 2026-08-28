# Security checklist before production

- Deploy only behind HTTPS.
- Restrict CORS to the real frontend origin.
- Add authentication and role-based access control.
- Store OAuth tokens in an encrypted secret store, not source control.
- Keep uploaded mail outside the public web root.
- Keep strict file-size/type limits and random server-side filenames.
- Never render raw email HTML directly in the dashboard; sanitize it if a future UI displays it.
- Never fetch attacker-controlled URLs from the server without a dedicated, isolated URL-analysis service.
- Add antivirus/sandbox scanning for attachments before any future extraction beyond safe metadata/hash operations.
- Use parameterized SQL queries / an ORM; never concatenate user input into SQL.
- Add rate limiting, audit logging, CSRF protections where applicable, security headers, dependency scanning and automated tests.
- Minimize email-body retention and document any external AI processing.
