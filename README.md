# JWT Authentication Server (Rust + Actix-web)

A minimal JWT authentication server built with Rust and Actix-web.

- JSON Web Tokens signed with HS512 (HMAC-SHA512)
- Passwords stored as Argon2id hashes
- Users loaded from `users.txt`
- Signing secret loaded from `secret.key`
- Endpoints: `/login`, `/user` (auth required), `/protected` (admin-only)
- Listens on `http://127.0.0.1:4000`

## Prerequisites

- Rust (stable) and Cargo
- A strong secret in `secret.key`
- A `users.txt` file with `username:argon2id-hash` lines

## Setup

1. Create a strong secret key file (example commands):

```bash
# Option A: 64 random bytes, base64-encoded
openssl rand -base64 64 > secret.key

# Option B: 64 random bytes hashed with SHA-512 (hex)
python3 - << 'PY'
import os, hashlib
print(hashlib.sha512(os.urandom(64)).hexdigest())
PY
# Copy the printed value into secret.key
```

2. Create users with Argon2id password hashes in `users.txt`.

Format is one user per line:

```text
username:argon2id-encoded-hash
```

Example (generate hashes with Python argon2-cffi):

```bash
python3 -m pip install --user argon2-cffi
python3 - << 'PY'
from argon2 import PasswordHasher
ph = PasswordHasher()  # defaults to Argon2id
for u,p in [('admin','admin'), ('user1','password1'), ('user2','password2')]:
    print(f"{u}:{ph.hash(p)}")
PY
# Paste the three lines into users.txt
```

3. Build and run:

```bash
cargo run
```

Server starts at:

```text
http://127.0.0.1:4000
```

## API

- POST `/login`
  - Body JSON: `{ "username": "admin", "password": "admin" }`
  - Returns: `{ "token": "<JWT>" }`

- GET `/user`
  - Header: `Authorization: Bearer <JWT>`
  - Returns user info if token is valid.

- GET `/protected`
  - Header: `Authorization: Bearer <JWT>`
  - Admin-only (only `sub == "admin"` allowed).

## VS Code REST Client examples

Create `requests.rest` and use:

```http
### Login
POST http://127.0.0.1:4000/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}

### Use the token returned above
GET http://127.0.0.1:4000/user
Authorization: Bearer <token>

GET http://127.0.0.1:4000/protected
Authorization: Bearer <token>
```

## Configuration notes

- Port and bind address are hardcoded in `src/main.rs` at `.bind(("127.0.0.1", 4000))`. Change as needed.
- JWT algorithm: HS512 (configured in `login`, `protected`, and `user`).
- Secret: loaded at startup from `secret.key` and injected via Actix `app_data`.
- Users: loaded from `users.txt` on each login request.

## Security considerations

- Do not commit `secret.key` or `users.txt` to source control.
- Use a long, high-entropy secret (>= 64 random bytes).
- Argon2id hashes embed salt and parameters; keep them strong (default settings are reasonable; tune per your environment).
- Prefer HTTPS in production and rotate your secrets regularly.

## License

MIT (or your choice).
