# JWT Authentication Server (Rust + Actix-web)

A secure JWT authentication server built with Rust and Actix-web using asymmetric RSA keys.

- JSON Web Tokens signed with RS512 (RSA-SHA512) for enhanced security
- Asymmetric key authentication using RSA private/public key pair
- Passwords stored as Argon2id hashes
- Users loaded from `users.txt`
- RSA private key loaded from `private.pem` for JWT signing
- RSA public key loaded from `jwt_public.pem` for JWT verification
- Endpoints: `/login`, `/user` (auth required), `/protected` (admin-only), `/token-info`, `/validate-token`, `/well-known/public.pem`
- Static file serving with demo login page
- Public key discovery endpoint for distributed JWT verification
- Listens on `http://0.0.0.0:4000`

## Prerequisites

- Rust (stable) and Cargo
- RSA private/public key pair (`private.pem` and `jwt_public.pem`)
- A `users.txt` file with `username:argon2id-hash` lines

## Setup

1. Generate RSA key pair for JWT signing/verification:

    ```bash
    # Generate RSA private key (4096-bit)
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:4096

    # Extract public key from private key
    openssl rsa -pubout -in private.pem -out jwt_public.pem
    ```

    **Security Note**: Keep `private.pem` secure and never share it. The `jwt_public.pem` can be shared for token verification.

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
http://0.0.0.0:4000
```

## API

- POST `/login`
  - Body JSON: `{ "username": "admin", "password": "admin" }`
  - Returns: `{ "token": "<JWT>" }`
  - JWT is signed with RSA private key using RS512 algorithm

- GET `/user`
  - Header: `Authorization: Bearer <JWT>`
  - Returns user info if token is valid (verified with RSA public key).

- GET `/protected`
  - Header: `Authorization: Bearer <JWT>`
  - Admin-only (only `sub == "admin"` allowed).

- GET `/token-info`
  - Header: `Authorization: Bearer <JWT>`
  - Returns detailed token information including claims, expiration, and metadata.

- POST `/validate-token`
  - Body JSON: `{ "token": "<JWT>" }`
  - Returns validation status and token details.

- GET `/well-known/public.pem`
  - Returns the RSA public key in PEM format for JWT verification.
  - Allows other services to discover and retrieve the public key.

- GET `/`
  - Serves static demo login page for testing authentication flow.

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

### Get token information
GET http://127.0.0.1:4000/token-info
Authorization: Bearer <token>

### Validate token
POST http://127.0.0.1:4000/validate-token
Content-Type: application/json

{
  "token": "<token>"
}

### Get public key for verification
GET http://127.0.0.1:4000/well-known/public.pem
```

## Configuration notes

- Port and bind address are configured in `src/main.rs` at `.bind(("0.0.0.0", 4000))`. Change as needed.
- JWT algorithm: RS512 (RSA-SHA512) configured in all JWT operations for enhanced security.
- RSA keys: `private.pem` loaded at startup for signing, `jwt_public.pem` for verification via Actix `app_data`.
- Users: loaded from `users.txt` on each login request.
- Static files: served from `./static` directory with `login.html` as the index page.

## Security considerations

- **Never commit RSA private key (`private.pem`) to source control** - keep it secure and access-controlled.
- Do not commit `users.txt` to source control as it contains password hashes.
- RSA-4096 keys provide excellent asymmetric security; RSA-2048 is minimum recommended for production.
- Asymmetric keys allow for distributed verification without sharing signing secrets.
- Public key (`jwt_public.pem`) can be safely shared for token verification by other services.
- Public key is available via the `/well-known/public.pem` endpoint for automated discovery.
- Argon2id hashes embed salt and parameters; keep them strong (default settings are reasonable).
- Prefer HTTPS in production and rotate your RSA keys regularly.
- Consider using hardware security modules (HSM) for private key protection in production.

## User Management

The project includes a companion CLI tool `user_manager` for managing users in the `users.txt` file:

```bash
cd user_manager
cargo run -- --help
```

See `user_manager/README.md` for detailed usage instructions.

## Demo Pages

Access the demo login interface at `http://0.0.0.0:4000/` to test the authentication flow with a web interface.

## Public Key Discovery

The server provides a `well-known` endpoint for public key discovery:

```bash
# Retrieve the public key for JWT verification
curl http://0.0.0.0:4000/well-known/public.pem
```

This allows other services to automatically discover and retrieve the RSA public key for JWT token verification without manual key distribution.

## License

MIT (or your choice).
