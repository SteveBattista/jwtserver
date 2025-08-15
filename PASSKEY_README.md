# Passkey Authentication Support

This JWT server now supports WebAuthn/Passkey authentication as an additional authentication method alongside traditional username/password authentication.

## Features Added

### Server-side Changes
- **New Dependencies**: Added `webauthn-rs`, `uuid`, and updated `base64` for WebAuthn support
- **New Endpoints**:
  - `POST /passkey/register/start` - Initiates passkey registration
  - `POST /passkey/register/finish` - Completes passkey registration
  - `POST /passkey/auth/start` - Initiates passkey authentication
  - `POST /passkey/auth/finish` - Completes passkey authentication and returns JWT token
- **Storage**: Passkey credentials are stored in `passkeys.json` file
- **Security**: Uses RS512 JWT tokens with the same expiration (60 minutes) as password authentication

### Client-side Changes
- **New UI Elements**: Added "Register Passkey" and "Login with Passkey" buttons to the login page
- **WebAuthn Integration**: Full client-side WebAuthn implementation with proper credential handling
- **Base64URL Encoding**: Proper handling of binary data between browser and server

## How to Use

### Prerequisites
1. A modern web browser that supports WebAuthn (Chrome 67+, Firefox 60+, Safari 14+, Edge 18+)
2. An authenticator device (built-in biometric sensor, security key, or platform authenticator)
3. HTTPS connection (for production) or localhost (for testing)

### Registration Process
1. **First-time Setup**: Users must first register with a traditional username/password
2. **Login with Password**: Authenticate once using username/password
3. **Register Passkey**: Click "Register Passkey" button on the login page
   - Enter your username
   - Follow browser prompts to create a passkey
   - The passkey will be stored both on your device and the server

### Authentication Process
1. **Passkey Login**: Click "Login with Passkey" button
2. **Enter Username**: Provide your username to identify which passkey to use
3. **Authenticate**: Follow browser prompts to authenticate with your passkey
4. **JWT Token**: Receive the same JWT token as password authentication

## Security Features

- **Phishing Resistant**: Passkeys are bound to the specific domain and cannot be used on malicious sites
- **No Shared Secrets**: Private keys never leave the user's device
- **Multi-factor by Design**: Combines something you have (device) with something you are (biometric) or something you know (PIN)
- **Replay Attack Protection**: Each authentication creates a unique signature

## API Endpoints

### Passkey Registration

#### Start Registration
```http
POST /passkey/register/start
Content-Type: application/json

{
  "username": "your_username"
}
```

Response: WebAuthn credential creation options

#### Finish Registration
```http
POST /passkey/register/finish
Content-Type: application/json

{
  "username": "your_username",
  "credential": {
    // WebAuthn credential response
  }
}
```

### Passkey Authentication

#### Start Authentication
```http
POST /passkey/auth/start
Content-Type: application/json

{
  "username": "your_username"
}
```

Response: WebAuthn credential request options

#### Finish Authentication
```http
POST /passkey/auth/finish
Content-Type: application/json

{
  "username": "your_username",
  "credential": {
    // WebAuthn authentication response
  }
}
```

Response: JWT token (same format as password authentication)

## File Structure

- `passkeys.json` - Stores registered passkey credentials (created automatically)
- `src/main.rs` - Updated with WebAuthn endpoints and logic
- `static/login.html` - Enhanced with passkey UI and JavaScript
- `Cargo.toml` - Added WebAuthn dependencies

## Testing

1. Start the server: `cargo run`
2. Open http://localhost:4000 in a WebAuthn-compatible browser
3. Register a user with password (if not already done)
4. Register a passkey for the user
5. Test authentication with the passkey

## Notes

- Passkeys are stored per-user and multiple passkeys can be registered per user
- The server requires users to have a traditional password account before registering passkeys
- Passkey authentication returns the same JWT format as password authentication
- All existing API endpoints continue to work unchanged
