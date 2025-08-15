use actix_web::middleware::Logger;
use actix_web::{App, Error, HttpResponse, HttpServer, Responder, web};
use actix_files as fs;
use anyhow::Result;
use argon2::{PasswordHash, PasswordVerifier};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// JWT token claims structure containing user identification and expiration.
/// 
/// # Fields
/// * `sub` - Subject (username) of the token holder
/// * `exp` - Expiration timestamp as Unix epoch seconds
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

/// Authentication request payload structure for login endpoint.
/// 
/// # Fields
/// * `username` - User's login identifier
/// * `password` - User's plain text password (validated against Argon2id hash)
#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

/// Passkey registration initiation request
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyRegisterStart {
    username: String,
}

/// Passkey registration completion request
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyRegisterFinish {
    username: String,
    credential: RegisterPublicKeyCredential,
}

/// Passkey authentication initiation request
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyAuthStart {
    username: String,
}

/// Passkey authentication completion request
#[derive(Debug, Serialize, Deserialize)]
struct PasskeyAuthFinish {
    username: String,
    credential: PublicKeyCredential,
}

/// Stored passkey credential data
#[derive(Debug, Serialize, Deserialize, Clone)]
struct StoredPasskey {
    username: String,
    credential_id: String,
    passkey: Passkey,
}


/// Loads the RSA private key from a PEM file for JWT signing.
/// 
/// # Arguments
/// * `path` - The file path containing the RSA private key in PEM format
/// 
/// # Returns
/// * `Result<EncodingKey>` - The encoding key for JWT signing, or an error if the file cannot be read
/// 
/// # Examples
/// ```
/// let private_key = load_private_key("private.pem")?;
/// ```
fn load_private_key(path: &str) -> Result<EncodingKey> {
    let key_data = std::fs::read(path)?;
    let key = EncodingKey::from_rsa_pem(&key_data)?;
    Ok(key)
}

/// Loads the RSA public key from a PEM file for JWT verification.
/// 
/// # Arguments
/// * `path` - The file path containing the RSA public key in PEM format
/// 
/// # Returns
/// * `Result<DecodingKey>` - The decoding key for JWT verification, or an error if the file cannot be read
/// 
/// # Examples
/// ```
/// let public_key = load_public_key("jwt_public.pem")?;
/// ```
fn load_public_key(path: &str) -> Result<DecodingKey> {
    let key_data = std::fs::read(path)?;
    let key = DecodingKey::from_rsa_pem(&key_data)?;
    Ok(key)
}

/// Loads user credentials and their Argon2id password hashes from a file.
/// 
/// # Arguments
/// * `path` - The file path containing user credentials in "username:hash" format
/// 
/// # Returns
/// * `Result<HashMap<String, String>>` - A map of usernames to their password hashes
/// 
/// # File Format
/// Each line should contain: `username:argon2id_hash`
/// 
/// # Examples
/// ```
/// let users = load_user_hashes("users.txt")?;
/// ```
fn load_user_hashes(path: &str) -> Result<HashMap<String, String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut users = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        if let Some((user, hash)) = line.split_once(':') {
            users.insert(user.to_string(), hash.to_string());
        }
    }
    Ok(users)
}

/// Creates a WebAuthn instance for passkey operations
fn create_webauthn() -> Result<Webauthn> {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:4000")?;
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
    Ok(builder.build()?)
}

/// Loads stored passkeys from file
fn load_passkeys() -> Result<HashMap<String, Vec<StoredPasskey>>> {
    let mut passkeys = HashMap::new();
    
    if let Ok(file) = File::open("passkeys.json") {
        let reader = BufReader::new(file);
        if let Ok(stored_passkeys) = serde_json::from_reader::<_, Vec<StoredPasskey>>(reader) {
            for passkey in stored_passkeys {
                passkeys.entry(passkey.username.clone())
                    .or_insert_with(Vec::new)
                    .push(passkey);
            }
        }
    }
    
    Ok(passkeys)
}

/// Saves passkeys to file
fn save_passkeys(passkeys: &HashMap<String, Vec<StoredPasskey>>) -> Result<()> {
    let all_passkeys: Vec<StoredPasskey> = passkeys
        .values()
        .flatten()
        .cloned()
        .collect();
    
    let mut file = File::create("passkeys.json")?;
    let json = serde_json::to_string_pretty(&all_passkeys)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Handles user login authentication and JWT token generation.
/// 
/// # Arguments
/// * `auth` - JSON payload containing username and password
/// * `private_key` - RSA private key for JWT signing
/// 
/// # Returns
/// * `HttpResponse` - JSON with JWT token on success, or error message on failure
/// 
/// # Process
/// 1. Loads user database from users.txt
/// 2. Verifies password using Argon2id hashing
/// 3. Generates JWT token with RS512 algorithm and 60-minute expiration
/// 4. Returns token or authentication error
/// 
/// # Examples
/// POST /login with {"username": "admin", "password": "admin"}
async fn login(auth: web::Json<AuthData>, private_key: web::Data<EncodingKey>) -> impl Responder {
    let Ok(users) = load_user_hashes("users.txt") else {
        return HttpResponse::InternalServerError().body("Failed to load user db");
    };

    if let Some(stored_hash) = users.get(&auth.username) {
        let parsed_hash = PasswordHash::new(stored_hash);
        if let Ok(parsed_hash) = parsed_hash {
            let argon2id = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::default(),
                argon2::Params::default(),
            );
            if argon2id
                .verify_password(auth.password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                let expiration = usize::try_from(
                    chrono::Utc::now()
                        .checked_add_signed(chrono::Duration::minutes(60))
                        .expect("valid timestamp")
                        .timestamp(),
                );
                if expiration.is_err() {
                    return HttpResponse::InternalServerError()
                        .body("Failed to calculate expiration time");
                }
                let claims = Claims {
                    sub: auth.username.clone(),
                    exp: expiration.unwrap(),
                };
                let header = Header::new(Algorithm::RS512);
                let token = encode(
                    &header,
                    &claims,
                    &private_key,
                ).unwrap();
                return HttpResponse::Ok().json(serde_json::json!({"token": token}));
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid credentials")
}

/// Handles admin-only protected endpoint access.
/// 
/// # Arguments
/// * `req` - HTTP request containing Authorization header
/// * `public_key` - RSA public key for JWT token validation
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - Success response for admin users, forbidden/unauthorized for others
/// 
/// # Process
/// 1. Extracts JWT token from Authorization header
/// 2. Validates token signature and expiration using RS512 algorithm
/// 3. Checks if user is "admin"
/// 4. Returns success for admin, forbidden for other valid users
/// 
/// # Examples
/// GET /protected with "Authorization: Bearer <`jwt_token`>"
async fn protected(req: actix_web::HttpRequest, public_key: web::Data<DecodingKey>) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::RS512);
        if let Ok(token_data) =
            decode::<Claims>(token, &public_key, &validation)
        {
            if token_data.claims.sub == "admin" {
                return Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Access granted (admin only)", "user": token_data.claims.sub})));
            }
            return Ok(HttpResponse::Forbidden().body("Only admin can access this endpoint"));
        }
    }
    Ok(HttpResponse::Unauthorized().body("Invalid or missing token"))
}

/// Handles general user endpoint access for any authenticated user.
/// 
/// # Arguments
/// * `req` - HTTP request containing Authorization header
/// * `public_key` - RSA public key for JWT token validation
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - Success response with user info, or unauthorized error
/// 
/// # Process
/// 1. Extracts JWT token from Authorization header
/// 2. Validates token signature and expiration using RS512 algorithm
/// 3. Returns user information from token claims
/// 
/// # Examples
/// GET /user with "Authorization: Bearer <`jwt_token`>"
async fn user(req: actix_web::HttpRequest, public_key: web::Data<DecodingKey>) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::RS512);
        if let Ok(token_data) =
            decode::<Claims>(token, &public_key, &validation)
        {
            return Ok(HttpResponse::Ok().json(
                serde_json::json!({"message": "Access granted", "user": token_data.claims.sub}),
            ));
        }
    }
    Ok(HttpResponse::Unauthorized().body("Invalid or missing token"))
}

/// Returns JWT token information and decoded claims for debugging/inspection.
/// 
/// # Arguments
/// * `req` - HTTP request containing Authorization header
/// * `public_key` - RSA public key for JWT token validation
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - JSON with token details or unauthorized error
/// 
/// # Process
/// 1. Extracts JWT token from Authorization header
/// 2. Validates token signature and expiration using RS512 algorithm
/// 3. Returns token header, claims, and metadata
/// 
/// # Examples
/// GET /token-info with "Authorization: Bearer <`jwt_token`>"
async fn token_info(req: actix_web::HttpRequest, public_key: web::Data<DecodingKey>) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::RS512);
        if let Ok(token_data) =
            decode::<Claims>(token, &public_key, &validation)
        {
            let current_time = usize::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
            let expires_in = token_data.claims.exp.saturating_sub(current_time);
            
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "valid": true,
                "token": token,
                "header": token_data.header,
                "claims": token_data.claims,
                "issued_for": token_data.claims.sub,
                "expires_at": token_data.claims.exp,
                "expires_in_seconds": expires_in,
                "current_time": current_time
            })));
        }
    }
    Ok(HttpResponse::Unauthorized().json(serde_json::json!({
        "valid": false,
        "error": "Invalid or missing token"
    })))
}

/// Validates a JWT token and returns success or failure status.
/// 
/// # Arguments
/// * `token_request` - JSON payload containing the JWT token to validate
/// * `public_key` - RSA public key for JWT token validation
/// 
/// # Returns
/// * `HttpResponse` - JSON with validation result and token status
/// 
/// # Process
/// 1. Extracts token from JSON request body
/// 2. Validates token signature and expiration using RS512 algorithm
/// 3. Returns validation status with reason
/// 
/// # Examples
/// POST /validate-token with {"token": "<`jwt_token`>"}
async fn validate_token(token_request: web::Json<serde_json::Value>, public_key: web::Data<DecodingKey>) -> impl Responder {
    let Some(token) = token_request.get("token").and_then(|t| t.as_str()) else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "valid": false,
            "error": "Missing 'token' field in request body"
        }));
    };

    let validation = Validation::new(Algorithm::RS512);
    match decode::<Claims>(token, &public_key, &validation) {
        Ok(token_data) => {
            let current_time = usize::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
            let expires_in = token_data.claims.exp.saturating_sub(current_time);
            
            HttpResponse::Ok().json(serde_json::json!({
                "valid": true,
                "message": "Token is valid",
                "user": token_data.claims.sub,
                "expires_at": token_data.claims.exp,
                "expires_in_seconds": expires_in,
                "current_time": current_time
            }))
        },
        Err(err) => {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "valid": false,
                "error": format!("Token validation failed: {}", err)
            }))
        }
    }
}

/// Serves the RSA public key for JWT verification at well-known/public.pem
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - The public key in PEM format with appropriate content type
/// 
/// # Process
/// 1. Reads the public key from jwt_public.pem file
/// 2. Returns it with text/plain content type for easy consumption
/// 3. Allows other services to discover and use the public key for JWT verification
/// 
/// # Examples
/// GET /well-known/public.pem
async fn well_known_public_key() -> Result<HttpResponse, Error> {
    match std::fs::read_to_string("jwt_public.pem") {
        Ok(public_key_content) => {
            Ok(HttpResponse::Ok()
                .content_type("text/plain")
                .body(public_key_content))
        },
        Err(_) => {
            Ok(HttpResponse::InternalServerError()
                .body("Failed to read public key file"))
        }
    }
}

/// Initiates passkey registration for a user
async fn passkey_register_start(
    req: web::Json<PasskeyRegisterStart>,
    _passkeys_data: web::Data<Mutex<HashMap<String, Vec<StoredPasskey>>>>,
    challenge_data: web::Data<Mutex<HashMap<String, PasskeyRegistration>>>,
) -> impl Responder {
    let webauthn = match create_webauthn() {
        Ok(wa) => wa,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create WebAuthn instance"),
    };

    // Check if user exists in the traditional auth system
    let Ok(users) = load_user_hashes("users.txt") else {
        return HttpResponse::InternalServerError().body("Failed to load user db");
    };

    if !users.contains_key(&req.username) {
        return HttpResponse::BadRequest().body("User must be registered with password first");
    }

    let user_unique_id = Uuid::new_v4();
    let (ccr, skr) = match webauthn.start_passkey_registration(
        user_unique_id,
        &req.username,
        &req.username,
        None,
    ) {
        Ok((ccr, skr)) => (ccr, skr),
        Err(_) => return HttpResponse::InternalServerError().body("Failed to start registration"),
    };

    // Store the challenge
    let mut challenges = challenge_data.lock().unwrap();
    challenges.insert(req.username.clone(), skr);

    HttpResponse::Ok().json(ccr)
}

/// Completes passkey registration for a user
async fn passkey_register_finish(
    req: web::Json<PasskeyRegisterFinish>,
    passkeys_data: web::Data<Mutex<HashMap<String, Vec<StoredPasskey>>>>,
    challenge_data: web::Data<Mutex<HashMap<String, PasskeyRegistration>>>,
) -> impl Responder {
    let webauthn = match create_webauthn() {
        Ok(wa) => wa,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create WebAuthn instance"),
    };

    // Retrieve the challenge
    let mut challenges = challenge_data.lock().unwrap();
    let skr = match challenges.remove(&req.username) {
        Some(skr) => skr,
        None => return HttpResponse::BadRequest().body("No active registration challenge"),
    };

    let passkey = match webauthn.finish_passkey_registration(&req.credential, &skr) {
        Ok(passkey) => passkey,
        Err(_) => return HttpResponse::BadRequest().body("Failed to verify registration"),
    };

    // Store the passkey
    let stored_passkey = StoredPasskey {
        username: req.username.clone(),
        credential_id: base64::engine::general_purpose::STANDARD.encode(passkey.cred_id()),
        passkey,
    };

    let mut passkeys = passkeys_data.lock().unwrap();
    passkeys.entry(req.username.clone())
        .or_insert_with(Vec::new)
        .push(stored_passkey);

    // Save to file
    if let Err(_) = save_passkeys(&passkeys) {
        return HttpResponse::InternalServerError().body("Failed to save passkey");
    }

    HttpResponse::Ok().json(serde_json::json!({"success": true, "message": "Passkey registered successfully"}))
}

/// Initiates passkey authentication
async fn passkey_auth_start(
    req: web::Json<PasskeyAuthStart>,
    passkeys_data: web::Data<Mutex<HashMap<String, Vec<StoredPasskey>>>>,
    auth_challenge_data: web::Data<Mutex<HashMap<String, PasskeyAuthentication>>>,
) -> impl Responder {
    let webauthn = match create_webauthn() {
        Ok(wa) => wa,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create WebAuthn instance"),
    };

    let passkeys = passkeys_data.lock().unwrap();
    let user_passkeys = match passkeys.get(&req.username) {
        Some(passkeys) => passkeys.iter().map(|sp| sp.passkey.clone()).collect::<Vec<_>>(),
        None => return HttpResponse::BadRequest().body("No passkeys registered for user"),
    };

    let (rcr, auth_state) = match webauthn.start_passkey_authentication(&user_passkeys) {
        Ok((rcr, auth_state)) => (rcr, auth_state),
        Err(_) => return HttpResponse::InternalServerError().body("Failed to start authentication"),
    };

    // Store the challenge
    let mut challenges = auth_challenge_data.lock().unwrap();
    challenges.insert(req.username.clone(), auth_state);

    HttpResponse::Ok().json(rcr)
}

/// Completes passkey authentication and returns JWT token
async fn passkey_auth_finish(
    req: web::Json<PasskeyAuthFinish>,
    _passkeys_data: web::Data<Mutex<HashMap<String, Vec<StoredPasskey>>>>,
    auth_challenge_data: web::Data<Mutex<HashMap<String, PasskeyAuthentication>>>,
    private_key: web::Data<EncodingKey>,
) -> impl Responder {
    let webauthn = match create_webauthn() {
        Ok(wa) => wa,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to create WebAuthn instance"),
    };

    // Retrieve the challenge
    let mut challenges = auth_challenge_data.lock().unwrap();
    let auth_state = match challenges.remove(&req.username) {
        Some(auth_state) => auth_state,
        None => return HttpResponse::BadRequest().body("No active authentication challenge"),
    };

    let _auth_result = match webauthn.finish_passkey_authentication(&req.credential, &auth_state) {
        Ok(auth_result) => auth_result,
        Err(_) => return HttpResponse::BadRequest().body("Failed to verify authentication"),
    };

    // Generate JWT token
    let expiration = usize::try_from(
        chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(60))
            .expect("valid timestamp")
            .timestamp(),
    );
    if expiration.is_err() {
        return HttpResponse::InternalServerError()
            .body("Failed to calculate expiration time");
    }
    
    let claims = Claims {
        sub: req.username.clone(),
        exp: expiration.unwrap(),
    };
    
    let header = Header::new(Algorithm::RS512);
    let token = match encode(&header, &claims, &private_key) {
        Ok(token) => token,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to generate token"),
    };

    HttpResponse::Ok().json(serde_json::json!({"token": token, "passkey_used": true}))
}

/// Main application entry point - configures and starts the JWT authentication server.
/// 
/// # Returns
/// * `std::io::Result<()>` - Success or IO error from server startup
/// 
/// # Server Configuration
/// - Loads RSA private key from "private.pem" file for JWT signing
/// - Loads RSA public key from "`jwt_public.pem`" file for JWT verification
/// - Uses RS512 algorithm for asymmetric JWT authentication
/// - Binds to 0.0.0.0:4000
/// - Serves static files from "./static" directory
/// - Configures API routes: /login, /user, /protected
/// - Sets up request logging middleware
/// 
/// # Routes
/// - `/` - Serves login.html (static files)
/// - `/login` - POST endpoint for authentication
/// - `/user` - GET endpoint for authenticated users
/// - `/protected` - GET endpoint for admin users only
/// - `/token-info` - GET endpoint to inspect JWT token details
/// - `/validate-token` - POST endpoint to validate JWT token
/// - `/well-known/public.pem` - GET endpoint to retrieve the RSA public key for JWT verification
/// - `/passkey/register/start` - POST endpoint to initiate passkey registration
/// - `/passkey/register/finish` - POST endpoint to complete passkey registration
/// - `/passkey/auth/start` - POST endpoint to initiate passkey authentication
/// - `/passkey/auth/finish` - POST endpoint to complete passkey authentication
/// 
/// # Examples
/// Server starts at: <http://0.0.0.0:4000>
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let private_key = load_private_key("private.pem").expect("Failed to load RSA private key");
    let public_key = load_public_key("jwt_public.pem").expect("Failed to load RSA public key");
    
    // Initialize passkey storage
    let passkeys = load_passkeys().unwrap_or_default();
    let passkeys_data = web::Data::new(Mutex::new(passkeys));
    let challenge_data = web::Data::new(Mutex::new(HashMap::<String, PasskeyRegistration>::new()));
    let auth_challenge_data = web::Data::new(Mutex::new(HashMap::<String, PasskeyAuthentication>::new()));
    
    println!("Starting server at http://0.0.0.0:4000");
    println!("Using RSA keys for JWT signing and verification");
    println!("Passkey support enabled");
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(private_key.clone()))
            .app_data(web::Data::new(public_key.clone()))
            .app_data(passkeys_data.clone())
            .app_data(challenge_data.clone())
            .app_data(auth_challenge_data.clone())
            .wrap(Logger::default())
            // API routes
            .route("/login", web::post().to(login))
            .route("/protected", web::get().to(protected))
            .route("/user", web::get().to(user))
            .route("/token-info", web::get().to(token_info))
            .route("/validate-token", web::post().to(validate_token))
            // Passkey routes
            .route("/passkey/register/start", web::post().to(passkey_register_start))
            .route("/passkey/register/finish", web::post().to(passkey_register_finish))
            .route("/passkey/auth/start", web::post().to(passkey_auth_start))
            .route("/passkey/auth/finish", web::post().to(passkey_auth_finish))
            // Well-known endpoints
            .route("/well-known/public.pem", web::get().to(well_known_public_key))
            // Static file serving
            .service(fs::Files::new("/", "./static").index_file("login.html"))
    })
    .bind(("0.0.0.0", 4000))?
    .run()
    .await
}
