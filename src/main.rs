use actix_web::middleware::Logger;
use actix_web::{App, Error, HttpResponse, HttpServer, Responder, web};
use actix_files as fs;
use anyhow::Result;
use argon2::{PasswordHash, PasswordVerifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

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


/// Loads the JWT signing secret from a file.
/// 
/// # Arguments
/// * `path` - The file path containing the secret key
/// 
/// # Returns
/// * `Result<Vec<u8>>` - The secret key as bytes, or an error if the file cannot be read
/// 
/// # Examples
/// ```
/// let secret = load_secret("secret.key")?;
/// ```
fn load_secret(path: &str) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut secret = String::new();
    use std::io::Read;
    reader.read_to_string(&mut secret)?;
    Ok(secret.trim().as_bytes().to_vec())
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

/// Handles user login authentication and JWT token generation.
/// 
/// # Arguments
/// * `auth` - JSON payload containing username and password
/// * `secret` - JWT signing secret loaded from file
/// 
/// # Returns
/// * `HttpResponse` - JSON with JWT token on success, or error message on failure
/// 
/// # Process
/// 1. Loads user database from users.txt
/// 2. Verifies password using Argon2id hashing
/// 3. Generates JWT token with 60-minute expiration
/// 4. Returns token or authentication error
/// 
/// # Examples
/// POST /login with {"username": "admin", "password": "admin"}
async fn login(auth: web::Json<AuthData>, secret: web::Data<Vec<u8>>) -> impl Responder {
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
                let header = Header::new(Algorithm::HS512);
                let token = encode(
                    &header,
                    &claims,
                    &EncodingKey::from_secret(&secret),
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
/// * `secret` - JWT signing secret for token validation
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - Success response for admin users, forbidden/unauthorized for others
/// 
/// # Process
/// 1. Extracts JWT token from Authorization header
/// 2. Validates token signature and expiration
/// 3. Checks if user is "admin"
/// 4. Returns success for admin, forbidden for other valid users
/// 
/// # Examples
/// GET /protected with "Authorization: Bearer <jwt_token>"
async fn protected(req: actix_web::HttpRequest, secret: web::Data<Vec<u8>>) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::HS512);
        if let Ok(token_data) =
            decode::<Claims>(token, &DecodingKey::from_secret(&secret), &validation)
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
/// * `secret` - JWT signing secret for token validation
/// 
/// # Returns
/// * `Result<HttpResponse, Error>` - Success response with user info, or unauthorized error
/// 
/// # Process
/// 1. Extracts JWT token from Authorization header
/// 2. Validates token signature and expiration
/// 3. Returns user information from token claims
/// 
/// # Examples
/// GET /user with "Authorization: Bearer <jwt_token>"
async fn user(req: actix_web::HttpRequest, secret: web::Data<Vec<u8>>) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::HS512);
        if let Ok(token_data) =
            decode::<Claims>(token, &DecodingKey::from_secret(&secret), &validation)
        {
            return Ok(HttpResponse::Ok().json(
                serde_json::json!({"message": "Access granted", "user": token_data.claims.sub}),
            ));
        }
    }
    Ok(HttpResponse::Unauthorized().body("Invalid or missing token"))
}

/// Main application entry point - configures and starts the JWT authentication server.
/// 
/// # Returns
/// * `std::io::Result<()>` - Success or IO error from server startup
/// 
/// # Server Configuration
/// - Loads JWT secret from "secret.key" file
/// - Binds to 127.0.0.1:4000
/// - Serves static files from "./static" directory
/// - Configures API routes: /login, /user, /protected
/// - Sets up request logging middleware
/// 
/// # Routes
/// - `/` - Serves login.html (static files)
/// - `/login` - POST endpoint for authentication
/// - `/user` - GET endpoint for authenticated users
/// - `/protected` - GET endpoint for admin users only
/// 
/// # Examples
/// Server starts at: http://127.0.0.1:4000
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let secret = load_secret("secret.key").expect("Failed to load secret key");
    println!("Starting server at http://127.0.0.1:4000");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(secret.clone()))
            .wrap(Logger::default())
            // API routes
            .route("/login", web::post().to(login))
            .route("/protected", web::get().to(protected))
            .route("/user", web::get().to(user))
            // Static file serving
            .service(fs::Files::new("/", "./static").index_file("login.html"))
    })
    .bind(("127.0.0.1", 4000))?
    .run()
    .await
}
