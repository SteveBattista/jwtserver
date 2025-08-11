use actix_web::middleware::Logger;
use actix_web::{App, Error, HttpResponse, HttpServer, Responder, web};
use anyhow::Result;
use argon2::{PasswordHash, PasswordVerifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    username: String,
    password: String,
}

const SECRET: &[u8] = b"secret_key_change_me";

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

async fn login(auth: web::Json<AuthData>) -> impl Responder {
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
                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(SECRET),
                )
                .unwrap();
                return HttpResponse::Ok().json(serde_json::json!({"token": token}));
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid credentials")
}

async fn protected(req: actix_web::HttpRequest) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::HS256);
        if let Ok(token_data) =
            decode::<Claims>(token, &DecodingKey::from_secret(SECRET), &validation)
        {
            if token_data.claims.sub == "admin" {
                return Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Access granted (admin only)", "user": token_data.claims.sub})));
            }
            return Ok(HttpResponse::Forbidden().body("Only admin can access this endpoint"));
        }
    }
    Ok(HttpResponse::Unauthorized().body("Invalid or missing token"))
}

async fn user(req: actix_web::HttpRequest) -> Result<HttpResponse, Error> {
    let auth_header = req.headers().get("Authorization");
    if let Some(header_value) = auth_header
        && let Ok(auth_str) = header_value.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let validation = Validation::new(Algorithm::HS256);
        if let Ok(token_data) =
            decode::<Claims>(token, &DecodingKey::from_secret(SECRET), &validation)
        {
            return Ok(HttpResponse::Ok().json(
                serde_json::json!({"message": "Access granted", "user": token_data.claims.sub}),
            ));
        }
    }
    Ok(HttpResponse::Unauthorized().body("Invalid or missing token"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    println!("Starting server at http://127.0.0.1:8080");
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/login", web::post().to(login))
            .route("/protected", web::get().to(protected))
            .route("/user", web::get().to(user))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
