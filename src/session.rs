//! In-memory admin session store and password hashing helpers.
//!
//! Sessions live only in process memory and never expire (a restart drops all
//! of them). The store sits behind a `std::sync::RwLock` because every critical
//! section is a tiny `HashMap` operation that never spans an `.await`, which in
//! turn lets the [`AuthSession`] extractor stay fully synchronous.

use std::collections::HashMap;
use std::future::{ready, Ready};
use std::sync::{Arc, RwLock};

use actix_web::{dev::Payload, web::Data, FromRequest, HttpRequest};
use argon2::password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::APIError;

/// Name of the cookie carrying the session token.
pub const SESSION_COOKIE: &str = "admin_session";

/// A single authenticated admin session. Sessions never expire, so there is no
/// expiry metadata to track here.
#[derive(Clone)]
pub struct Session {
    pub login: String,
}

/// Thread-safe, in-memory map of session token -> [`Session`].
#[derive(Clone, Default)]
pub struct SessionStore(Arc<RwLock<HashMap<String, Session>>>);

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new session for `login` and return its freshly generated token.
    pub fn create(&self, login: String) -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        let session = Session { login };
        self.0
            .write()
            .expect("session store lock poisoned")
            .insert(token.clone(), session);
        token
    }

    /// Look up a session by token.
    pub fn get(&self, token: &str) -> Option<Session> {
        self.0
            .read()
            .expect("session store lock poisoned")
            .get(token)
            .cloned()
    }

    /// Remove a session by token (logout).
    pub fn remove(&self, token: &str) {
        self.0
            .write()
            .expect("session store lock poisoned")
            .remove(token);
    }
}

/// Hash a plaintext password into an argon2 PHC string.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("Failed to hash password: {err}"))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against an argon2 PHC string. Returns `Ok(false)`
/// on a mismatch and `Err` only when the stored hash cannot be parsed.
pub fn verify_password(hash: &str, password: &str) -> anyhow::Result<bool> {
    let parsed =
        PasswordHash::new(hash).map_err(|err| anyhow::anyhow!("Invalid password hash: {err}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Request guard that authenticates the caller via the session cookie.
///
/// Yields `Err(APIError::Unauthorized)` when the cookie is missing or the token
/// is unknown, so any handler taking it as an argument is implicitly protected.
pub struct AuthSession {
    pub login: String,
}

impl FromRequest for AuthSession {
    type Error = APIError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token = req.cookie(SESSION_COOKIE).map(|c| c.value().to_string());
        let store = req.app_data::<Data<SessionStore>>();

        let session = match (token, store) {
            (Some(token), Some(store)) => store.get(&token),
            _ => None,
        };

        match session {
            Some(session) => ready(Ok(AuthSession {
                login: session.login,
            })),
            None => ready(Err(APIError::Unauthorized)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let hash = hash_password("secret").unwrap();
        assert!(verify_password(&hash, "secret").unwrap());
        assert!(!verify_password(&hash, "wrong").unwrap());
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(verify_password("not-a-hash", "secret").is_err());
    }

    #[test]
    fn store_crud() {
        let store = SessionStore::new();
        let token = store.create("admin".to_string());
        assert_eq!(store.get(&token).map(|s| s.login).as_deref(), Some("admin"));
        store.remove(&token);
        assert!(store.get(&token).is_none());
    }

    #[test]
    fn tokens_are_unique_and_sized() {
        let store = SessionStore::new();
        let a = store.create("admin".to_string());
        let b = store.create("admin".to_string());
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
        assert_ne!(a, b);
    }
}
