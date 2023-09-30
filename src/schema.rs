use axum_keycloak_auth::role::{KeycloakRole, Role};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseKeycloakToken<R: Role> {
    pub expires_at: String,
    pub issued_at: String,
    pub jwt_id: String,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub authorized_party: String,
    pub roles: Vec<KeycloakRole<R>>,
    pub given_name: String,
    pub family_name: String,
    pub full_name: String,
    pub preferred_username: String,
    pub email: String,
    pub email_verified: bool,
}
