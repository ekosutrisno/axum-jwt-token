use std::sync::Arc;

use axum::{http::StatusCode, response::IntoResponse, routing::get, Extension, Json, Router};
use axum_keycloak_auth::{
    decode::KeycloakToken, error::AuthError, role::KeycloakRole, service::KeycloakAuthLayer,
    PassthroughMode,
};
use jsonwebtoken::DecodingKey;
use serde_json::json;

use crate::schema::ResponseKeycloakToken;

mod schema;

#[tokio::main]
async fn main() {
    let decoding_key = Arc::new(
        create_decoding_key().expect("Public key from which a DecodingKey can be constructed"),
    );

    println!("{:<10} On Port 8000", "Listening");
    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(protected_router(decoding_key).into_make_service())
        .await
        .unwrap();
}

pub fn protected_router(decoding_key: Arc<DecodingKey>) -> Router {
    Router::new().route("/protected", get(protected)).layer(
        KeycloakAuthLayer::<String>::builder()
            .decoding_key(decoding_key)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .required_roles(vec![String::from("admin"), String::from("view-profile")])
            .build(),
    )
}
pub async fn protected(
    Extension(token): Extension<KeycloakToken<String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let response_token = ResponseKeycloakToken {
        expires_at: token.expires_at.to_string(),
        issued_at: token.expires_at.to_string(),
        jwt_id: token.jwt_id,
        issuer: token.issuer,
        audience: token.audience,
        subject: token.subject,
        authorized_party: token.authorized_party,
        roles: token.roles,
        given_name: token.given_name,
        family_name: token.family_name,
        full_name: token.full_name,
        preferred_username: token.preferred_username,
        email: token.email,
        email_verified: token.email_verified,
    };

    let filtered_roles: Vec<_> = response_token
    .roles
    .iter()
    .filter(|role| {
        matches!(role, KeycloakRole::Client { client, .. } if client == &response_token.authorized_party)
    })
    .collect();

    println!("Token payload is {:?}", response_token);
    println!("Filtered roles are {:?}", filtered_roles);

    let user_data = json!({
        "filtered_roles": filtered_roles,
        "user_data": response_token,
    });

    Ok((StatusCode::OK, Json(user_data)))
}
fn create_decoding_key() -> Result<DecodingKey, AuthError> {
    const KC_REALM_PUBLIC_KEY: &str = r#"
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6Rm1949B24xc8fwsKXl3AM0wnWet7ahRiksqDc3XxBd9MbiGDM0tCu/bbMs/Pp77C/HmKLUnhEnATeaCUrBGsGPwmERTALDHc6oluAEO4xycWWIFhmEnuMptvoTt0JTAGsk+heEOH+/MnE+aAQCAgxNC3jW5DKk6V4hIMwKojjFP5iA45tq8ssHu7bs3l4W0BfdBGHNYEmQJg/8EBgHbg7OKso6WQ8VkIykHzDpjOiweRsP/8ahTXeGaIcYxPbPblRXKhKhUBoELw94hK/bhHu26Goqm3cwgIha6CGU3bFTLCDV26MhsThLs2GPGLtxEojfGA+LvpVXXKcKOf101WQIDAQAB
    -----END PUBLIC KEY-----
    "#;

    DecodingKey::from_rsa_pem(KC_REALM_PUBLIC_KEY.as_bytes())
        .map_err(|err| AuthError::CreateDecodingKey { source: err })
}
