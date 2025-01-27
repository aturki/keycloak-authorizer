use crate::keycloak::Claims;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

#[inline]
pub fn parse_token_from_header(authorization_token: String) -> Result<String, String> {
    if authorization_token.len() >= 8 && &(authorization_token[0..7]) == "Bearer " {
        return Ok(authorization_token[7..].to_string());
    }
    Err("Authorization header must start with `Bearer`".to_string())
}

#[inline]
pub fn generate_unsigned_jwt_token(claims: &Claims) -> Result<String, String> {
    let header = Header::new(Algorithm::HS256);
    let token = encode(&header, claims, &EncodingKey::from_secret("".as_ref()))
        .map_err(|e| e.to_string())?;
    Ok(token)
}
