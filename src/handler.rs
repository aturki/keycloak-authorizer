use crate::keycloak;
use crate::token;

// constant error code for header not found error
const HEADER_NOT_FOUND: u16 = 400;

pub struct Error {
    pub code: u16,
    pub message: String,
}

pub async fn handle(tenant: String, jwt: String, oidc_server_url: &str) -> Result<String, Error> {
    let public_key: keycloak::ModulusExponent =
        match keycloak::get_public_key(&tenant, &jwt.as_str(), &oidc_server_url).await {
            Ok(key) => key,
            Err(err) => {
                return Err(Error {
                    message: err,
                    code: HEADER_NOT_FOUND,
                })
            }
        };

    let token_data = match keycloak::validate_token(&jwt, &tenant, &public_key, &oidc_server_url) {
        Ok(claim) => claim.claims,
        Err(message) => {
            return Err(Error {
                message: message,
                code: 401,
            })
        }
    };

    Ok(token::generate_unsigned_jwt_token(&token_data).unwrap())
}
