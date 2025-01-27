use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
// Claims structure expected in the JWT
#[derive(Debug, Deserialize, Serialize)]
struct RealmAccess {
    roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    exp: u32,
    iat: u32,
    jti: String,
    iss: String,
    azp: String,
    sid: String,
    scope: String,
    realm_access: RealmAccess,
    session_state: String,
    acr: String,
    platform_id: u32,
    email_verified: bool,
    name: String,
    preferred_username: String,
    given_name: String,
    family_name: String,
    email: String,
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ModulusExponent {
    modulus: String,
    exponent: String,
}

pub async fn get_public_key(
    tenant: &str,
    jwt: &str,
    oidc_server_url: &str,
) -> Result<ModulusExponent, String> {
    let oidc_server_url = Url::parse(oidc_server_url)
        .map_err(|e| e.to_string())?
        .join(&format!("/realms/{}/protocol/openid-connect/certs", tenant))
        .map_err(|e| e.to_string())?
        .to_string();

    log::debug!("Using KC URL {}", oidc_server_url);

    let header = match decode_header(&jwt) {
        Ok(h) => h,
        Err(e) => return Err(format!("Failed to parse header: {}", e).to_string()),
    };

    println!("{:?}", &header);
    // let kid = match header.kid {
    //     Some(k) => k,
    //     None => panic!("Unable to get kid"),
    // };
    // log::debug!("kid {}", &header.kid.unwrap_or("None".to_string()));

    let header = match decode_header(&jwt) {
        Ok(h) => h,
        Err(_) => return Err("Failed to parse header".to_string()),
    };
    let client = Client::new();
    let response = client
        .get(&oidc_server_url)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to fetch public key: HTTP {}",
            response.status()
        ));
    }

    let certs: Value = response.json().await.map_err(|e| e.to_string())?;

    // extract n and e fields that match kid value
    let key = certs["keys"]
        .as_array()
        .ok_or("Failed to extract public key components")?
        .iter()
        .find(|key| key["kid"].as_str().unwrap() == header.kid.as_ref().unwrap())
        .ok_or("Failed to find key for kid")?;

    Ok(ModulusExponent {
        modulus: key["n"].as_str().unwrap().to_string(),
        exponent: key["e"].as_str().unwrap().to_string(),
    })
}

pub fn validate_token(
    token: &str,
    tenant: &str,
    public_key: &ModulusExponent,
    oidc_server_url: &str
) -> Result<TokenData<Claims>, String> {
    let decoding_key =
        DecodingKey::from_rsa_components(public_key.modulus.as_str(), public_key.exponent.as_str())
            .map_err(|_| "Invalid public key")?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 1;
    validation.reject_tokens_expiring_in_less_than = 5;
    validation.set_audience(&["account"]);
    validation.set_issuer(&[format!("{}realms/{}", oidc_server_url, tenant)]);

    decode::<Claims>(token, &decoding_key, &validation).map_err(|e| e.to_string())
}
