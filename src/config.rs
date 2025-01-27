use dotenvy;
use log;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub host: String,
    pub oidc_server_url: String,
    pub realm_header: Option<String>,
    pub log_level: String,
}

pub fn load_config() -> Result<Config, String> {
    dotenvy::dotenv_override().unwrap();

    let port = env::var("PORT")
        .unwrap_or("8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a number in the range 1 - 65536");

    let host = env::var("HOST").unwrap_or("127.0.0.1".to_string());
    let log_level = env::var("LOG_LEVEL").unwrap_or("debug".to_string());

    let realm_header = env::var("REALM_HEADER").unwrap_or("".to_string());

    let keycloak_url = env::var("KEYCLOAK_URL").unwrap_or("".to_string());

    if keycloak_url.len() == 0 {
        return Err("Invalid JWT_URL".to_string());
    }

    let config = Config {
        port,
        host,
        oidc_server_url: keycloak_url,
        realm_header: if realm_header.len() > 0 {
            Some(realm_header)
        } else {
            None
        },
        log_level,
    };

    log::debug!("{:?}", config);

    Ok(config)
}
