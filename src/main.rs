#[allow(non_snake_case)]
use actix_web::web::Data;
use actix_web::{
    get, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use config::Config;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::{sync::Mutex, time::Duration};

mod config;
mod handler;
mod keycloak;
mod token;

#[derive(Serialize)]
struct SuccessResponse {
    token: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    code: u16,
}

#[get("/auth")]
async fn auth(req: HttpRequest) -> impl Responder {
    let configuration = req
        .app_data::<Data<Mutex<config::Config>>>()
        .unwrap()
        .lock()
        .unwrap();

    log::info!("Got Headers {:?}", req.headers());
    log::info!(
        "Using header {} to identify realm",
        &configuration.realm_header.as_ref().unwrap().as_str()
    );

    let tenant = match configuration.realm_header.clone() {
        Some(realm_header) => req
            .headers()
            .get(realm_header.as_str())
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
        None => "master".to_string(),
    };

    let jwt: String = match token::parse_token_from_header(
        req.headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
    ) {
        Ok(jwt) => jwt,
        Err(_) => {
            return HttpResponse::ExpectationFailed().json(ErrorResponse {
                message: "Authorization Header Not Found".to_string(),
                code: 403,
            })
        }
    };

    let result = handler::handle(tenant, jwt, &configuration.oidc_server_url).await;

    match result {
        Ok(value) => return HttpResponse::Ok().json(SuccessResponse { token: value }),
        Err(e) => {
            return HttpResponse::ExpectationFailed().json(ErrorResponse {
                message: e.message,
                code: e.code,
            })
        }
    }
}

async fn auth_on_lambda(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let (event, _context) = event.into_parts();
    let realm_header: String = env::var("REALM_HEADER")?;
    let oidc_server_url: String = env::var("KEYCLOAK_URL")?;

    let tenant = event
        .get("headers")
        .unwrap()
        .get(realm_header.as_str())
        .unwrap().as_str().unwrap().to_string();

    log::debug!("tenant: `{}`", tenant);

    let jwt: String = match token::parse_token_from_header(
        event
        .get("headers")
        .unwrap()
        .get("Authorization")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string(),
    ) {
        Ok(jwt) => jwt,
        Err(e) => {
            return Err(e.into())
        }
    };

    let result = handler::handle(tenant.to_string(), jwt, &oidc_server_url.as_str()).await;

    match result {
        Ok(value) => return Ok(json!(SuccessResponse { token: value })),
        Err(e) => {
            return Err(Error::from(e.message));
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let conf = match config::load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!("{:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Can not bind to address.",
            ));
        }
    };

    env_logger::init_from_env(env_logger::Env::new().default_filter_or(&conf.log_level));

    let data = web::Data::new(Mutex::new(Config {
        port: conf.port.clone(),
        host: conf.host.clone(),
        oidc_server_url: conf.oidc_server_url.clone(),
        realm_header: conf.realm_header.clone(),
        log_level: conf.log_level.clone(),
    }));

    let is_running_on_lambda = true;

    if is_running_on_lambda {
        let func = service_fn(|event: LambdaEvent<Value>| auth_on_lambda(event));
        match lambda_runtime::run(func).await {
            Ok(result) => Ok(result),
            Err(e) => {
                log::error!("Error: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ));
            }
        }
    } else {
        log::info!("starting HTTP server at http://{}:{}", conf.host, conf.port);

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::clone(&data))
                .wrap(Logger::default())
                .service(auth)
        })
        .workers(16)
        .keep_alive(Duration::from_secs(60))
        .bind((conf.host, conf.port))?
        .run()
        .await
    }
}
