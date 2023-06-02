use actix_web::{web::Data, App, HttpServer};
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::fs;
use std::io::Result;

mod services;
use services::update_ip;

pub struct AppState {
    db: Pool<Postgres>,
    dest_port: u16,
    final_reject: bool,
}

#[derive(Deserialize)]
struct Config {
    database: DatabaseConfig,
    server: ServerConfig,
}

#[derive(Deserialize)]
struct DatabaseConfig {
    url: String,
}

#[derive(Deserialize)]
struct ServerConfig {
    port: u16,
    dest_port: u16,
    final_reject: bool,
}

fn read_config() -> Config {
    let config_content = fs::read_to_string("/etc/auth-iptables/config.toml")
        .expect("Error reading /etc/auth-iptables/config.toml");
    let config: Config =
        toml::from_str(&config_content).expect("Error parsing /etc/auth-iptables/config.toml");
    config
}

#[actix_web::main]
async fn main() -> Result<()> {
    let config: Config = read_config();
    if config.server.dest_port == 22 {
        panic!("For safety, dest_port may not be set to 22");
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await
        .expect("Error creating connection pool to the PostgreSQL server");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState {
                db: pool.clone(),
                dest_port: config.server.dest_port,
                final_reject: config.server.final_reject,
            }))
            .service(update_ip)
    })
    .bind(("127.0.0.1", config.server.port))?
    .run()
    .await
}
