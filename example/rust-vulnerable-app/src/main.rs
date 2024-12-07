use actix_web::{get, web, App, HttpResponse, HttpServer, Result};
use rusqlite::{Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::process::Command;

// Vulnerable database initialization
fn init_db() -> SqliteResult<()> {
    let conn = Connection::open("users.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        [],
    )?;

    // Insert default user if not exists
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')",
        [],
    )?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i32,
    username: String,
    password: String,
}

// Vulnerability 1: SQL Injection
#[get("/sqli")]
async fn sql_injection(query: web::Query<HashMap<String, String>>) -> Result<HttpResponse> {
    let username = query.get("username").unwrap_or(&String::from(""));

    // Vulnerable SQL query - DO NOT USE IN PRODUCTION
    let query_str = format!("SELECT * FROM users WHERE username = '{}'", username);

    let conn = Connection::open("users.db").unwrap();
    let mut stmt = conn.prepare(&query_str).unwrap();

    let users: Vec<User> = stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password: row.get(2)?,
            })
        })
        .unwrap()
        .filter_map(|u| u.ok())
        .collect();

    Ok(HttpResponse::Ok().json(users))
}

// Vulnerability 2: Command Injection
#[get("/cmdi")]
async fn command_injection(query: web::Query<HashMap<String, String>>) -> Result<HttpResponse> {
    let hostname = query.get("hostname").unwrap_or(&String::from("localhost"));

    // Vulnerable command execution - DO NOT USE IN PRODUCTION
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", hostname))
        .output()
        .expect("Failed to execute command");

    let result = String::from_utf8_lossy(&output.stdout);

    Ok(HttpResponse::Ok().body(result.to_string()))
}

// Vulnerability 3: Path Traversal
#[get("/file")]
async fn file_read(query: web::Query<HashMap<String, String>>) -> Result<HttpResponse> {
    let filename = query.get("name").unwrap_or(&String::from("default.txt"));

    // Vulnerable file read - DO NOT USE IN PRODUCTION
    match std::fs::read_to_string(filename) {
        Ok(content) => Ok(HttpResponse::Ok().body(content)),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize database
    init_db().expect("Failed to initialize database");

    println!("Starting server at http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .service(sql_injection)
            .service(command_injection)
            .service(file_read)
            .route(
                "/",
                web::get().to(|| async {
                    HttpResponse::Ok().body(
                        r#"
                    <h1>Vulnerable Rust Application</h1>
                    <ul>
                        <li><a href="/sqli?username=admin">SQL Injection</a></li>
                        <li><a href="/cmdi?hostname=localhost">Command Injection</a></li>
                        <li><a href="/file?name=README.md">Path Traversal</a></li>
                    </ul>
                    "#,
                    )
                }),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
