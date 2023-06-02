use crate::AppState;
use actix_web::{
    get,
    web::{self, Data},
    HttpRequest, HttpResponse, Responder,
};
use sqlx::{self, FromRow};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

#[derive(FromRow)]
struct UserIp {
    ip_addr: String,
}

#[get("/{key}")]
async fn update_ip(
    state: Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> impl Responder {
    let key = path.into_inner();

    let new_ip = match req.connection_info().realip_remote_addr() {
        Some(ip) => ip.to_string(),
        None => {
            return HttpResponse::InternalServerError().body("Error getting request IP address\n")
        }
    };

    if new_ip.parse::<Ipv4Addr>().is_err() {
        return HttpResponse::BadRequest().body(
            "Client IP must be IPv4, contact the administrator if this needs to be changed\n",
        );
    }

    let old_ip: String =
        match sqlx::query_as::<_, UserIp>("SELECT ip_addr FROM auth WHERE \"key\" = $1")
            .bind(&key)
            .fetch_one(&state.db)
            .await
        {
            Ok(entry) => entry.ip_addr,
            Err(_) => return HttpResponse::Unauthorized().body("Unauthorized key\n"),
        };

    Command::new("sudo")
        .args([
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "-m",
            "state",
            "--state",
            "NEW",
            "-m",
            "tcp",
            "--dport",
            &state.dest_port.to_string(),
            "-s",
            &old_ip,
            "-j",
            "ACCEPT",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to execute iptables with sudo");

    Command::new("sudo")
        .args([
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "udp",
            "-m",
            "state",
            "--state",
            "NEW",
            "-m",
            "udp",
            "--dport",
            &state.dest_port.to_string(),
            "-s",
            &old_ip,
            "-j",
            "ACCEPT",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to execute iptables with sudo");

    {
        let tcp_output = Command::new("sudo")
            .args([
                "iptables",
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "-m",
                "state",
                "--state",
                "NEW",
                "-m",
                "tcp",
                "--dport",
                &state.dest_port.to_string(),
                "-s",
                &new_ip,
                "-j",
                "ACCEPT",
            ])
            .output()
            .expect("Failed to execute iptables with sudo");
        if !tcp_output.status.success() {
            return HttpResponse::InternalServerError().body("Error creating new tcp input rule\n");
        }
    }

    {
        let udp_output = Command::new("sudo")
            .args([
                "iptables",
                "-A",
                "INPUT",
                "-p",
                "udp",
                "-m",
                "state",
                "--state",
                "NEW",
                "-m",
                "udp",
                "--dport",
                &state.dest_port.to_string(),
                "-s",
                &new_ip,
                "-j",
                "ACCEPT",
            ])
            .output()
            .expect("Failed to execute iptables with sudo");
        if !udp_output.status.success() {
            return HttpResponse::InternalServerError().body("Error creating new udp input rule\n");
        }
    }

    let mut update_error = false;
    if let Err(_) = sqlx::query("UPDATE auth SET ip_addr = $1 WHERE \"key\" = $2")
        .bind(&new_ip)
        .bind(&key)
        .execute(&state.db)
        .await
    {
        update_error = true;
    }

    if state.final_reject {
        {
            let delete_output = Command::new("sudo")
                .args([
                    "iptables",
                    "-D",
                    "INPUT",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-host-prohibited",
                ])
                .output()
                .expect("Failed to execute iptables with sudo");
            if !delete_output.status.success() {
                return HttpResponse::InternalServerError()
                    .body("Error deleting final reject input rule\n");
            }
        }
        {
            let create_output = Command::new("sudo")
                .args([
                    "iptables",
                    "-A",
                    "INPUT",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-host-prohibited",
                ])
                .output()
                .expect("Failed to execute iptables with sudo");
            if !create_output.status.success() {
                return HttpResponse::InternalServerError()
                    .body("Error creating final reject input rule\n");
            }
        }
    }

    if update_error {
        return HttpResponse::InternalServerError().body("Error editing entry to new ip\n");
    }

    HttpResponse::Ok().body(format!("{}\n", new_ip))
}
