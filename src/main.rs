use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
    response::Response,
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use tokio::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv()?;
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/wh/github/pink-bot", post(pink_bot_webhook));
    let addr = SocketAddr::from(([127, 0, 0, 1], 32030));

    tracing::info!("listening on http://{addr}");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn pink_bot_webhook(req: Request<Body>) -> Result<impl IntoResponse, Response> {
    let hub_signature = req
        .headers()
        .get("x-hub-signature-256")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Missing signature header".to_owned(),
            )
                .into_response()
        })?
        .to_owned();
    let hub_signature = &hub_signature.as_bytes()[7..];

    let body = hyper::body::to_bytes(req.into_body())
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    // TODO: overwrite secret for hooks instead of using same one for everything
    // ```toml
    // [hooks.pink_bot]
    // secret_env = "PINK_BOT_ACTION_WEBHOOK_SECRET"
    // ```
    let mut mac = Hmac::<Sha256>::new_from_slice(
        env::var("PINK_BOT_ACTION_WEBHOOK_SECRET")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    mac.update(&body);
    let signature = hex::encode(mac.finalize().into_bytes()).into_bytes();

    if signature != hub_signature {
        return Err((StatusCode::FORBIDDEN, "Bad signature header".to_owned()).into_response());
    }

    let action: Value = serde_json::from_slice(&body)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?;

    tokio::spawn(async move {
        if let Err(err) = run_checks(action).await {
            tracing::error!("error running checks: {err}")
        }
    });

    Ok(())
}

async fn run_checks(json: Value) -> Result<(), String> {
    // TODO: define these in toml config
    for def in [
        ["/action", "==", "completed"],
        ["/check_suite/conclusion", "==", "success"],
        ["/repository/full_name", "~=", "fogapod/pink"],
    ] {
        if let Err(err) = PayloadCheck::new(&def).validate(&json) {
            tracing::info!("{err}");
            return Err(err);
        }
    }

    tracing::info!("checks passed, performing action");

    // TODO: define these in toml config
    for command_str in  [
        "docker pull fogapod/pink",
        "docker stop pink-bot | true",
        "docker run --name pink-bot --rm -v /home/eugene/pink/settings.toml:/code/settings.toml --hostname pink_prod --network host -d fogapod/pink",
    ] {
        tracing::info!("running {command_str}");

        let status = Command::new("sh").arg("-c").arg(command_str)
            .spawn()
            .map_err(|err| format!("Unable to spawn command: {err}"))?
            .wait()
            .await
            .map_err(|err| format!("Error running command: {err}"))?;

        tracing::debug!("exited with status {:?}", status.code());

        if !status.success() {
            return Err(match status.code() {
                Some(code) => format!("Bad exist status: {code}"),
                None => "Terminated by signal".to_owned(),
            });
        }
    }

    Ok(())
}

#[derive(Debug)]
enum PayloadCheckOperation {
    CaseSensitiveCompare(String),
    CaseInsensitiveCompare(String),
}

impl PayloadCheckOperation {
    fn validate(&self, value: &str) -> Result<(), String> {
        match self {
            Self::CaseSensitiveCompare(original) => {
                if value != original {
                    return Err(format!("Value {} did not match ={}", value, original));
                }
            }
            Self::CaseInsensitiveCompare(original) => {
                if &value.to_lowercase() != original {
                    return Err(format!("Value {} did not match ~{}", value, original));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct PayloadCheck {
    path: String,
    condition: PayloadCheckOperation,
}

impl PayloadCheck {
    fn new(source: &[&str]) -> Self {
        let path = source[0].to_owned();
        let condition = match source[1] {
            "==" => PayloadCheckOperation::CaseSensitiveCompare(source[2].to_owned()),
            "~=" => PayloadCheckOperation::CaseInsensitiveCompare(source[2].to_lowercase()),
            _ => panic!(
                "Unknown operation {} followed by {:?}",
                source[1],
                &source[1..],
            ),
        };

        PayloadCheck { path, condition }
    }

    fn validate(&self, root: &Value) -> Result<(), String> {
        let value = root
            .pointer(&self.path)
            .ok_or_else(|| format!("Path {} did not match", self.path))?;

        self.condition.validate(
            value
                .as_str()
                .ok_or_else(|| format!("{} is not a string", value))?,
        )
    }
}
