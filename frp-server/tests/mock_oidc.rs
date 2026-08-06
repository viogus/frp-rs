use axum::{extract::State, routing::get, Json, Router};
use frp_core::base64::encode as base64_encode;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------
// Mock OIDC Provider
// ---------------------------------------------------------------
//
// Serves a minimal OIDC discovery + JWKS endpoint on localhost.
// Uses HS256 symmetric keys (oct JWK) to avoid RSA key extraction
// complexity with ring. The OidcVerifier in frp-core supports oct
// keys via DecodingKey::from_base64_secret.

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,
    iss: String,
    exp: usize,
    iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

struct MockOidcState {
    issuer: String,
    jwks: serde_json::Value,
    encoding_key: EncodingKey,
    kid: String,
}

pub struct MockOidcProvider {
    state: Arc<MockOidcState>,
    pub issuer: String,
    #[allow(dead_code)]
    pub port: u16,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_handle: tokio::task::JoinHandle<()>,
}

impl MockOidcProvider {
    /// Start the mock OIDC provider on the given port.
    /// Returns after the server is ready to accept connections.
    pub async fn start(port: u16) -> Self {
        let issuer = format!("http://127.0.0.1:{}", port);
        let secret = uuid::Uuid::new_v4().to_string();
        let kid = uuid::Uuid::new_v4().to_string();
        let encoded_secret = base64_encode(secret.as_bytes());

        let jwks = serde_json::json!({
            "keys": [{
                "kty": "oct",
                "kid": kid.clone(),
                "k": encoded_secret.clone(),
                "alg": "HS256",
                "use": "sig"
            }]
        });

        let encoding_key = EncodingKey::from_base64_secret(&encoded_secret)
            .expect("valid base64 secret for HS256 encoding key");

        let state = Arc::new(MockOidcState {
            issuer: issuer.clone(),
            jwks,
            encoding_key,
            kid,
        });

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(oidc_discovery))
            .route("/jwks", get(oidc_jwks))
            .with_state(state.clone());

        let socket = tokio::net::TcpSocket::new_v4().expect("create mock OIDC socket");
        socket
            .set_reuseaddr(true)
            .expect("set SO_REUSEADDR on mock OIDC socket");
        socket
            .bind(format!("127.0.0.1:{}", port).parse().unwrap())
            .expect("bind mock OIDC provider");
        let listener = socket.listen(128).expect("listen mock OIDC");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("mock OIDC server error");
        });

        // Wait for the server to be ready
        let startup_url = format!("{}/.well-known/openid-configuration", issuer);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        for _ in 0..30 {
            if client.get(&startup_url).send().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        MockOidcProvider {
            state,
            issuer,
            port,
            shutdown_tx: Some(shutdown_tx),
            server_handle,
        }
    }

    /// Generate a valid JWT signed with the provider's HS256 key.
    /// Includes iss, aud, sub, iat, exp claims matching the provider config.
    pub fn generate_token(&self, subject: &str) -> String {
        self.generate_token_with_jti(subject, None)
    }

    /// Generate a valid JWT with an explicit jti claim (replay-protection
    /// tests need to control the jti independently of the subject).
    pub fn generate_token_with_jti(&self, subject: &str, jti: Option<&str>) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: subject.to_string(),
            aud: "test-audience".to_string(),
            iss: self.issuer.clone(),
            exp: now + 3600,
            iat: now,
            jti: jti.map(|s| s.to_string()),
        };

        let header = Header {
            alg: Algorithm::HS256,
            kid: Some(self.state.kid.clone()),
            ..Default::default()
        };

        encode(&header, &claims, &self.state.encoding_key).expect("JWT encode")
    }
}

impl Drop for MockOidcProvider {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.server_handle.abort();
    }
}

// ---------------------------------------------------------------
// Axum route handlers
// ---------------------------------------------------------------

async fn oidc_discovery(State(state): State<Arc<MockOidcState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/jwks", state.issuer),
        "authorization_endpoint": format!("{}/auth", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"]
    }))
}

async fn oidc_jwks(State(state): State<Arc<MockOidcState>>) -> Json<serde_json::Value> {
    Json(state.jwks.clone())
}
