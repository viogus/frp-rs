use axum::{
    extract::Request,
    http::StatusCode,
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};
use std::sync::Arc;

use crate::auth::constant_time_eq_str;

#[derive(Clone)]
struct AuthState {
    enabled: bool,
    expected_header: String,
}

/// Apply HTTP Basic Auth middleware to a router.
///
/// When either `user` or `password` is empty, auth is skipped
/// (pass-through): an empty half would otherwise be silently accepted as an
/// empty credential, and both callers (frps dashboard, frpc admin API)
/// already force a localhost-only bind in that case. A half-configured pair
/// (exactly one of the two empty) additionally logs an explicit warning at
/// startup so the operator is not left believing auth is enforced. Only when
/// BOTH are non-empty is auth enforced — requests without a valid
/// `Authorization: Basic <base64(user:pass)>` header receive
/// 401 with `WWW-Authenticate: Basic realm="frp"`.
///
/// **Security note:** Basic Auth transmits credentials in plaintext
/// (base64 is NOT encryption). Use a reverse proxy with TLS termination
/// (nginx, Caddy) to protect credentials in production.
pub fn apply_admin_auth<S>(router: Router<S>, user: &str, password: &str) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let enabled = !user.is_empty() && !password.is_empty();
    if enabled {
        tracing::warn!(
            "Admin API: Basic Auth enabled without TLS — credentials sent in plaintext. \
             Use a reverse proxy with TLS termination in production."
        );
    } else if user.is_empty() != password.is_empty() {
        // Half-configured: exactly one of user/password is empty. Auth stays
        // OFF (AND semantics — an empty half must not become an accepted
        // empty credential), but an operator setting one of the two may
        // believe auth is on. Say so explicitly; both callers already force
        // a localhost-only bind in this case.
        let which = if user.is_empty() {
            "user empty, password set"
        } else {
            "user set, password empty"
        };
        tracing::warn!(
            "Admin API: admin auth DISABLED — {which} (half-configured); binding \
             localhost-only. Set BOTH user and password to enable auth."
        );
    }
    let expected = if enabled {
        format!(
            "Basic {}",
            crate::base64::encode(format!("{}:{}", user, password).as_bytes())
        )
    } else {
        String::new()
    };

    let state = Arc::new(AuthState {
        enabled,
        expected_header: expected,
    });

    async fn check_auth(req: Request, next: Next) -> Response {
        let state = match req.extensions().get::<Arc<AuthState>>().cloned() {
            Some(s) => s,
            None => {
                // Extension not injected — middleware layer was not properly
                // applied. This is a configuration/programming error, not a
                // client auth failure. Return 500 so the operator notices.
                tracing::error!("Admin auth middleware: AuthState extension missing — middleware layer not properly applied");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal configuration error",
                )
                    .into_response();
            }
        };
        if state.enabled {
            let ok = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|v| constant_time_eq_str(v, &state.expected_header))
                .unwrap_or(false);
            if !ok {
                // Match Go frp's authFailDelay (200ms) to slow brute-force attacks
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                return (
                    StatusCode::UNAUTHORIZED,
                    [("www-authenticate", "Basic realm=\"frp\"")],
                    "Unauthorized",
                )
                    .into_response();
            }
        }
        next.run(req).await
    }

    router.layer(middleware::from_fn(move |mut req: Request, next: Next| {
        let s = state.clone();
        async move {
            req.extensions_mut().insert(s);
            check_auth(req, next).await
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn test_auth_disabled_when_empty() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "", "");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_disabled_when_password_empty() {
        // Either-empty means "no auth" (AND semantics): a user without a
        // password must not turn the admin API into a public endpoint
        // protected by an empty credential. Half-configured pairs also emit
        // an explicit startup warning in apply_admin_auth ("user set,
        // password empty") so the operator notices auth is off — the warning
        // itself is not log-asserted here (no tracing capture in unit
        // tests); the disabled-auth behavior it accompanies is what this
        // test pins down.
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_disabled_when_user_empty() {
        // Symmetric case: a password without a user is not enforced either
        // (also warned about at startup: "user empty, password set").
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "", "secret");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_rejects_no_header() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_accepts_valid() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let creds = crate::base64::encode(b"admin:secret");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .header("Authorization", format!("Basic {}", creds))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_rejects_wrong_password() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let creds = crate::base64::encode(b"admin:wrong");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/test")
                    .header("Authorization", format!("Basic {}", creds))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
