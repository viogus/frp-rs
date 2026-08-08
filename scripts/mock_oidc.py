#!/usr/bin/env python3
"""Minimal OIDC provider for cross-compat tests: discovery + token + JWKS (HS256).

Standard library only. Serves:
  GET  /.well-known/openid-configuration
  POST /token            (client_credentials grant -> HS256-signed JWT)
  GET  /jwks             (oct JWK matching the signing secret)

Usage: mock_oidc.py PORT ISSUER SECRET AUD [LOG_FILE]
"""
import base64
import hashlib
import hmac
import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

port = int(sys.argv[1])
issuer = sys.argv[2]
secret = sys.argv[3].encode()
aud = sys.argv[4]
log_file = sys.argv[5] if len(sys.argv) > 5 else None

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# Rust OidcVerifier (jsonwebtoken) expects the oct JWK "k" (and the HS256
# encoding secret) as standard base64 WITH padding — mirror mock_oidc.rs
# (frp_core::base64::encode).
enc_secret = base64.b64encode(secret).decode()

def sign_jwt(header: dict, payload: dict) -> str:
    signing_input = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
                    b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(base64.b64decode(enc_secret), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64u(sig)

def jwks_json():
    return {
        "keys": [{
            "kty": "oct",
            "k": enc_secret,
            "alg": "HS256",
            "kid": "mock-oidc-key",
            "use": "sig",
        }]
    }

def log(msg: str):
    if log_file:
        with open(log_file, "a") as f:
            f.write(msg + "\n")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log("idp: " + (fmt % args))

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            body = json.dumps({
                "issuer": issuer,
                "token_endpoint": issuer + "/token",
                "jwks_uri": issuer + "/jwks",
                "response_types_supported": ["code"],
                "id_token_signing_alg_values_supported": ["HS256"],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/jwks":
            body = json.dumps(jwks_json()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length < 0:
            length = 0
        form = parse_qs(self.rfile.read(length).decode())
        if self.path == "/token" and form.get("grant_type", [""])[0] == "client_credentials":
            now = int(time.time())
            payload = {
                "iss": issuer,
                "sub": form.get("client_id", ["mock-client"])[0],
                "aud": aud,
                "iat": now,
                "exp": now + 300,
                "jti": str(uuid.uuid4()),
            }
            token = sign_jwt({"alg": "HS256", "typ": "JWT", "kid": "mock-oidc-key"}, payload)
            body = json.dumps({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 300,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()

ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
