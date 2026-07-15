# Deployment hardening guide

How to put ThreatOrbit on a network without embarrassing yourself. The API
already ships baseline security headers (`nosniff`, `DENY` framing,
`no-referrer`, `no-store`) on every response; everything else here is the
deployment's job.

## Topology

```
internet --TLS--> reverse proxy (nginx/caddy)
                    ├-- /            → frontend  (static export, :3000 or files)
                    └-- /api/*       → dashboard_api (:8002)
                                       threat_api (:8000), log_api (:8001) stay internal
```

- Terminate TLS at the proxy. The app services speak plain HTTP **on an
  internal network only** - never publish :8000/:8001/:8002 directly.
- The frontend is a static export (`next build` with `output: 'export'`), so
  its security headers (CSP, HSTS) are set by whatever serves the files -
  reference configs below.

## Environment checklist (fail the deploy if unset)

| Variable | Why |
|---|---|
| `DASHBOARD_JWT_SECRET` | session signing - `openssl rand -hex 32`; the boot log warns on the dev default |
| `DASHBOARD_ENCRYPTION_KEY` | secrets-at-rest key - pin it BEFORE first use (docs/OPERATIONS.md) |
| `DASHBOARD_EVIDENCE_SECRET` | evidence-bundle signatures survive JWT rotation |
| `CORS_ORIGINS` | the exact frontend origin(s) - never `*` in production |
| `DASHBOARD_METRICS_TOKEN` | gate `/metrics` if the proxy exposes it |
| `SMTP_*` / `SENTRY_DSN` / `DASHBOARD_LOG_FORMAT=json` | mail, error tracking, log shipping (optional, honest-degrade) |
| `ANTHROPIC_API_KEY` | enables the full AI dashboard assistant (optional). Unset = the assistant degrades to a deterministic command set. `DASHBOARD_ASSISTANT_MODEL` overrides the model (default `claude-opus-4-8`). The assistant is read-only, runs as the caller, and never returns credentials. |

## nginx reference

```nginx
server {
    listen 443 ssl http2;
    server_name threatorbit.example.com;
    ssl_certificate     /etc/letsencrypt/live/threatorbit.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/threatorbit.example.com/privkey.pem;

    # HSTS only once TLS is known-good everywhere:
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    # CSP for the static frontend (Next.js export uses inline bootstrap
    # scripts - hence 'unsafe-inline'; tighten with hashes if you fork the UI):
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" always;

    root /srv/threatorbit/frontend;          # the static export
    location / { try_files $uri $uri/ /index.html; }

    location /api/ {
        proxy_pass http://127.0.0.1:8002/;   # dashboard_api, internal only
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        client_max_body_size 25m;            # log uploads
        proxy_read_timeout 75s;              # SSE stream (/api/stream)
        proxy_buffering off;                 # required for SSE
    }
}
server { listen 80; server_name threatorbit.example.com; return 301 https://$host$request_uri; }
```

## Caddy reference (automatic TLS)

```caddy
threatorbit.example.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    }
    handle /api/* {
        uri strip_prefix /api
        reverse_proxy 127.0.0.1:8002 { flush_interval -1 }   # SSE-safe
    }
    root * /srv/threatorbit/frontend
    file_server
    try_files {path} {path}/ /index.html
}
```

## Containers

- `dashboard_api/Dockerfile` runs as the unprivileged `app` user (uid 10001);
  only the `/data` volume is writable. Verify after any base-image change:
  `docker build dashboard_api/ && docker run --rm -p 8002:8002 <img>` then
  `curl :8002/health`.
- In compose, add per-service limits and a read-only root where possible:

```yaml
    read_only: true
    tmpfs: [/tmp]
    mem_limit: 1g
    cpus: "1.0"
    security_opt: ["no-new-privileges:true"]
```

- Pin images by digest (`python:3.11-slim@sha256:…`) once you've built and
  scanned a known-good one; re-pin deliberately, not implicitly.

## What the platform refuses to pretend about

- No TLS in the app processes - terminate at the proxy (above).
- `/metrics` is open unless `DASHBOARD_METRICS_TOKEN` is set - gate it or
  keep it off the public proxy.
- The syslog listener (`DASHBOARD_SYSLOG_PORT`) is plain UDP RFC 3164/5424;
  TLS syslog (RFC 5425) is a Tier-2 roadmap item - until then, keep log
  transport on trusted networks (VPN/VPC).
