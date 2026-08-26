# Deployment

Repository Manager manages the *contents* of package repositories. It deliberately does
not serve them (AD-3): a web server does that far better, and putting a Python process in
the path of every `apt` fetch would be a needless bottleneck and a needless attack surface.

That split means a working deployment has two halves:

1. **The application**, behind a reverse proxy that terminates TLS, exposing the management
   interface at `REPOMAN_PUBLIC_URL`.
2. **The repository trees**, served read-only as static files at `REPOMAN_REPOSITORY_BASE_URL`.

The client setup snippets shown on each repository's page are built from the *second* URL.
If the two do not line up with what the web server actually serves, the snippets will be
wrong — so this is worth getting right before anyone copies one.

## Reference nginx configuration

This assumes every repository lives under one allowed root, `/srv/repositories`, and that a
repository with slug `internal` has its root at `/srv/repositories/internal`.

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name packages.example.com;

    ssl_certificate     /etc/ssl/certs/packages.example.com.pem;
    ssl_certificate_key /etc/ssl/private/packages.example.com.key;

    # ---------------------------------------------------------------- repositories
    #
    # Static, read-only, and anonymous. This is what `apt update` talks to.
    location /repos/ {
        alias /srv/repositories/;
        autoindex on;
        autoindex_exact_size off;

        # Only ever read. A PUT or DELETE reaching the filesystem here would
        # bypass every check the application makes.
        limit_except GET HEAD { deny all; }

        # Indices change on every publish; packages never change once published,
        # because overwriting a published version is refused (5.1).
        location ~ ^/repos/[^/]+/dists/ {
            add_header Cache-Control "no-cache";
        }
        location ~ ^/repos/[^/]+/pool/ {
            add_header Cache-Control "public, max-age=31536000, immutable";
        }

        # The lockfile and the upload staging directory are internal state.
        # nginx hides dotfiles from autoindex, but not from a direct request.
        location ~ /\. { deny all; }
    }

    # ---------------------------------------------------------------- application
    location / {
        proxy_pass http://127.0.0.1:8000;

        # Strip anything the client sent, then set the values ourselves. Without
        # the reset, a client could present its own X-Forwarded-For and poison
        # the audit log or escape a rate limit (10.6).
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header Host              $host;

        client_max_body_size 2g;   # match REPOMAN_MAX_UPLOAD_BYTES
    }
}
```

The application only honours those `X-Forwarded-*` headers if the proxy's address is listed
in `REPOMAN_TRUSTED_PROXIES`. That setting has no default: with it unset the headers are
ignored entirely and the peer address is used, which is the safe behaviour for a
directly-exposed instance but *not* what you want here. For the configuration above:

```
REPOMAN_TRUSTED_PROXIES=127.0.0.1
REPOMAN_PUBLIC_URL=https://packages.example.com
REPOMAN_REPOSITORY_BASE_URL=https://packages.example.com/repos
REPOMAN_ALLOWED_ROOTS=/srv/repositories
```

## Sub-path deployment

To serve the application under a prefix rather than at the domain root, set both
`REPOMAN_ROOT_PATH` and the path in `REPOMAN_PUBLIC_URL`; the two must agree, and startup
fails if they do not.

```
REPOMAN_ROOT_PATH=/repoman
REPOMAN_PUBLIC_URL=https://packages.example.com/repoman
REPOMAN_REPOSITORY_BASE_URL=https://packages.example.com/repos
```

```nginx
location /repoman/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header X-Forwarded-Prefix /repoman;
    # ... the same forwarded headers as above
}
```

Both mounts are exercised by the same end-to-end suite on every commit, so a link or asset
that only works at the domain root is a build failure rather than a surprise in production.

## Client setup

Each repository's page shows the exact two commands. They come to this:

```sh
# 1. Trust the repository's signing key.
sudo curl -fsSL https://packages.example.com/repos/internal/internal.asc \
  -o /usr/share/keyrings/internal.asc

# 2. Add the source.
echo 'deb [signed-by=/usr/share/keyrings/internal.asc] \
  https://packages.example.com/repos/internal bookworm main' \
  | sudo tee /etc/apt/sources.list.d/internal.list

sudo apt update
```

`signed-by` scopes the trust to this one repository. Without it the key would be trusted for
*every* source on the machine, which is how a compromised third-party repository turns into
a compromised system.

## Filesystem ownership

The application must run as a dedicated non-root user that owns the repository tree, and
the web server needs only read access:

```sh
sudo install -d -o repoman -g repoman -m 0755 /srv/repositories
sudo install -d -o repoman -g repoman -m 0700 /var/lib/repoman/gnupg
```

The GnuPG home holds private key material and must not be inside a served root — the
directory is created 0700 and the application refuses to start if it is more permissive.

## Applying migrations

Migrations are never applied implicitly: a process that rewrites the schema on start is a
bad surprise during a rollback. Run them as a deliberate step before starting the new
version.

```sh
repository-manager db upgrade
repository-manager check-config    # prints the resolved settings, never the secret
```
