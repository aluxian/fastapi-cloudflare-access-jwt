# FastAPI bearer class for Cloudflare Access (Argo Tunnel)

A FastAPI middleware for authenticating requests from Cloudflare Access (formerly Argo Tunnel) using JWT tokens.

## Why?

When using Cloudflare Access to protect your FastAPI application, you need to validate the JWT tokens that Cloudflare Access sends with each request. This package provides a simple way to validate these tokens and protect your FastAPI routes.

## Installation

```sh
pip install fastapi-cloudflare-access-jwt
```

## Usage

1. Set up your environment variables:

```sh
export CF_ACCESS_CERTS_URL="https://your-team-name.cloudflareaccess.com/cdn-cgi/access/certs"
export CF_ACCESS_POLICY_AUD="your-application-audience-tag"
```

2. Use in your FastAPI application:

```python
from fastapi import FastAPI, Depends
from cloudflare_access_jwt import enforce_cf_access

app = FastAPI(dependencies=[Depends(enforce_cf_access)])

@app.get("/protected")
async def protected_route():
    return {"message": "This route is protected by Cloudflare Access"}

# Or protect specific routes:
@app.get("/also-protected")
async def another_protected_route(cf_claims=Depends(enforce_cf_access)):
    return {"message": "This route is also protected", "user": cf_claims}
```

You can also initialize the middleware with parameters instead of environment variables:

```python
from cloudflare_access_jwt import CloudflareAccessJWT

custom_enforcer = CloudflareAccessJWT(
    certs_url="https://your-team-name.cloudflareaccess.com/cdn-cgi/access/certs",
    policy_aud="your-application-audience-tag"
)

app = FastAPI(dependencies=[Depends(custom_enforcer)])
```

## Development

1. Clone the repository and install dependencies:

```sh
git clone https://github.com/aluxian/fastapi-cloudflare-access-jwt.git
cd fastapi-cloudflare-access-jwt
uv venv
source .venv/bin/activate
uv sync
```

2. Run linting checks:

```sh
uv run ruff check .
```

3. Run tests:

```sh
uv run pytest
```

4. Start Aider:

```sh
uvx --python 3.12 --from 'aider-chat[playwright]' --with 'aider-chat[help]' aider
```
