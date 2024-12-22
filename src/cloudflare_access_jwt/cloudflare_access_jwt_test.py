import os
from unittest.mock import patch
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from cloudflare_access_jwt import CloudflareAccessJWT, enforce_cf_access


# Mock environment variables
os.environ["CF_ACCESS_CERTS_URL"] = "https://test.cloudflareaccess.com/certs"
os.environ["CF_ACCESS_AUD"] = "test_audience"

# Mock response for the public keys endpoint
MOCK_CERTS_RESPONSE = {
    "keys": [
        {
            "kid": "test_key_id",
            "kty": "RSA",
            "alg": "RS256",
            "n": "test_modulus",
            "e": "AQAB",
        }
    ]
}

# Test with environment variables
app = FastAPI(dependencies=[Depends(enforce_cf_access)])

# Test with constructor parameters
custom_enforcer = CloudflareAccessJWT(
    certs_url="https://test.cloudflareaccess.com/certs", policy_aud="test_audience"
)
app_with_params = FastAPI(dependencies=[Depends(custom_enforcer)])


@app.get("/protected")
@app_with_params.get("/protected")
async def protected_route():
    return {"message": "Access granted"}


@patch("requests.get")
def test_cloudflare_access_jwt_bad_cookie(mock_get):
    # Mock the certs endpoint response
    mock_get.return_value.json.return_value = MOCK_CERTS_RESPONSE
    mock_get.return_value.status_code = 200

    client = TestClient(app)
    client.cookies.set("CF_Authorization", "bad_token")
    response = client.get("/protected")
    assert response.status_code == 403
    assert response.json() == {"detail": "Bad Cloudflare Access token"}


@patch("requests.get")
def test_cloudflare_access_jwt_no_cookie(mock_get):
    # Mock the certs endpoint response
    mock_get.return_value.json.return_value = MOCK_CERTS_RESPONSE
    mock_get.return_value.status_code = 200

    client = TestClient(app)
    client.cookies.clear()  # Ensure no cookies are set
    response = client.get("/protected")
    assert response.status_code == 403
    assert response.json() == {"detail": "Bad Cloudflare Access token"}


@patch("requests.get")
def test_cloudflare_access_jwt_with_constructor_params(mock_get):
    # Mock the certs endpoint response
    mock_get.return_value.json.return_value = MOCK_CERTS_RESPONSE
    mock_get.return_value.status_code = 200

    client = TestClient(app_with_params)
    client.cookies.set("CF_Authorization", "bad_token")
    response = client.get("/protected")
    assert response.status_code == 403
    assert response.json() == {"detail": "Bad Cloudflare Access token"}
