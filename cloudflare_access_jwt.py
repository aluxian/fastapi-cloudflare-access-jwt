from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer
from loguru import logger
import requests
import jwt
import os
from datetime import datetime, timedelta

# Module-level variables
_certs_url = None
_policy_aud = None

# Module-level cache variables
_public_keys_cache = None
_public_keys_last_fetched = None
_public_keys_cache_duration = timedelta(days=7)


class CloudflareAccessJWT(HTTPBearer):
    def __init__(self):
        super().__init__()

    def _lazy_init(self):
        global _certs_url
        if _certs_url is None:
            _certs_url = os.getenv("CF_ACCESS_CERTS_URL")
            logger.debug(f"Cloudflare Access public keys URL: {_certs_url}")

        global _policy_aud
        if _policy_aud is None:
            _policy_aud = os.getenv("CF_ACCESS_POLICY_AUD")
            logger.debug(f"Cloudflare Access policy audience: {_policy_aud}")

        # Check if we need to refresh the keys
        global _public_keys_cache, _public_keys_last_fetched
        now = datetime.now()
        if (
            _public_keys_cache is None
            or _public_keys_last_fetched is None
            or now - _public_keys_last_fetched > _public_keys_cache_duration
        ):
            logger.debug("Fetching fresh Cloudflare Access public keys")
            _public_keys_cache = [
                jwt.algorithms.RSAAlgorithm.from_jwk(key)
                for key in requests.get(_certs_url).json()["keys"]
            ]
            logger.debug(f"Cloudflare Access public keys: {_public_keys_cache}")
            _public_keys_last_fetched = now

    def __call__(self, request: Request):
        self._lazy_init()

        token = request.cookies.get("CF_Authorization")
        errors = []

        for key in _public_keys_cache:
            try:
                claims = jwt.decode(
                    token, key=key, audience=_policy_aud, algorithms=["RS256"]
                )
                logger.debug(f"Cloudflare Access claims: {claims}")
                return claims
            except jwt.PyJWTError as e:
                errors.append(str(e))
                continue

        for error in errors:
            logger.error(f"Cloudflare Access JWT error: {error}")
        raise HTTPException(status_code=403, detail="Bad Cloudflare Access token")


enforce_cf_access = CloudflareAccessJWT()
