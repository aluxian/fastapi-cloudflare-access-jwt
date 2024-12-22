from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer
from loguru import logger as default_logger
import requests
import jwt
import os
from datetime import datetime, timedelta


class CloudflareAccessJWT(HTTPBearer):
    def __init__(
        self, certs_url: str = None, policy_aud: str = None, logger=default_logger
    ):
        super().__init__()

        self.certs_url = certs_url
        self.policy_aud = policy_aud
        self.logger = logger

        self._public_keys_cache = None
        self._public_keys_last_fetched = None
        self._public_keys_cache_duration = timedelta(days=7)

    def _lazy_init(self):
        if self.certs_url is None:
            self.certs_url = self.certs_url or os.getenv("CF_ACCESS_CERTS_URL")
            self.logger.debug(f"Cloudflare Access public keys URL: {self.certs_url}")

        if self.policy_aud is None:
            self.policy_aud = self.policy_aud or os.getenv("CF_ACCESS_POLICY_AUD")
            self.logger.debug(f"Cloudflare Access policy audience: {self.policy_aud}")

        # Check if we need to refresh the keys
        now = datetime.now()
        if (
            self._public_keys_cache is None
            or self._public_keys_last_fetched is None
            or now - self._public_keys_last_fetched > self._public_keys_cache_duration
        ):
            self.logger.debug("Fetching fresh Cloudflare Access public keys")
            self._public_keys_cache = [
                jwt.algorithms.RSAAlgorithm.from_jwk(key)
                for key in requests.get(self.certs_url).json()["keys"]
            ]
            self.logger.debug(
                f"Cloudflare Access public keys: {self._public_keys_cache}"
            )
            self._public_keys_last_fetched = now

    def __call__(self, request: Request):
        self._lazy_init()

        token = request.cookies.get("CF_Authorization")
        errors = []

        for key in self._public_keys_cache:
            try:
                claims = jwt.decode(
                    token, key=key, audience=self.policy_aud, algorithms=["RS256"]
                )
                self.logger.debug(f"Cloudflare Access claims: {claims}")
                return claims
            except jwt.PyJWTError as e:
                errors.append(str(e))
                continue

        for error in errors:
            self.logger.error(f"Cloudflare Access JWT error: {error}")

        raise HTTPException(status_code=403, detail="Bad Cloudflare Access token")
