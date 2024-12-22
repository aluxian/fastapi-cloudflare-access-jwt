from .cloudflare_access_jwt import CloudflareAccessJWT

enforce_cf_access = CloudflareAccessJWT()

__all__ = ["CloudflareAccessJWT", "enforce_cf_access"]
