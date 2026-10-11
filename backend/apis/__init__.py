"""
Threat-intelligence source adapters.

Modules here read their API keys at call time with os.getenv, so each one that
needs a key imports `env_config` itself (side effect: fills gaps from
backend/.env). That import is deliberately NOT in this package __init__:
`apis.rate_limit` is a pure in-memory limiter with no secrets, `auth` imports
it, and making every `apis.*` import read a file from disk would hand auth a
JWT_SECRET it should have had to find in the real environment.

See env_config for what the missing keys cost — a 190,542-domain known-malicious
corpus scanned 73% SAFE because VirusTotal and Safe Browsing were never reached.
"""
