"""
Block Bord AI — Centralized Limiter
Maintains a single SlowAPI Limiter instance to avoid circular imports
when applying rate limits to modular routers.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize Limiter
# Using get_remote_address as the default key (per-IP)
limiter = Limiter(key_func=get_remote_address)
