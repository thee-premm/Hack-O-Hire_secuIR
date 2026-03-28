"""
Redis Configuration Module
Handles connection, key naming, and TTL settings.
Gracefully falls back to in-memory when Redis is not available.
"""

import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import redis as _redis_lib
except ImportError:
    _redis_lib = None
    logger.warning("redis-py not installed. Using in-memory fallback only.")


class RedisConfig:
    """Redis connection manager with automatic fallback."""

    def __init__(self):
        self.host = os.getenv('REDIS_HOST', 'localhost')
        self.port = int(os.getenv('REDIS_PORT', 6379))
        self.db = int(os.getenv('REDIS_DB', 0))
        self.password = os.getenv('REDIS_PASSWORD', None)

        # TTL settings (seconds)
        self.user_ttl = 30 * 24 * 3600   # 30 days for user baselines
        self.global_ttl = None            # Permanent
        self.session_ttl = 30 * 60        # 30 minutes

        self.client = None
        self._connect()

    def _connect(self):
        if _redis_lib is None:
            logger.info("Redis library not available - in-memory mode")
            return
        try:
            self.client = _redis_lib.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            self.client.ping()
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
        except Exception as e:
            logger.info(f"Redis unavailable ({e}) - using in-memory fallback")
            self.client = None

    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            return self.client.ping()
        except Exception:
            return False

    def get_key(self, *parts) -> str:
        return f"secuir:{':'.join(str(p) for p in parts)}"

    def health(self) -> dict:
        if not self.is_available():
            return {'status': 'unavailable', 'mode': 'in-memory'}
        try:
            info = self.client.info('stats')
            return {'status': 'healthy', 'mode': 'redis', 'keys': self.client.dbsize()}
        except Exception:
            return {'status': 'error'}


# Singleton
redis_config = RedisConfig()
