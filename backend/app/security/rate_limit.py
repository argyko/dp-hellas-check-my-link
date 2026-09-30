from __future__ import annotations
import os
import time
import redis

class RateLimitExceeded(RuntimeError):
    pass

def _redis():
    return redis.Redis.from_url(os.getenv('REDIS_URL','redis://redis:6379/0'), decode_responses=True)

def check_rate_limit(identity: str, limit: int | None = None, window_seconds: int | None = None) -> tuple[bool,int]:
    limit = limit or int(os.getenv('SCAN_RATE_LIMIT', '10'))
    window_seconds = window_seconds or int(os.getenv('SCAN_RATE_WINDOW_SECONDS', '60'))
    bucket = int(time.time() // window_seconds)
    key = f'ratelimit:scan:{identity}:{bucket}'
    r = _redis()
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, window_seconds + 5)
    count, _ = pipe.execute()
    return count <= limit, max(0, limit - count)


def check_daily_quota(identity: str, quota: int | None = None) -> tuple[bool,int]:
    quota = quota or int(os.getenv('DAILY_SCAN_QUOTA', '100'))
    day = time.strftime('%Y-%m-%d', time.gmtime())
    key = f'quota:scan:{identity}:{day}'
    r=_redis(); pipe=r.pipeline(); pipe.incr(key); pipe.expire(key, 172800); count,_=pipe.execute()
    return count <= quota, max(0, quota-count)
