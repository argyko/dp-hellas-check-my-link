import os
from app.pipeline import run_scan
from app.security.limits import MAX_CONCURRENT_SCANS

try:
    from celery import Celery
    import redis
    celery=Celery('check_my_link',broker=os.getenv('REDIS_URL','redis://redis:6379/0'),backend=os.getenv('REDIS_URL','redis://redis:6379/0'))
    celery.conf.update(
        task_track_started=True, task_acks_late=True, worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True, task_time_limit=int(os.getenv('MAX_SCAN_TIMEOUT_SECONDS','180')),
        task_soft_time_limit=max(30, int(os.getenv('MAX_SCAN_TIMEOUT_SECONDS','180'))-15),
        worker_max_tasks_per_child=50,
    )
    def _acquire_slot():
        r=redis.Redis.from_url(os.getenv('REDIS_URL','redis://redis:6379/0'))
        value=r.incr('scan:global:active')
        if value > MAX_CONCURRENT_SCANS:
            r.decr('scan:global:active')
            return None
        return r
    def _release_slot(r):
        if r:
            try: r.decr('scan:global:active')
            except Exception: pass
    @celery.task(name='scan.run', autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={'max_retries':2})
    def run_scan_task(scan_id, url):
        slot=_acquire_slot()
        if slot is None:
            raise RuntimeError('Global scan concurrency limit reached.')
        try:
            return run_scan(scan_id,url)
        finally:
            _release_slot(slot)
except ImportError:
    celery=None
    def run_scan_task(scan_id,url): return run_scan(scan_id,url)
