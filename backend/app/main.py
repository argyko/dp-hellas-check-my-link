from __future__ import annotations
import os
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from app.database import init_db, create_scan, get_scan, get_scan_events, count_active_scans
from app.worker import run_scan_task
from app.security.limits import MAX_REQUEST_BODY_BYTES
from app.security.network_policy import validate_network_policy, NetworkPolicyError
from app.security.rate_limit import check_rate_limit, check_daily_quota
from app.observability import configure_logging, log_event
from app.security.auth import require_api_key, require_admin, validate_production_auth_config, Principal

configure_logging()
app=FastAPI(title='DP Hellas Check My Link API',version='1.9.0',description='Production-oriented asynchronous URL security scanning backend.')
origins=[o.strip() for o in os.getenv('CORS_ORIGINS','http://localhost:3000').split(',') if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=['GET','POST','OPTIONS'], allow_headers=['Content-Type','X-API-Key','X-Admin-Key'])
init_db()
validate_production_auth_config()

class ScanRequest(BaseModel):
    url: HttpUrl

def _client_identity(request: Request) -> str:
    if os.getenv('TRUST_PROXY','false').lower() in {'1','true','yes','on'}:
        forwarded=request.headers.get('x-forwarded-for')
        if forwarded: return forwarded.split(',')[0].strip()
    return request.client.host if request.client else 'unknown'

@app.middleware('http')
async def request_limits(request: Request, call_next):
    content_length=request.headers.get('content-length')
    if content_length:
        try:
            if int(content_length)>MAX_REQUEST_BODY_BYTES:
                return JSONResponse({'detail':'Request body too large.'},status_code=413)
        except ValueError:
            return JSONResponse({'detail':'Invalid Content-Length.'},status_code=400)
    if request.url.path=='/api/v1/scan' and request.method=='POST':
        try: body=await request.body()
        except Exception: return JSONResponse({'detail':'Invalid request body.'},status_code=400)
        if len(body)>MAX_REQUEST_BODY_BYTES: return JSONResponse({'detail':'Request body too large.'},status_code=413)
        try: allowed,remaining=check_rate_limit(_client_identity(request))
        except Exception:
            if os.getenv('RATE_LIMIT_FAIL_OPEN','false').lower() not in {'1','true','yes','on'}:
                return JSONResponse({'detail':'Rate limiter unavailable.'},status_code=503)
            allowed,remaining=True,0
        if not allowed:
            return JSONResponse({'detail':'Too many scan requests. Try again later.','remaining':0},status_code=429,headers={'Retry-After':'60'})
    return await call_next(request)

@app.get('/health')
def health():
    db='ok'; redis='ok'; network='ok'; auth='ok'
    try: init_db()
    except Exception: db='error'
    try:
        import redis as redis_lib
        redis_lib.Redis.from_url(os.getenv('REDIS_URL','redis://redis:6379/0'),socket_connect_timeout=1).ping()
    except Exception: redis='error'
    try: validate_network_policy()
    except NetworkPolicyError: network='error'
    try: validate_production_auth_config()
    except RuntimeError: auth='error'
    status='ok' if all(x=='ok' for x in (db,redis,network,auth)) else 'degraded'
    return {'status':status,'service':'dp-hellas-check-my-link','version':'1.9.0','dependencies':{'database':db,'redis':redis,'network_policy':network,'auth_config':auth}}

@app.post('/api/v1/scan',status_code=202)
def create(payload: ScanRequest, principal: Principal = Depends(require_api_key)):
    try: validate_network_policy()
    except NetworkPolicyError as exc: raise HTTPException(status_code=503,detail=str(exc))
    if count_active_scans(principal.key_id)>=int(os.getenv('MAX_ACTIVE_SCANS_PER_KEY','2')):
        raise HTTPException(status_code=429,detail='Active scan quota exceeded.')
    quota_ok,_=check_daily_quota(principal.key_id)
    if not quota_ok: raise HTTPException(status_code=429,detail='Daily scan quota exceeded.')
    sid=create_scan(str(payload.url),principal.key_id)
    if hasattr(run_scan_task,'delay'): run_scan_task.delay(sid,str(payload.url))
    else: run_scan_task(sid,str(payload.url))
    log_event('scan.queued',scan_id=sid,owner_id=principal.key_id)
    return {'scan_id':sid,'status':'QUEUED'}

@app.get('/api/v1/scan/{scan_id}')
def get(scan_id:str, principal: Principal = Depends(require_api_key)):
    row=get_scan(scan_id,principal.key_id,admin=(principal.role=='admin'))
    if not row: raise HTTPException(status_code=404,detail='Scan not found')
    return row

@app.get('/api/v1/scan/{scan_id}/audit')
def audit(scan_id:str, principal: Principal = Depends(require_admin)):
    row=get_scan(scan_id,admin=True)
    if not row: raise HTTPException(status_code=404,detail='Scan not found')
    return {'scan_id':scan_id,'events':get_scan_events(scan_id)}
