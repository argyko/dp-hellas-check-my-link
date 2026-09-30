import json, os, sqlite3, uuid
from datetime import datetime, timezone

DB_URL = os.getenv('DATABASE_URL', 'postgresql://checklink:checklink@localhost:5432/check_my_link')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY,
 url TEXT NOT NULL,
 owner_id TEXT NOT NULL DEFAULT 'anonymous',
 status TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 result_json JSONB,
 error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_status_created ON scans(status, created_at);
CREATE TABLE IF NOT EXISTS scan_events (
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, trace_id TEXT NOT NULL,
 event_type TEXT NOT NULL, component TEXT NOT NULL, status TEXT,
 duration_ms DOUBLE PRECISION, metadata_json JSONB, created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_created ON scan_events(scan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_events_trace ON scan_events(trace_id);
'''

def _is_sqlite(): return DB_URL.startswith('sqlite:///')
def _sqlite_path(): return DB_URL.replace('sqlite:///','',1)

def _connect():
    if _is_sqlite():
        con=sqlite3.connect(_sqlite_path()); con.row_factory=sqlite3.Row; return con
    import psycopg
    return psycopg.connect(DB_URL)

def init_db():
    con=_connect()
    try:
        if _is_sqlite():
            con.execute('''CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, url TEXT NOT NULL, owner_id TEXT NOT NULL DEFAULT 'anonymous', status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, result_json TEXT, error TEXT)''')
            con.execute('''CREATE TABLE IF NOT EXISTS scan_events (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, trace_id TEXT NOT NULL, event_type TEXT NOT NULL, component TEXT NOT NULL, status TEXT, duration_ms REAL, metadata_json TEXT, created_at TEXT NOT NULL)''')
            con.execute('CREATE INDEX IF NOT EXISTS idx_scan_events_scan_created ON scan_events(scan_id, created_at)')
            con.execute('CREATE INDEX IF NOT EXISTS idx_scan_events_trace ON scan_events(trace_id)')
        else:
            with con.cursor() as cur: cur.execute(SCHEMA)
        con.commit()
        # Backward-compatible migration for v1.8 databases.
        try:
            if _is_sqlite(): con.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'anonymous'")
            else:
                with con.cursor() as cur: cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS owner_id TEXT NOT NULL DEFAULT 'anonymous'")
            con.commit()
        except Exception:
            pass
    finally: con.close()

def create_scan(url, owner_id='anonymous'):
    sid=str(uuid.uuid4()); now=datetime.now(timezone.utc)
    con=_connect()
    try:
        if _is_sqlite():
            con.execute('INSERT INTO scans (id,url,owner_id,status,created_at,updated_at,result_json,error) VALUES (?,?,?,?,?,?,?,?)',(sid,url,owner_id,'QUEUED',now.isoformat(),now.isoformat(),None,None))
        else:
            with con.cursor() as cur: cur.execute('INSERT INTO scans (id,url,owner_id,status,created_at,updated_at,result_json,error) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',(sid,url,owner_id,'QUEUED',now,now,None,None))
        con.commit(); return sid
    finally: con.close()

def update_scan(sid,status,result=None,error=None):
    now=datetime.now(timezone.utc); payload=json.dumps(result,ensure_ascii=False) if result is not None else None
    con=_connect()
    try:
        if _is_sqlite(): con.execute('UPDATE scans SET status=?,updated_at=?,result_json=?,error=? WHERE id=?',(status,now.isoformat(),payload,error,sid))
        else:
            with con.cursor() as cur: cur.execute('UPDATE scans SET status=%s,updated_at=%s,result_json=%s,error=%s WHERE id=%s',(status,now,payload,error,sid))
        con.commit()
    finally: con.close()

def get_scan(sid, owner_id=None, admin=False):
    con=_connect()
    try:
        if _is_sqlite(): row=con.execute('SELECT * FROM scans WHERE id=?' + ('' if admin or owner_id is None else ' AND owner_id=?'), ((sid,) if admin or owner_id is None else (sid,owner_id))).fetchone(); d=dict(row) if row else None
        else:
            with con.cursor() as cur:
                cur.execute('SELECT id,url,owner_id,status,created_at,updated_at,result_json,error FROM scans WHERE id=%s' + ('' if admin or owner_id is None else ' AND owner_id=%s'), ((sid,) if admin or owner_id is None else (sid,owner_id))); row=cur.fetchone()
            d=dict(zip(['id','url','owner_id','status','created_at','updated_at','result_json','error'],row)) if row else None
        if not d: return None
        raw=d.pop('result_json',None)
        d['result']=json.loads(raw) if isinstance(raw,str) else raw
        return d
    finally: con.close()


def add_scan_event(scan_id, trace_id, event_type, component, status=None, duration_ms=None, metadata=None):
    now=datetime.now(timezone.utc); eid=str(uuid.uuid4()); payload=json.dumps(metadata, ensure_ascii=False, default=str) if metadata is not None else None
    con=_connect()
    try:
        if _is_sqlite():
            con.execute('INSERT INTO scan_events VALUES (?,?,?,?,?,?,?,?,?)',(eid,scan_id,trace_id,event_type,component,status,duration_ms,payload,now.isoformat()))
        else:
            with con.cursor() as cur:
                cur.execute('INSERT INTO scan_events (id,scan_id,trace_id,event_type,component,status,duration_ms,metadata_json,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',(eid,scan_id,trace_id,event_type,component,status,duration_ms,payload,now))
        con.commit()
    finally: con.close()

def get_scan_events(scan_id):
    con=_connect()
    try:
        if _is_sqlite():
            rows=con.execute('SELECT id,scan_id,trace_id,event_type,component,status,duration_ms,metadata_json,created_at FROM scan_events WHERE scan_id=? ORDER BY created_at',(scan_id,)).fetchall()
            out=[]
            for r in rows:
                d=dict(r); d['metadata']=json.loads(d.pop('metadata_json')) if d.get('metadata_json') else None; out.append(d)
            return out
        with con.cursor() as cur:
            cur.execute('SELECT id,scan_id,trace_id,event_type,component,status,duration_ms,metadata_json,created_at FROM scan_events WHERE scan_id=%s ORDER BY created_at',(scan_id,)); rows=cur.fetchall()
        keys=['id','scan_id','trace_id','event_type','component','status','duration_ms','metadata','created_at']
        return [dict(zip(keys,r)) for r in rows]
    finally: con.close()


def count_active_scans(owner_id: str) -> int:
    con=_connect()
    try:
        if _is_sqlite():
            row=con.execute("SELECT COUNT(*) FROM scans WHERE owner_id=? AND status IN ('QUEUED','RUNNING')", (owner_id,)).fetchone()
            return int(row[0])
        with con.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM scans WHERE owner_id=%s AND status IN ('QUEUED','RUNNING')", (owner_id,))
            return int(cur.fetchone()[0])
    finally: con.close()
