import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_audit_persistence():
    from app import database
    old=database.DB_URL
    fd,path=tempfile.mkstemp(); os.close(fd)
    database.DB_URL='sqlite:///'+path
    try:
        database.init_db(); sid=database.create_scan('https://example.com')
        database.add_scan_event(sid,'trace-1','SCAN_STARTED','pipeline',status='RUNNING')
        database.add_scan_event(sid,'trace-1','STEP_COMPLETED','http',status='OK',duration_ms=12.3,metadata={'status_code':200})
        events=database.get_scan_events(sid)
        assert len(events)==2 and events[1]['metadata']['status_code']==200
    finally:
        database.DB_URL=old
        try: os.unlink(path)
        except OSError: pass

def test_json_formatter():
    from app.observability import JsonFormatter
    import logging, json
    r=logging.LogRecord('x',logging.INFO,'',0,'hello',(),None)
    r.event_data={'event':'test','scan_id':'abc'}
    d=json.loads(JsonFormatter().format(r))
    assert d['event']=='test' and d['scan_id']=='abc'
