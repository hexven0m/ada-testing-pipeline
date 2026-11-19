"""Full unchanged frontend visits in three approved, already-open Octo profiles."""
import fcntl,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
from urllib.request import urlopen
from octo_test_tab import octo_test_tab
ROOT=Path(__file__).resolve().parent
pins=json.loads((ROOT/'source-pins.json').read_text())
assert {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'candidate').glob('*.js')}==pins
lock=open('/tmp/adatest.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
approved=json.loads((ROOT/'approved-private.json').read_text())
def active():
 with urlopen('http://127.0.0.1:58888/api/profiles/active',timeout=5) as r:data=json.load(r)
 assert isinstance(data,list)
 return data
def binding(identity):
 row=next(r for r in active() if r.get('uuid')==identity)
 assert row.get('headless') is False and row.get('one_time') is False
 pid=row['browser_pid'];assert type(pid) is int
 cmd=subprocess.run(['ps','-p',str(pid),'-o','args='],capture_output=True,text=True,check=True).stdout
 assert 'Octium.app/' in cmd and not re.search(r'(?:^|\s)--headless(?:[=\s]|$)',cmd)
 return pid
bindings=[dict(slot=i+1,identity_sha256=hashlib.sha256(v.encode()).hexdigest(),pid=binding(v),headless=False)
          for i,v in enumerate(approved)]
rows=[];record=dict(scope='Two repeated full original frontend visits per existing headed Mac Octo profile; server/source binding, no CDP original-call instrumentation',
 source_sha256=pins,bindings=bindings,rows=rows,raw_original_headless_completion='UNVERIFIED',
 profiles_started=0,profiles_stopped=0,profile_settings_changed=0,existing_tabs_closed=0,tab_cleanup_required=True)
def save():
 tmp=ROOT/'manual-results.tmp';tmp.write_text(json.dumps(record,indent=2)+'\n');os.chmod(tmp,0o600);tmp.replace(ROOT/'manual-results.json')
server=None;save()
try:
 with (ROOT/'server.log').open('x') as log:
  server=subprocess.Popen([sys.executable,str(ROOT/'serve_frontend_mode_diagnostic.py'),'--candidate',str(ROOT/'candidate'),
       '--templates',str(ROOT/'templates'),'--state',str(ROOT/'server'),'--host','127.0.0.1','--port','0'],
       stdout=log,stderr=subprocess.STDOUT)
 for _ in range(100):
  try:session=json.loads((ROOT/'server/private-session.json').read_text());break
  except (OSError,ValueError):time.sleep(.1)
 else:raise RuntimeError('SERVER_NOT_READY')
 manifest=json.loads((ROOT/'server/manifest.json').read_text())
 assert all(manifest['source_sha256']['/static/detections/'+f]==h for f,h in pins.items())
 assert manifest['original_template_sha256']==manifest['template_sha256']
 record['frontend_template_unchanged']=True;record['server_source_pins_verified']=True
 # Each visit gets a unique order and a new top-level test tab; no result-driven retries.
 for round in range(2):
  for i,identity in enumerate(approved):
   pid=binding(identity);order=round*3+i
   row=dict(round=round,slot=i+1,mode='headed',expected_framework='octo',expected_headless=False,
            native_profile_pid_binding_verified=True,pid=pid,order_number=order,state='UNKNOWN',started_at=time.time())
   url=f'http://127.0.0.1:{session["port"]}/_web?order_number={order}&session_id={session["session_id"]}'
   try:
    with octo_test_tab(pid,url,row):
     path=ROOT/'server'/f'payload-{order}.json'
     deadline=time.monotonic()+45
     while time.monotonic()<deadline:
      try:payload=json.loads(path.read_text());break
      except (OSError,ValueError):time.sleep(.2)
     else:payload=None
     if payload is not None:
      assert payload['order_number']==order and type(payload['headless']) is bool
      row.update(state='COLLECTOR_RECEIVED',submitted_framework=payload['submitted_framework'],headless=payload['headless'],
                 product_correct=payload['submitted_framework']==['octo'],mode_correct=payload['headless'] is False,
                 collided=len(payload['submitted_framework'])>1)
     else:row['reason']='NO_COLLECTOR_RECEIPT'
    row['profile_still_headed_and_bound']=binding(identity)==pid
   finally:
    rows.append(row);save();print(json.dumps({k:v for k,v in row.items() if k!='pid'}),flush=True)
 record['state']='FINISHED' if len(rows)==6 else 'INCOMPLETE';save()
finally:
 if server:
  server.terminate()
  try:server.wait(timeout=8)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
  record['server_stopped']=server.poll() is not None
 record['test_tab_cleanup_confirmed']=bool(rows) and all(row.get('test_tab_cleanup_confirmed') is True for row in rows)
 save()
