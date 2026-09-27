"""FastAPI app: read-only SSH audit of the inventory (hosts.yaml), plus the
network-reachability, WAF, API-connections and synchronization add-ons that
register their own routes via `management.install`/`synchronization.install`.
No route ever runs a remote write; every collection loop only ever updates
this app's own SQLite state and never the remote host."""
import json, os, sqlite3, threading, time, hashlib, getpass, shutil
from contextlib import contextmanager, asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from dataclasses import asdict
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from config import load_config
from collector import collect
from audit_engine import redact
from ssh import AUDIT_PATH
from network_audit import collect_network
from audit_retention import retain_attempt, display_audit

# Identifiants API : on complete l'environnement depuis le coffre Windows AVANT
# toute lecture. Sans cela, demarrer le serveur autrement que par le lanceur
# donnait une instance sans aucun secret, ou les cinq collectes echouaient avec
# des messages sans rapport apparent. Une variable deja definie n'est jamais
# ecrasee : le lanceur et les surcharges manuelles gardent la priorite.
import secret_store
SECRETS_CHARGES=secret_store.charger()
BASE=Path(__file__).parent
inventory_path = Path(os.getenv('OPSCONTROL_INVENTORY', str(BASE / 'hosts.yaml')))
if not inventory_path.exists():
    inventory_path = BASE / 'hosts.example.yaml'
cfg,HOSTS=load_config(str(inventory_path))
for h in HOSTS:
 h.setdefault('environment','À renseigner');h.setdefault('services',[]);h.setdefault('criticality','standard')
if len({h['key'] for h in HOSTS})!=len(HOSTS):raise ValueError('Clés inventaire dupliquées')
DB=Path(os.getenv('OPSCONTROL_DB', os.getenv('COCKPIT_DB', str(BASE/'data/state.sqlite3'))))
DB.parent.mkdir(parents=True,exist_ok=True)
@contextmanager
def connect():
 db=sqlite3.connect(DB,timeout=30)
 try:
  with db:yield db
 finally:db.close()
with connect() as db:
 db.execute('CREATE TABLE IF NOT EXISTS states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, ts TEXT, status TEXT, summary TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS network(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS audit_snapshots(key TEXT, ts TEXT, payload TEXT, PRIMARY KEY(key,ts))')
 # Purge et fiche serveur filtrent l'historique par clé : sans index, balayage complet a chaque audit.
 db.execute('CREATE INDEX IF NOT EXISTS history_key ON history(key,id)')
 for key,payload in db.execute('SELECT key,payload FROM states').fetchall():
  recorded=json.loads(payload)
  if recorded.get('collected_at'):db.execute('INSERT OR IGNORE INTO audit_snapshots VALUES(?,?,?)',(key,recorded['collected_at'],payload))
WORKERS=max(1,min(16,int(os.getenv('COCKPIT_WORKERS','4'))))
SNAPSHOT_DAYS=7
BATCH_EVERY=1800
batch_last=[0.0]
lock=threading.Lock();stop=threading.Event()
job={'running':False,'completed':0,'total':0,'error':None,'scope':'all','started_at':None}
def read_setting(name):
 try:
  with connect() as db:
   row=db.execute('SELECT value FROM settings WHERE name=?',(name,)).fetchone()
   return row[0] if row else None
 except sqlite3.Error:
  return None
def write_setting(name,value):
 try:
  with connect() as db:db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(name,str(value)))
 except sqlite3.Error:
  pass
def initial_monitoring():
 """Intervalle d'actualisation au demarrage.

 Ordre : dernier choix enregistre de l'operateur, puis variable d'environnement
 (valeur par defaut du lanceur ou du service), puis 0. L'ordre inverse faisait
 ecraser le choix de l'operateur a chaque redemarrage par le lanceur. Sans la persistance, demarrer autrement que
 par le lanceur remettait l'intervalle a 0 : plus aucune collecte automatique,
 les audits vieillissaient, et les etats reels basculaient en « Incomplet ».
 Des mesures anciennes peuvent alors rester affichees pendant plusieurs jours.

 On ne choisit jamais d'intervalle a la place de l'operateur : on restitue le
 sien. Lancer des audits SSH periodiques sans qu'il l'ait demande serait une
 charge imposee a son infrastructure."""
 brut=read_setting('monitor_interval') or os.getenv('OPSCONTROL_AUTO_INTERVAL') or '0'
 try:interval=int(brut)
 except (TypeError,ValueError):interval=0
 if interval not in (0,60,300,900):interval=0
 return {'interval':interval,'next_at':time.time() if interval else None}
monitor=initial_monitoring()
net_lock=threading.Lock()
net_job={'running':False,'completed':0,'total':0,'error':None}
def fingerprint(h):
 """Hash of the host fields/config that affect what gets collected. A stored
 configuration changes require a new audit; a prior observation for the same
 IP remains visible with an explicit configuration-change warning."""
 data={'cfg':asdict(cfg),'host':{k:h.get(k) for k in ['ip','role','services','user','port','key_path','ssh_host','ssh_config','collect_enabled']},'version':5}
 from waf_audit import is_waf_host
 if is_waf_host(h):data['waf_version']=2
 return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
def sanitize(v):
 """Recursively redact secrets from collected data before it is stored or served."""
 if isinstance(v,str):return redact(v)
 if isinstance(v,list):return [sanitize(x) for x in v]
 if isinstance(v,dict):return {k:sanitize(x) for k,x in v.items()}
 return v
def rows():
 """Inventory joined with each host's last stored audit (or an 'Audit initial
 requis' placeholder), marking results older than 15 minutes as stale."""
 with connect() as db:saved={k:(ip,json.loads(p)) for k,ip,p in db.execute('SELECT key,ip,payload FROM states')}
 out=[]
 for h in HOSTS:
  prior=saved.get(h['key'])
  s=display_audit(prior[1] if prior and prior[0]==h['ip'] else None,fingerprint(h))
  row={**h,**s}
  if row.get('waf'):
   from waf_findings import decorate
   decorate(row)
  out.append(row)
 return out
def refresh(selected,requester):
 """Audit `selected` hosts concurrently (up to WORKERS at a time) and persist
 each result plus a trimmed (20-entry) history. Runs in its own thread,
 started by `launch`; `job` is the only channel back to the API/UI."""
 try:
  with ThreadPoolExecutor(max_workers=WORKERS) as pool:
   futures={pool.submit(collect,h,cfg,requester):h for h in selected}
   for future in as_completed(futures):
    h=futures[future]
    try:result=sanitize(future.result())
    except Exception as exc:result={'status':'unknown','issues':['Erreur locale : '+redact(exc)],'checks':[],'findings':[],'collected_at':datetime.now(timezone.utc).isoformat(),'coverage':{'measured':0,'total':15}}
    result['fingerprint']=fingerprint(h)
    summary={'issues':result['issues'],'coverage':result.get('coverage',{}),'findings_count':len(result.get('findings',[]))}
    if result.get('waf'):
     sections=result['waf'].get('sections',{})
     summary['waf']={name:sections.get(section,{}).get('data',{}).get(field) for name,section,field in [('banned','fail2ban','currently_banned'),('requests','traffic','requests'),('errors_5xx_pct','traffic','errors_5xx_pct'),('alerts','modsecurity','alert_lines')]}
    with connect() as db:
     previous=db.execute('SELECT ip,payload FROM states WHERE key=?',(h['key'],)).fetchone()
     retained=retain_attempt(result,json.loads(previous[1]) if previous and previous[0]==h['ip'] else None)
     db.execute('INSERT OR REPLACE INTO states VALUES(?,?,?)',(h['key'],h['ip'],json.dumps(retained)))
     db.execute('INSERT OR REPLACE INTO audit_snapshots VALUES(?,?,?)',(h['key'],result['collected_at'],json.dumps(result)))
     # Rétention : les 20 derniers audits, plus UN par heure sur 7 jours. Avec un
     # réaudit toutes les 10 min, 20 audits ne couvraient que 3 h : trop peu pour
     # la tendance de remplissage des disques (alert_policy exige 12 h).
     cutoff=(datetime.now(timezone.utc)-timedelta(days=SNAPSHOT_DAYS)).isoformat()
     db.execute('DELETE FROM audit_snapshots WHERE key=? AND ts NOT IN (SELECT ts FROM audit_snapshots WHERE key=? ORDER BY ts DESC LIMIT 20) AND (ts<? OR ts NOT IN (SELECT min(ts) FROM audit_snapshots WHERE key=? GROUP BY substr(ts,1,13)))',(h['key'],h['key'],cutoff,h['key']))
     db.execute('INSERT INTO history(key,ts,status,summary) VALUES(?,?,?,?)',(h['key'],result['collected_at'],result['status'],json.dumps(summary)))
     db.execute('DELETE FROM history WHERE key=? AND id NOT IN (SELECT id FROM history WHERE key=? ORDER BY id DESC LIMIT 100)',(h['key'],h['key']))
    with lock:job['completed']+=1
 except Exception as exc:
  with lock:job['error']=redact(exc)
 finally:
  with lock:job['running']=False
def launch(selected,requester,scope):
 """Start `refresh` in a background thread unless one is already running for
 this job (batches never overlap); returns the (possibly already-running) job state."""
 with lock:
  if job['running']:return dict(job)
  job.update(running=True,completed=0,total=len(selected),error=None,scope=scope,started_at=datetime.now(timezone.utc).isoformat())
  threading.Thread(target=refresh,args=(selected,requester),daemon=True).start()
  return dict(job)
def network_rows():
 with connect() as db:saved={(k,ip):json.loads(p) for k,ip,p in db.execute('SELECT key,ip,payload FROM network')}
 empty={'collected_at':None,'ping':None,'ports':[],'ssh_key_known':None}
 return [{'key':h['key'],'name':h['name'],'ip':h['ip'],'environment':h['environment'],'role':h['role'],**saved.get((h['key'],h['ip']),empty)} for h in HOSTS]
def refresh_network(selected,requester):
 try:
  with ThreadPoolExecutor(max_workers=WORKERS) as pool:
   futures={pool.submit(collect_network,h,cfg):h for h in selected}
   for future in as_completed(futures):
    h=futures[future]
    try:result=sanitize(future.result())
    except Exception as exc:result={'collected_at':datetime.now(timezone.utc).isoformat(),'ping':None,'ports':[],'ssh_key_known':None,'error':redact(exc)}
    with connect() as db:db.execute('INSERT OR REPLACE INTO network VALUES(?,?,?)',(h['key'],h['ip'],json.dumps(result)))
    with net_lock:net_job['completed']+=1
  from synchronization import federate
  from asset_registry import enroll
  assets=federate(rows(),api_connections(),network_rows())['assets']
  with connect() as db:enroll(db,assets)
 except Exception as exc:
  with net_lock:net_job['error']=redact(exc)
 finally:
  with net_lock:net_job['running']=False
def launch_network(selected,requester):
 with net_lock:
  if net_job['running']:return dict(net_job)
  net_job.update(running=True,completed=0,total=len(selected),error=None)
  threading.Thread(target=refresh_network,args=(selected,requester),daemon=True).start()
  return dict(net_job)
def scheduler():
 """Fil de fond demarre avec l'application, declenche a chaque intervalle.

 Il n'audite PAS tout le parc en SSH : seulement les hotes nouvellement
 decouverts (initial_audit_hosts). Les audits existants sont conserves, et
 leur reactualisation reste une action explicite de l'operateur — 87 sessions
 SSH periodiques sont une charge qu'on ne s'impose pas sans le decider.
 Disponibilite reseau, sources API et traitements sont, eux, rafraichis ici.

 (La version precedente de ce commentaire annoncait un audit SSH complet :
 c'etait faux, et cela rendait incomprehensible le vieillissement des preuves.)"""
 while not stop.wait(1):
  with lock:
   critical_enabled=bool(monitor['interval'])
   due=monitor['interval'] and monitor['next_at'] and time.time()>=monitor['next_at']
   if due:monitor['next_at']=time.time()+monitor['interval']
  critical_tick(critical_enabled)
  # Voie rapide : toujours active, indépendante de l'intervalle choisi.
  if 'tier0_tick' in globals():tier0_tick()
  # Réaudit SSH en rotation (ssh_refresh.py) : réglage distinct, désactivé par défaut.
  if 'ssh_refresh_tick' in globals():ssh_refresh_tick()
  if due:
   from asset_registry import discover, initial_audit_hosts
   additions,_=discover(HOSTS,api_connections())
   if additions:add_discovered_hosts(additions)
   selected=initial_audit_hosts(rows())
   if selected:launch(selected,'audit-initial','nouveaux')
   launch_network(HOSTS,'monitoring-local')
   launch_api_sync()
   # Inventaire batch : une connexion SSH par hôte, pour des planifications qui
   # changent rarement. Relancé chaque minute (intervalle 60 s), il occupait le
   # bastion en continu et, avec la rotation SSH, provoquait des « banner exchange
   # timeout ». Au plus toutes les 30 min ; le bouton reste immédiat.
   if time.time()-batch_last[0]>=BATCH_EVERY:
    batch_last[0]=time.time();launch_batches()
@asynccontextmanager
async def lifespan(app):
 from run_opscontrol import application_tunnel
 with application_tunnel(api_connections):
  stop.clear();thread=threading.Thread(target=scheduler,daemon=True);thread.start()
  try:yield
  finally:stop.set();thread.join(2)
app=FastAPI(title='OpsControl — Infrastructure Operations Center',version='5.0.0',lifespan=lifespan)
# /api/overview pese ~1,8 Mo et part toutes les 30 s (5 s pendant un audit) : le JSON
# se compresse d'environ 10x. Starlette exclut text/event-stream : le flux SSE reste intact.
app.add_middleware(GZipMiddleware,minimum_size=2048)
@app.middleware('http')
async def guard(request:Request,call_next):
 # Webhook Zabbix : appel serveur à serveur, authentifié par son propre jeton (tier0.py).
 if request.method=='POST' and request.url.path!='/api/webhooks/zabbix':
  if request.headers.get('x-cockpit-request')!='1':return JSONResponse({'detail':'En-tête requis'},status_code=403)
  origin=request.headers.get('origin')
  if origin and origin!=str(request.base_url).rstrip('/'):return JSONResponse({'detail':'Origine refusée'},status_code=403)
 response=await call_next(request)
 response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Cache-Control']='no-store'
 return response
@app.get('/api/overview')
def overview():
 from synchronization import federate
 connections=api_connections()
 snapshot=federate(rows(), connections, network_rows())
 hosts=snapshot['assets']
 from asset_registry import enroll, backup_summaries
 with connect() as db:enroll(db,hosts)
 backups=backup_summaries(hosts,connections)
 for h in hosts:h['backup_summary']=backups[h['key']]
 counts={s:sum(h['status']==s for h in hosts) for s in ['ok','critical','warning','unreachable','unknown']}
 with lock:progress=dict(job);monitoring=dict(monitor)
 with net_lock:network_progress=dict(net_job)
 api_progress=api_sync_state()
 reasons={}
 for h in hosts:
  if h.get('scope_reason'):reasons[h['scope_reason']]=reasons.get(h['scope_reason'],0)+1
 # Sources dont la variable d'environnement est déclarée mais absente de CE
 # processus : aucune de leurs collectes ne peut aboutir. Remonté ici pour que
 # l'interface le dise une fois, globalement, au lieu de laisser l'opérateur
 # constater cinq échecs distincts sans en comprendre la cause commune.
 missing_auth=[c['name'] for c in connections if c.get('auth_configured') is False]
 # Liste allégée (payload_slim) : la fiche serveur /api/hosts/{clé} garde tout le détail.
 from payload_slim import slim
 return {'hosts':[slim(h) for h in hosts],'counts':counts,'job':progress,'monitoring':{**monitoring,'critical_interval':10},
         'missing_auth':missing_auth,
         'jobs':{'ssh':progress,'network':network_progress,'api':api_progress,'batch':batch_job()},
         'availability':{'exclusions':reasons,'sources':snapshot['sources']}}
@app.post('/api/refresh',status_code=202)
def global_refresh(request:Request):
 return launch(HOSTS,request.client.host if request.client else 'local','all')
@app.post('/api/hosts/{key}/refresh',status_code=202)
def host_refresh(key:str,request:Request):
 selected=[h for h in HOSTS if h['key']==key]
 if not selected:raise HTTPException(404,'Serveur inconnu')
 return launch(selected,request.client.host if request.client else 'local',key)
@app.get('/api/hosts/{key}')
def detail(key:str):
 from synchronization import federate
 from asset_registry import source_details
 connections=api_connections();assets=federate(rows(),connections,network_rows())['assets']
 for h in assets:
  if h['key']==key:
   with connect() as db:h['history']=[{'ts':ts,'status':status,**json.loads(summary)} for ts,status,summary in db.execute('SELECT ts,status,summary FROM history WHERE key=? ORDER BY id DESC LIMIT 20',(key,))]
   h['source_details']=source_details(h,assets,connections)
   batches=batch_snapshot()
   h['batches']=[j for j in batches['jobs'] if j.get('host_key')==key]
   h['batch_coverage']=next((c for c in batches['coverage'] if c['host_key']==key),{})
   with connect() as db:snapshots=[json.loads(payload) for payload, in db.execute('SELECT payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC LIMIT 20',(key,))]
   h['audit_versions']=[{'collected_at':s.get('collected_at'),'status':s.get('status')} for s in snapshots]
   from server_alerts import build as server_alerts
   h['alerts']=server_alerts(h,snapshots)
   return h
 raise HTTPException(404,'Serveur inconnu')
@app.get('/api/hosts/{key}/audits')
def saved_audit(key:str,at:str):
 if not any(h['key']==key for h in HOSTS):raise HTTPException(404,'Serveur inconnu')
 with connect() as db:row=db.execute('SELECT payload FROM audit_snapshots WHERE key=? AND ts=?',(key,at)).fetchone()
 if row is None:raise HTTPException(404,'Audit absent')
 return json.loads(row[0])
class Monitoring(BaseModel):
 model_config=ConfigDict(extra='forbid')
 interval:int
@app.post('/api/monitoring')
def monitoring(settings:Monitoring):
 if settings.interval not in (0,60,300,900):raise HTTPException(422,'Intervalle autorisé : 0, 60, 300 ou 900 secondes')
 with lock:
  monitor.update(interval=settings.interval,next_at=time.time()+settings.interval if settings.interval else None)
 # Hors du verrou : le choix survit au redemarrage, quel que soit le mode de lancement.
 write_setting('monitor_interval',settings.interval)
 with lock:return dict(monitor)
@app.get('/api/services')
def services_all():
 """Toutes les unités observées, par serveur : la page Services (retirées de /api/overview)."""
 from payload_slim import services
 return services(rows())
@app.get('/api/network')
def network_overview():
 with net_lock:progress=dict(net_job)
 return {'hosts':network_rows(),'job':progress}
@app.post('/api/network/refresh',status_code=202)
def network_refresh(request:Request):
 return launch_network(HOSTS,request.client.host if request.client else 'local')
@app.post('/api/network/hosts/{key}/refresh',status_code=202)
def network_host_refresh(key:str,request:Request):
 selected=[h for h in HOSTS if h['key']==key]
 if not selected:raise HTTPException(404,'Serveur inconnu')
 return launch_network(selected,request.client.host if request.client else 'local')
@app.get('/api/inventory-report')
def inventory_report():
 path = BASE / 'inventory-report.json'
 if not path.exists():path = BASE / 'inventory-report.example.json'
 return json.loads(path.read_text(encoding='utf-8'))
@app.get('/api/runtime')
def runtime():
 def present(path):
  try:return Path(path).expanduser().is_file()
  except OSError:return None
 return {'transport':cfg.transport,'local_user':getpass.getuser(),'home':str(Path.home()),'ssh_executable':shutil.which('ssh'),'key_path':str(Path(cfg.key_path).expanduser()),'key_exists':present(cfg.key_path),'config_path':cfg.config_path or str(Path.home()/'.ssh/config'),'config_exists':present(cfg.config_path or str(Path.home()/'.ssh/config')),'known_hosts_exists':present(Path.home()/'.ssh/known_hosts'),'audit_path':str(AUDIT_PATH.resolve()),'workers':WORKERS,'hint':'Configuration OpenSSH locale reprise, y compris ProxyJump. Les empreintes doivent être vérifiées manuellement.'}
import management, sys
management.install(app, sys.modules[__name__])
import critical_monitor
critical_monitor.install(sys.modules[__name__])
import tier0
tier0.install(app, sys.modules[__name__])
import ssh_refresh
ssh_refresh.install(app, sys.modules[__name__])
import inventory_completion
inventory_completion.install(app, sys.modules[__name__])
import synchronization
synchronization.install(app, sys.modules[__name__])
import realtime
realtime.install(app, sys.modules[__name__])
import batch_monitor, daily_view
batch_monitor.install(app, sys.modules[__name__])
daily_view.install(app, sys.modules[__name__])
import shares_view, alert_center
shares_view.install(app, sys.modules[__name__])
alert_center.install(app, sys.modules[__name__])
app.mount('/',StaticFiles(directory=str(BASE/'web'),html=True),name='web')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
