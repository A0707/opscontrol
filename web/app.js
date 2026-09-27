const $=s=>document.querySelector(s);
const esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels={ok:'OK',critical:'Critique',warning:'À surveiller',unreachable:'Injoignable',unknown:'Incomplet',pass:'Concluant',fail:'Anomalie',observed:'Observé',active:'Actif',failed:'Échec',inactive:'Inactif'};
const badge=s=>'<span class="badge '+(Object.hasOwn(labels,s)?s:'unknown')+'">● '+esc(labels[s]||s)+'</span>';
const stamp=v=>v?new Date(v).toLocaleString('fr-FR'):'Jamais collecté';
const pct=v=>v==null?'—':esc(v)+' %';
let state=null,page='Vue globale',selected=null,hostDetail=null,detailTab='problems',filters={q:'',status:'',environment:'',role:''},mode='incidents',renderId=0,loading=false,netState=null;
async function api(url,options){const r=await fetch(url,options);if(!r.ok)throw Error('Erreur '+r.status+' : '+await r.text());return r.json()}
async function post(url,body){return api(url,{method:'POST',headers:{'X-Cockpit-Request':'1','Content-Type':'application/json'},body:JSON.stringify(body||{})})}
function toast(text){$('#toast').textContent=text;setTimeout(()=>$('#toast').textContent='',2800)}
let lastHostSnapshot='', lastDetailSnapshot='', lastSourceRefresh=0;
const pageFilters=new Map();
// The clock is not a new observation. Keep the investigation mounted on polling.
function detailSignature(result){
 const alerts=result.alerts;
 return JSON.stringify({...result,alerts:alerts?{...alerts,generated_at:undefined,
  items:(alerts.items||[]).map(({duration_seconds,duration_until,...evidence})=>evidence)}:alerts});
}
function restoreDetailFocus(id,start,end){
 const el=id&&document.getElementById(id);if(!el)return;
 el.focus({preventScroll:true});
 if(start!=null&&typeof el.setSelectionRange==='function')el.setSelectionRange(start,end??start);
}
function backupBadge(h){
 const b=h.backup_summary;
 if(!b?.matched)return '<span class="badge unknown">Aucun job associé</span>';
 const texts={ok:'Derniers jobs réussis',critical:'Dernier passage en erreur',warning:'Avertissement',running:'Job en cours',pending:'Job en attente',unknown:'Résultat non mesuré'};
 const color=b.fresh?({ok:'ok',critical:'critical',warning:'warning',running:'active'}[b.severity]||'unknown'):'unknown';
 return '<button class="link" data-host="'+esc(h.key)+'"><span class="badge '+color+'">'+esc(texts[b.severity]||texts.unknown)+'</span></button><small>'+esc(b.jobs_count)+' job(s) · '+(b.fresh?'Collecte récente':'À reconfirmer')+'</small><small>'+stamp(b.collected_at)+'</small>';
}

// Chaque page adossée à une source API y inscrit son chargeur : la couche de
// base déclare l'emplacement, les modules le remplissent. L'inverse — app.js
// citant loadWazuh(), loadZabbix()… — rendait le socle dépendant de fichiers
// chargés après lui.
const sourceLoaders={};
async function load(){
 // On ne sollicite pas le serveur ni tout le parc pour un onglet que personne
 // ne regarde. Le rattrapage est assuré par l'écouteur visibilitychange plus bas ;
 // sans lui, ouvrir OpsControl dans un onglet d'arrière-plan laissait l'interface
 // vide jusqu'à la prochaine minuterie, soit 30 secondes.
 if(loading||document.hidden)return;
 loading=true;
 try{
  const data=await api('/api/overview');
  const snapshot=JSON.stringify(data.hosts);
  const changed=snapshot!==lastHostSnapshot;
  const initial=!state;
  state=data;lastHostSnapshot=snapshot;
  // Un secret manquant rend TOUTES les collectes d'une source impossibles. On le
  // dit une fois, globalement et en nommant la manoeuvre : sans ça, l'opérateur
  // ne voit que cinq échecs distincts sans cause commune apparente.
  const sansSecret=state.missing_auth||[];
  $('#error').textContent=state.job.error||(sansSecret.length
   ?'Identifiants absents pour '+sansSecret.length+' source'+(sansSecret.length>1?'s':'')+' ('+sansSecret.join(', ')+') : aucune collecte API ne peut aboutir. Arrêter ce serveur et le relancer avec LANCER-OPSCONTROL.ps1 en saisissant les secrets.'
   :'');
  const jobs=state.jobs||{ssh:state.job};
  document.querySelectorAll('[data-audit-host]').forEach(button=>button.disabled=Boolean(state.job.running));
  $('#refresh').disabled=Object.values(jobs).some(j=>j.running);
  $('#interval').value=String(state.monitoring.interval);
  $('#progress').textContent=Object.entries(jobs).map(([name,j])=>name.toUpperCase()+' : '+(j.running?(j.completed||0)+' / '+(j.total||0):'au repos')).join(' · ')+(state.monitoring.interval?' · Automatique toutes les '+state.monitoring.interval/60+' min · Incidents Zabbix : 10 s':' · Actualisation manuelle');
  if(selected){
   const key=selected, result=await api('/api/hosts/'+encodeURIComponent(key));
   if(selected!==key)return;
   const signature=detailSignature(result);
   hostDetail=result;
   if(signature!==lastDetailSnapshot){lastDetailSnapshot=signature;render();}
  }else{
   // sourceLoaders est un point d'extension rempli par chaque module de page
   // (voir plus bas sa déclaration) : app.js n'a plus à connaître leurs noms.
   // Keep the source page and its controls mounted while SSH jobs progress.
   if(!initial&&sourceLoaders[page]){
    if(Date.now()-lastSourceRefresh>30000){lastSourceRefresh=Date.now();await sourceLoaders[page]();}
   }else if(initial||changed)render();
  }
 }catch(e){$('#error').textContent=e.message}finally{loading=false}
}
$('#refresh').onclick=async()=>{try{await post('/api/refresh');await load()}catch(e){$('#error').textContent=e.message}};
$('#interval').onchange=async e=>{try{await post('/api/monitoring',{interval:Number(e.target.value)});await load()}catch(error){$('#error').textContent=error.message}};
function navigate(p){if(page===p&&!selected)return;pageFilters.set(page,{...filters});page=p;selected=null;hostDetail=null;filters={...(pageFilters.get(p)||{q:'',status:'',environment:'',role:''})};render();window.scrollTo(0,0)}
$('#nav').onclick=e=>{const b=e.target.closest('[data-page]');if(b)navigate(b.dataset.page)};
function coverage(h){const c=h.coverage||{measured:0,total:15};return (h.stale?'Obsolète · ':'')+esc(c.measured)+' / '+esc(c.total)}
function incidents(hosts,includeUnknown=false){return hosts.flatMap(h=>(h.findings||[]).filter(f=>includeUnknown?f.severity==='unknown':f.severity!=='unknown').map(f=>({h,f}))).sort((a,b)=>({critical:0,unreachable:0,warning:1,unknown:2}[a.f.severity]??2)-({critical:0,unreachable:0,warning:1,unknown:2}[b.f.severity]??2))}
function command(label,text){return '<div class="command"><div class="panel-head"><b>'+esc(label)+'</b><button data-copy="'+esc(text||'')+'">Copier</button></div><pre>'+esc(text||'Commande à définir après diagnostic')+'</pre></div>'}
function issue(h,f){return '<article class="panel issue '+esc(f.severity)+'"><header><div>'+badge(f.severity)+' <span class="mini">'+esc(f.domain)+'</span><h3>'+esc(f.title)+'</h3><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+' · '+esc(h.ip)+'</button></div><span class="mini">'+stamp(h.collected_at)+(h.stale?' · PREUVE OBSOLÈTE':'')+'</span></header><details><summary>Preuve collectée</summary><div class="evidence">'+esc(f.evidence)+'</div></details><p class="note">'+esc(f.scope)+'</p><div class="commands">'+command('1. Vérifier',f.check_command)+command(f.requires_adaptation?'2. Préparer la correction':'2. Correction proposée',f.solution_command)+'</div><p class="note">'+esc(f.precaution)+'</p><p class="mini">Copie uniquement · aucune commande de correction exécutée par la plateforme.</p></article>'}
function checks(h){return (h.checks||[]).map(c=>'<details class="panel"><summary>'+badge(c.status)+' '+esc(c.title)+'</summary><p class="note">Commande de contrôle en lecture seule</p><pre>'+esc(c.command)+'</pre><p>Preuve</p><pre>'+esc(c.evidence)+'</pre>'+(c.error?'<p>'+esc(c.error)+'</p>':'')+'</details>').join('')||'<div class="empty">Lancer un audit pour afficher les contrôles et leurs preuves.</div>'}
// Audit age and coverage are different from current server availability.
function hostAuditBadge(h){
 const measured=(h.coverage?.measured||0)>0;
 if(!measured)return '<span class="badge unknown">● Audit non mesuré</span>';
 if(h.stale&&measured)return '<span class="badge unknown">● Audit ancien</span><small>Dernier audit : '+esc(labels[h.audit_status||h.last_status]||'État non mesuré')+'</small>';
 if(h.status==='unknown')return '<span class="badge unknown">● '+(measured?'Audit partiel':'Audit non mesuré')+'</span>';
 return badge(h.status);
}
function detailView(h){let html='<div class="panel"><div class="detail-banner"><div><button data-go="Serveurs">← Serveurs</button><h2>'+esc(h.name)+' '+hostAuditBadge(h)+'</h2><p>'+esc(h.ip)+' · '+esc(h.environment)+' · '+esc(h.role)+'</p><p>SSH : '+esc(h.ssh_user)+' · port '+esc(h.ssh_port)+' · '+freshnessMarkup(h.collected_at,'Mesures SSH',30)+'</p></div><div><button class="primary" data-audit-host="'+esc(h.key)+'" '+(state.job.running?'disabled':'')+'>↻ Auditer ce serveur</button><button data-export>Exporter l’audit JSON</button></div></div>'+(h.stale?'<p class="instruction">Mesures obsolètes. Refaire les vérifications avant toute correction.</p>':'')+'<div class="detail-grid">'+[['CPU',pct(h.cpu)],['RAM',pct(h.ram)],['Disque max',pct(h.disk_max)]].map(([k,v])=>'<div class="card">'+k+'<strong>'+v+'</strong></div>').join('')+'</div><p class="note">Couverture : '+coverage(h)+' contrôles renseignés. Cela ne constitue pas une certification de sécurité.</p></div><div class="tabs">'+[['problems','Problèmes et commandes'],['checks','Audit détaillé'],['services','Services'],['inventory','Inventaire'],['history','Historique']].map(([k,v])=>'<button class="'+(detailTab===k?'active':'')+'" data-tab="'+k+'">'+v+'</button>').join('')+'</div>';
 if(detailTab==='problems')html+=(h.findings||[]).map(f=>issue(h,f)).join('')||'<div class="panel empty">'+esc((h.issues||[]).join(' · ')||'Aucune anomalie sur les contrôles accessibles.')+'</div>';
 if(detailTab==='checks')html+=checks(h)+'<details class="panel"><summary>Tentatives de connexion SSH</summary><pre>'+esc(JSON.stringify(h.attempts||[],null,2))+'</pre></details>';
 if(detailTab==='services')html+='<div class="panel"><h2>Services observés</h2><p>Les unités inactives non déclarées critiques ne déclenchent pas d’alerte. Les unités failed en déclenchent une.</p><div class="table"><table><thead><tr><th>Unité</th><th>État</th><th>Critique configurée</th></tr></thead><tbody>'+(h.all_services||[]).map(s=>'<tr><td>'+esc(s.name)+'</td><td>'+badge(s.status)+'</td><td>'+(s.configured?'Oui':'Non')+'</td></tr>').join('')+'</tbody></table></div></div>';
 if(detailTab==='inventory')html+='<div class="panel"><h2>Informations documentaires</h2><p>Nœud : '+esc(h.node)+' · VMID : '+esc(h.vmid)+'</p><p>'+esc((h.inventory_warnings||[]).join(' · '))+'</p><p class="note">Informations historiques du classeur ; aucun état live déduit.</p><pre>'+esc(JSON.stringify(h.documented||{},null,2))+'</pre><h3>Sources</h3><pre>'+esc((h.inventory_sources||[]).join('\n'))+'</pre></div>';
 if(detailTab==='history')html+='<div class="panel"><h2>20 derniers audits — résumés</h2>'+(h.history||[]).map(x=>'<div class="row">'+badge(x.status)+'<div>'+stamp(x.ts)+'<p>'+esc((x.issues||[]).join(' · '))+'</p></div></div>').join('')+'</div>';
 return html;
}
function netBadge(v){return v===true?'<span class="badge ok">● Oui</span>':v===false?'<span class="badge critical">● Non</span>':'<span class="badge unknown">● Inconnu</span>'}
async function renderNetwork(id){
 const target=$('#net');if(!target)return;
 try{netState=await api('/api/network');if(id!==renderId)return;
 const p=$('#netprogress');if(p)p.textContent=netState.job.running?'Vérification en cours : '+netState.job.completed+' / '+netState.job.total+' serveurs':'';
 document.querySelectorAll('[data-net-refresh]').forEach(b=>b.disabled=netState.job.running);
 target.innerHTML='<div class="table"><table><thead><tr>'+['Serveur','IP','Ping','Ports TCP','Clé hôte SSH connue','Dernière vérification',''].map(v=>'<th>'+v+'</th>').join('')+'</tr></thead><tbody>'+netState.hosts.map(h=>'<tr><td>'+esc(h.name)+'</td><td>'+esc(h.ip)+'</td><td>'+netBadge(h.ping)+'</td><td>'+((h.ports||[]).map(p=>esc(p.port)+' '+netBadge(p.ok)).join(' · ')||'—')+'</td><td>'+netBadge(h.ssh_key_known)+'</td><td>'+stamp(h.collected_at)+'</td><td><button data-net-host="'+esc(h.key)+'" '+(netState.job.running?'disabled':'')+'>Vérifier</button></td></tr>').join('')+'</tbody></table></div>'+(netState.hosts.length?'':'<div class="empty">Aucun serveur.</div>')
 }catch(e){if(id===renderId)target.textContent=e.message}
}
async function renderExtra(id){
 const target=$('#extra');if(!target)return;
 try{const data=await api(page==='Connexion'?'/api/runtime':'/api/inventory-report');if(id!==renderId)return;
 target.innerHTML=page==='Connexion'?runtimeView(data):'<h2>Rapprochement de l’inventaire</h2><p>'+esc(data.policy)+'</p><p>'+esc(data.hosts)+' serveurs · '+data.conflicts.length+' écarts IP · '+data.excluded.length+' entrées exclues ou à confirmer.</p><details><summary>Écarts entre feuilles</summary><pre>'+esc(data.conflicts.map(c=>c.host+' : '+c.retained_ip+' retenue / '+c.other_ip+' ('+c.source+')').join('\n'))+'</pre></details><details><summary>Entrées non retenues</summary><pre>'+esc(JSON.stringify(data.excluded,null,2))+'</pre></details>'
 }catch(e){if(id===renderId)target.textContent=e.message}
}
$('#content').addEventListener('input',e=>{if(e.target.id==='search'){filters.q=e.target.value;render()}});
$('#content').addEventListener('change',e=>{if(e.target.dataset.filter){filters[e.target.dataset.filter]=e.target.value;render()}});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 try{
 if(b.dataset.go)navigate(b.dataset.go);
 if(b.dataset.host){const key=b.dataset.host;selected=key;detailTab='problems';b.disabled=true;const result=await api('/api/hosts/'+encodeURIComponent(key));if(selected!==key)return;hostDetail=result;lastDetailSnapshot=detailSignature(result);render();window.scrollTo(0,0)}
 if(b.dataset.tab){detailTab=b.dataset.tab;render()}
 if(b.dataset.mode){mode=b.dataset.mode;render()}
 if(b.dataset.auditHost){await post('/api/hosts/'+encodeURIComponent(b.dataset.auditHost)+'/refresh');await load()}
 if(b.hasAttribute('data-net-refresh')){await post('/api/network/refresh');await renderNetwork(renderId)}
 if(b.dataset.netHost){await post('/api/network/hosts/'+encodeURIComponent(b.dataset.netHost)+'/refresh');await renderNetwork(renderId)}
 if(b.hasAttribute('data-copy')){await navigator.clipboard.writeText(b.dataset.copy);toast('Commande copiée · aucune exécution')}
 if(b.hasAttribute('data-export')){const blob=new Blob([JSON.stringify(hostDetail,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='audit-'+hostDetail.key+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 }catch(error){$('#error').textContent=error.message}finally{if(b.isConnected)b.disabled=false}
});
setInterval(()=>{if(Object.values(state?.jobs||{ssh:state?.job}).some(j=>j?.running))load()},5000);setInterval(()=>{if(!Object.values(state?.jobs||{ssh:state?.job}).some(j=>j?.running))load()},30000);
setInterval(()=>{if(!document.hidden&&page==='Réseau'&&netState?.job?.running)renderNetwork(renderId)},2000);


// Interface additions; collection and SSH stay in the existing backend.
const iconPaths={overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',server:'M4 3h16v7H4z M4 14h16v7H4z M7 6h1 M7 17h1',alert:'M12 3 2 21h20z M12 9v5 M12 17v1',service:'M3 12h4l3-8 4 16 3-8h4',audit:'M6 3h12v18H6z M9 8h6 M9 12h6 M9 16h4',network:'M9 3h6v5H9z M3 16h6v5H3z M15 16h6v5h-6z M12 8v4 M6 16v-4h12v4',backup:'M4 6c0-4 16-4 16 0v12c0 4-16 4-16 0z M4 6c0 4 16 4 16 0 M4 12c0 4 16 4 16 0',shield:'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z M8 12l3 3 5-6',inventory:'M4 4h16v16H4z M4 9h16 M9 9v11',key:'M14 4a5 5 0 1 1-3 9l-7 7H2v-3l7-7a5 5 0 0 1 5-6z'};
const icon=k=>'<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="'+iconPaths[k]+'"/></svg>';
const navGroups=[['EXPLOITATION',[['Vue globale','overview'],['Serveurs','server'],['Problèmes','alert'],['Services','service'],['Audit','audit']]],['INFRASTRUCTURE',[['Réseau','network'],['Sauvegardes','backup'],['Proxmox','server'],['WAF / HA','shield'],['Sécurité','shield']]],['CONFIGURATION',[['Inventaire','inventory'],['Connexion','key']]]];
function navigation(){
 const signature=JSON.stringify(navGroups);
 const nav=$('#nav');
 if(nav.dataset.structure!==signature){
  nav.innerHTML=navGroups.map(([title,items])=>'<div class="nav-section">'+title+'</div>'+items.map(([p,i])=>'<button data-page="'+p+'">'+icon(i)+p+'<span class="nav-count"></span></button>').join('')).join('');
  nav.dataset.structure=signature;
 const mobile=$('#mobile-nav');if(mobile)mobile.innerHTML=navGroups.map(([title,items])=>'<optgroup label="'+title+'">'+items.map(([p])=>'<option value="'+p+'">'+p+'</option>').join('')+'</optgroup>').join('');
 }
 if($('#mobile-nav'))$('#mobile-nav').value=page;
 for(const button of nav.querySelectorAll('[data-page]')){
  const target=button.dataset.page;
  button.classList.toggle('active',target===page);
  if(target===page)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
  const count=button.querySelector('.nav-count');
  count.textContent=state&&target==='Serveurs'?onlineHosts().length:state&&target==='Problèmes'?incidents(state.hosts).filter(x=>!x.h.stale).length:'';
 }
}
let sortKey='status',sortDir=1;
const rank={critical:0,unreachable:1,warning:2,unknown:3,ok:4};
const subtitles={'Vue globale':'L’état de votre parc. Les priorités de votre journée.',Serveurs:'Parc enregistré durablement. Disponibilité actualisée ; audit SSH initial conservé.',Problèmes:'Des anomalies documentées, des preuves et des commandes à préparer.',Services:'Les unités observées et les services déclarés critiques.',Audit:'La couverture des contrôles et leurs preuves, serveur par serveur.',Réseau:'Disponibilité, ports et empreintes SSH : comprendre les accès bloqués.',Sauvegardes:'Informations documentaires et couverture des sauvegardes.',Proxmox:'Répartition documentaire des machines par hyperviseur.', 'WAF / HA':'Périmètre WAF et haute disponibilité à partir de l’inventaire.',Sécurité:'Les anomalies de sécurité observées par l’audit SSH.',Inventaire:'Votre parc consolidé et les écarts entre les sources.',Connexion:'Le contexte SSH utilisé par cette instance du cockpit.'};
function relative(v){if(!v)return 'Jamais';const m=Math.max(0,Math.floor((Date.now()-new Date(v).getTime())/60000));return m<1?'À l’instant':m<60?'Il y a '+m+' min':m<1440?'Il y a '+Math.floor(m/60)+' h':'Il y a '+Math.floor(m/1440)+' j'}
const bucket5=n=>Math.max(0,Math.min(100,Math.round(n/5)*5));
function metric(v,stale=false,k='cpu'){if(v==null||!Number.isFinite(Number(v)))return '<span class="mini">Non mesuré</span>';const n=Math.max(0,Math.min(100,Number(v)));const limits=k==='disk_max'?[80,90]:k==='ram'?[90,97]:[90,98];const state=n>=limits[1]?'critical':n>=limits[0]?'warning':'normal';const stateLabel={critical:'Seuil critique dépassé',warning:'Seuil d’alerte dépassé',normal:'Dans les limites normales'}[state];return '<div class="metric '+(stale?'stale':'')+'" title="'+(stale?'Dernière mesure ancienne':'Dernière mesure')+'"><span class="metric-label">'+pct(v)+'</span><div class="meter '+(state==='normal'?'':state)+'" role="img" aria-label="'+stateLabel+'"><i class="w'+bucket5(n)+'"></i></div></div>'}
function onlineHosts(){return (state?.hosts||[]).filter(h=>h.registered===true||h.active_scope===true)}
function list(){return state.hosts.filter(h=>(!['Serveurs','Vue globale'].includes(page)||h.registered===true||h.active_scope===true)&&(!filters.q||(h.name+' '+h.ip).toLowerCase().includes(filters.q.toLowerCase()))&&['status','environment','role'].every(k=>!filters[k]||h[k]===filters[k])).sort((a,b)=>{let av=sortKey==='status'?rank[a.status]:a[sortKey],bv=sortKey==='status'?rank[b.status]:b[sortKey];if(av==null)return bv==null?0:1;if(bv==null)return -1;return (typeof av==='number'?av-bv:String(av).localeCompare(String(bv),'fr'))*sortDir||a.name.localeCompare(b.name)})}
function availabilityMessage(){
 const reasons=state?.availability?.exclusions||{};
 if(onlineHosts().length)return '';
 return '<section class="instruction" role="status"><b>Aucun serveur confirmé en ligne pour le moment</b><p>La liste attend un état Proxmox démarré et un ping récent. Une collecte API seule ne suffisait pas à renouveler le ping.</p>'+Object.entries(reasons).map(([reason,count])=>'<p>'+esc(count)+' · '+esc(reason)+'</p>').join('')+'<button data-refresh-availability>Actualiser Proxmox et ping</button></section>';
}
function toolbar(){return (['Serveurs','Vue globale'].includes(page)?availabilityMessage()+'<p class="note">'+onlineHosts().length+' serveurs enregistrés · Un arrêt ou un ping en échec ne retire pas un serveur du parc. <button class="link" data-go="Inventaire">Tout l’inventaire</button> · <button class="link" data-go="Synchronisation">Voir les exclusions</button></p>':'')+'<div class="filters"><input id="search" aria-label="Rechercher hostname ou IP" placeholder="⌕  Rechercher un hostname ou une adresse IP…" value="'+esc(filters.q)+'">'+['status','environment','role'].map(k=>'<select data-filter="'+k+'" aria-label="'+({status:'État',environment:'Environnement',role:'Rôle'}[k])+'"><option value="">'+({status:'Tous les états',environment:'Environnements',role:'Tous les rôles'}[k])+'</option>'+[...new Set(state.hosts.map(h=>h[k]))].filter(v=>v!=null).sort().map(v=>'<option '+(v===filters[k]?'selected ':'')+'value="'+esc(v)+'">'+esc(labels[v]||v)+'</option>').join('')+'</select>').join('')+(Object.values(filters).some(Boolean)?'<button class="filter-reset" data-reset>Effacer</button>':'')+'</div>'}
function table(hosts){const cols=[['Serveur','name'],['IP','ip'],['Rôle / env.','role'],['État','status'],['CPU','cpu'],['RAM','ram'],['Disque max','disk_max'],['Services',''],['Backup',''],['Audit',''],['Collecte','collected_at']];return '<div class="table"><table><thead><tr>'+cols.map(([title,k])=>'<th '+(k===sortKey?'aria-sort="'+(sortDir===1?'ascending':'descending')+'"':'')+'>'+(k?'<button class="sort-button" data-sort="'+k+'">'+title+(sortKey===k?(sortDir===1?' ↑':' ↓'):' ↕')+'</button>':title)+'</th>').join('')+'</tr></thead><tbody>'+hosts.map(h=>{const sv=h.all_services||h.service_states||[],failed=sv.filter(s=>s.status==='failed').length;return '<tr><td><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+'</button><small>'+esc(h.active_scope?'En ligne confirmé':h.scope_reason||h.node||'Disponibilité non mesurée')+'</small></td><td class="ip">'+esc(h.ip)+'</td><td>'+esc(h.role)+'<small>'+esc(h.environment)+'</small></td><td>'+hostAuditBadge(h)+(h.stale?'<small>État à actualiser</small>':'')+'</td>'+['cpu','ram','disk_max'].map(k=>'<td>'+metric(h[k],h.stale,k)+'</td>').join('')+'<td>'+(h.stale?'<span class="mini">À actualiser</span>':failed?'<span class="badge critical">'+failed+' en échec</span>':(h.services||[]).length?'<span class="mini">Voir les contrôles</span>':'<span class="mini">À configurer</span>')+'</td><td>'+backupBadge(h)+'</td><td class="mini">'+coverage(h)+'</td><td title="'+esc(stamp(h.collected_at))+'">'+freshnessMarkup(h.collected_at,'Mesures SSH',30)+'</td></tr>'}).join('')+'</tbody></table></div>'+(hosts.length?'<div class="table-foot"><span>'+hosts.length+' serveur'+(hosts.length>1?'s':'')+' affiché'+(hosts.length>1?'s':'')+'</span><span>Cliquer sur un hostname pour ouvrir son audit</span></div>':'<div class="empty">Aucun serveur pour ces critères.</div>')}
function brief(hosts){const all=incidents(hosts).filter(x=>!x.h.stale).sort((a,b)=>((a.f.id==='ssh')-(b.f.id==='ssh'))),old=all.length===0,visible=old?incidents(hosts).filter(x=>x.h.stale):all;return '<section class="panel priority-list"><div class="panel-head"><h2>À traiter maintenant <span class="state-count">'+all.length+'</span></h2><button data-go="Problèmes">Tous les problèmes →</button></div>'+(old&&visible.length?'<p class="note">Derniers problèmes connus · preuves anciennes à actualiser</p>':'')+visible.slice(0,4).map(({h,f})=>'<div class="row">'+(old?'<span class="badge unknown">Ancien</span>':badge(f.severity))+'<div><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+'</button><p>'+esc(f.title)+'</p></div><button data-host="'+esc(h.key)+'">Diagnostic ↗</button></div>').join('')+(visible.length?'':'<div class="empty"><span class="empty-symbol">◎</span>Aucune anomalie récente disponible.<br>Actualisez les audits pour connaître l’état du parc.</div>')+'</section>'}
function health(hosts=state.hosts){const total=hosts.length,recent=hosts.filter(h=>h.collected_at&&!h.stale),observed=recent.filter(h=>h.cpu!=null),ok=recent.filter(h=>h.status==='ok').length,score=recent.length&&total?Math.round(ok/total*100):null,blocked=recent.filter(h=>h.cpu==null).length;return '<section class="panel health-panel"><div class="panel-head"><h2>Santé & couverture</h2></div><div class="health-body"><div class="health-ring hv'+bucket5(score||0)+'"><strong>'+(score==null?'—':score+'%')+'</strong></div><div><b>Parc confirmé OK</b><p>'+ok+' / '+total+' serveurs</p><p>Sur les contrôles disponibles</p></div></div><div><div class="health-line"><span>Mesures récentes</span><b>'+observed.length+' / '+total+'</b></div><div class="health-line"><span>Accès sans mesures</span><b>'+blocked+'</b></div><div class="health-line"><span>Anciens ou jamais collectés</span><b>'+(total-recent.length)+'</b></div></div><div class="health-note">Les états inconnus ne sont pas considérés comme OK.<br><button data-go="Audit">Consulter la couverture →</button></div></section>'}
function overview(){const hosts=onlineHosts(),counts={};for(const h of hosts)counts[h.status]=(counts[h.status]||0)+1;return '<div class="stats">'+[['Serveurs',hosts.length,'','VM démarrées · ping réussi'],['OK',counts.ok||0,'ok','Contrôles concluants'],['Critiques',counts.critical||0,'critical','Incidents ou accès refusés'],['À surveiller',counts.warning||0,'warning','Seuils et anomalies'],['Injoignables',counts.unreachable||0,'unreachable','Collecte impossible'],['Incomplets',counts.unknown||0,'unknown','À vérifier ou actualiser']].map(([n,v,c,s])=>'<button class="card stat-card '+c+'" data-status="'+c+'"><span class="stat-dot"></span>'+n+'<strong>'+v+'</strong><small>'+s+'</small></button>').join('')+'</div><div class="overview-grid">'+brief(hosts)+health(hosts)+'</div>'}
function serviceView(){const hs=list(),units=hs.flatMap(h=>(h.all_services||[]).map(s=>({h,s}))).sort((a,b)=>(a.s.status==='failed'?-1:1)-(b.s.status==='failed'?-1:1));return '<div class="panel"><div class="panel-head"><h2>Services observés</h2><span class="mini">'+units.length+' unités</span></div>'+toolbar()+'<div class="service-summary"><span>'+units.filter(x=>x.s.status==='failed'&&!x.h.stale).length+' échecs récents</span><span>'+hs.filter(h=>!(h.services||[]).length).length+' listes critiques à configurer</span></div><div class="table"><table><thead><tr><th>Serveur</th><th>Unité</th><th>État observé</th><th>Déclarée critique</th><th>Collecte</th></tr></thead><tbody>'+units.map(({h,s})=>'<tr><td><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+'</button></td><td>'+esc(s.name)+'</td><td>'+badge(h.stale?'unknown':s.status)+(h.stale?'<small>Ancien état : '+esc(s.status)+'</small>':'')+'</td><td>'+(s.configured?'Oui':'Non')+'</td><td>'+freshnessMarkup(h.collected_at,'Mesures SSH',30)+'</td></tr>').join('')+'</tbody></table></div>'+(units.length?'':'<div class="empty">Aucune unité disponible. Actualisez l’infrastructure.</div>')+'</div>'}
function backups(){return '<div class="panel"><div class="panel-head"><h2>Sauvegardes</h2><span class="badge unknown">Proxmox Backup Server non raccordé</span></div><p class="note">Les chemins ci-dessous proviennent de l’inventaire. Ils ne prouvent ni l’exécution ni la réussite d’une sauvegarde.</p>'+toolbar()+'<div class="table"><table><thead><tr><th>Serveur</th><th>État réel</th><th>Chemins documentés</th><th>Rétention documentée</th></tr></thead><tbody>'+list().map(h=>'<tr><td><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+'</button></td><td>'+badge('unknown')+'</td><td>'+esc(h.documented?.backup?.paths||'Non renseignés')+'</td><td>'+esc(h.documented?.backup?.retention||'Non renseignée')+'</td></tr>').join('')+'</tbody></table></div></div>'}
function security(){const findings=incidents(list()).filter(({f})=>/sécurité|security|permissions|ssh_policy/i.test(f.domain+' '+f.id));return '<div class="panel"><div class="panel-head"><h2>Contrôles de sécurité SSH</h2><span class="badge unknown">Wazuh non raccordé</span></div><p>Cette vue présente les anomalies accessibles au compte SSH. Les contrôles non accessibles sont détaillés dans chaque audit.</p>'+toolbar()+'</div>'+findings.map(({h,f})=>issue(h,f)).join('')+(findings.length?'':'<div class="panel empty">Aucune anomalie de sécurité disponible sur ce périmètre. Cela ne vaut pas validation de conformité.</div>')}
function runtimeView(data){return '<h2>Contexte de connexion</h2><p class="note">'+esc(data.hint)+'</p><div class="runtime-grid">'+[['Transport',data.transport],['Compte local',data.local_user],['Clé privée configurée',data.key_path],['Configuration SSH',data.config_path],['Collectes simultanées',data.workers],['Journal d’audit',data.audit_path]].map(([k,v])=>'<div class="runtime-item"><small>'+k+'</small><b>'+esc(v)+'</b></div>').join('')+'</div><p class="instruction">Les empreintes SSH sont vérifiées manuellement. Les comptes et ports utilisés sont visibles dans les tentatives de chaque serveur.</p><details><summary>Informations techniques</summary><pre>'+esc(JSON.stringify(data,null,2))+'</pre></details>'}
// Sans état, on affiche explicitement l'attente plutôt que de sortir en laissant
// le DOM de la page précédente : sinon « Sécurité » affichait le contenu de
// « Proxmox », dernier module à avoir peint. Mesuré : 4 pages sur 17 concernées.
function render(){if(!state){$('#title').textContent=page;$('#breadcrumb').textContent=page;$('#subtitle').textContent=subtitles[page]||'';navigation();$('#content').innerHTML='<div class="panel empty">Chargement de l’état du parc…</div>';return}const id=++renderId,focus=document.activeElement?.id,position=document.activeElement?.selectionStart,selectionEnd=document.activeElement?.selectionEnd;const expanded=[...document.querySelectorAll('#content details')].map((d,i)=>d.open?i:-1).filter(i=>i>=0);$('#title').textContent=selected?hostDetail?.name||'Serveur':page;$('#breadcrumb').textContent=selected?'Serveurs / '+(hostDetail?.name||'Chargement'):page;$('#subtitle').textContent=selected?'Mesures, services et preuves : comprendre avant d’intervenir.':subtitles[page]||'';navigation();let html='';
 if(selected&&hostDetail){$('#content').innerHTML=detailView(hostDetail);expanded.forEach(i=>{const d=document.querySelectorAll('#content details')[i];if(d)d.open=true});restoreDetailFocus(focus,position,selectionEnd);return}
 if(page==='Vue globale')html=overview();
 if(['Serveurs','Audit','Inventaire'].includes(page))html+='<div class="panel"><div class="panel-head"><h2>'+(page==='Audit'?'Couverture par serveur':'Parc serveurs')+' <span class="state-count">'+(['Serveurs','Vue globale'].includes(page)?onlineHosts().length:state.hosts.length)+'</span></h2><span class="mini">'+list().length+' résultat'+(list().length>1?'s':'')+'</span></div>'+toolbar()+table(list())+'</div>';
 if(page==='Problèmes'){const data=incidents(list(),mode==='coverage');html='<div class="panel">'+toolbar()+'<div class="tabs"><button data-mode="incidents" class="'+(mode==='incidents'?'active':'')+'">Anomalies observées</button><button data-mode="coverage" class="'+(mode==='coverage'?'active':'')+'">Contrôles incomplets</button></div><p class="note">Commandes à copier. Les corrections sont à examiner et à exécuter manuellement après diagnostic.</p></div>'+data.map(({h,f})=>issue(h,f)).join('')+(data.length?'':'<div class="panel empty">Aucun résultat. Consultez Audit pour les contrôles absents.</div>')}
 if(page==='Réseau')html='<div class="panel"><div class="panel-head"><h2>Disponibilité réseau et SSH</h2><button data-net-refresh>↻ Vérifier le réseau</button></div><p class="note">Ping, ports TCP et présence des empreintes connues. Aucun ajout automatique de clé.</p><span id="netprogress" class="mini"></span><div id="net">Chargement…</div></div>';
 if(page==='Services')html=serviceView();if(page==='Sauvegardes')html=backups();if(page==='Sécurité')html=security();
 if(page==='Connexion'||page==='Inventaire')html+='<section class="panel" id="extra">Chargement…</section>';
 $('#content').innerHTML=html;renderExtra(id);renderNetwork(id);if(focus==='search'){$('#search')?.focus();$('#search')?.setSelectionRange(position,position)}
}
$('#content').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.hasAttribute('data-status')){navigate('Serveurs');filters={q:'',status:b.dataset.status,environment:'',role:''};render()}if(b.hasAttribute('data-reset')){filters={q:'',status:'',environment:'',role:''};render()}if(b.dataset.sort){sortDir=sortKey===b.dataset.sort?-sortDir:1;sortKey=b.dataset.sort;render()}});
function applyTheme(theme){document.documentElement.dataset.theme=theme;$('#theme').setAttribute('aria-label','Activer le thème '+(theme==='dark'?'clair':'sombre'))}
try{applyTheme(localStorage.getItem('opscontrol-theme')||'dark')}catch{applyTheme('dark')}
$('#theme').onclick=()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';applyTheme(theme);try{localStorage.setItem('opscontrol-theme',theme)}catch{}};
navigation();

// Rattrapage immediat quand l'onglet redevient visible : la garde document.hidden
// de load() protege le serveur, cet ecouteur evite qu'elle laisse l'interface vide.
document.addEventListener('visibilitychange',()=>{if(!document.hidden)load()});
load();



$('#mobile-nav').addEventListener('change',e=>navigate(e.target.value));

$('#content').addEventListener('click',async e=>{const b=e.target.closest('[data-refresh-availability]');if(!b)return;b.disabled=true;try{await post('/api/availability/refresh');await load();}catch(error){$('#error').textContent=error.message;}finally{if(b.isConnected)b.disabled=false;}});
