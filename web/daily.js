// Daily entry point: explicit freshness, bounded lists, links to supporting evidence.
let dailyData=null, batchData=null, batchSearch='', batchKind='', batchState='', batchOffset=0;
const batchLabels={running:'En cours',failed:'Échec observé',success:'Dernière exécution réussie',scheduled:'Planifié · résultat inconnu',warning:'Avertissement',unknown:'Non mesuré'};
const batchColors={running:'active',failed:'critical',success:'ok',scheduled:'observed',warning:'warning',unknown:'unknown'};
const sourcePages={Proxmox:'Proxmox',Zabbix:'Zabbix',Wazuh:'Wazuh',Elasticsearch:'Elasticsearch',Bacula:'Sauvegardes'};
navGroups[0][1].push(['Batch / Planification','service']);
subtitles['Vue globale']='Votre point quotidien : priorités, disponibilité, audits, sources et traitements.';
subtitles['Batch / Planification']='Cron, timers systemd et jobs Bacula : où, quand, et quel résultat a été observé.';
navigation();

function dailyCard(label,value,note,target){return '<button class="card stat-card" data-go="'+esc(target)+'"><span>'+esc(label)+'</span><strong>'+esc(value)+'</strong><small>'+esc(note)+'</small></button>';}
function dailySourceSummary(s){
 const c=s.counts||{};
 if(s.provider==='Proxmox')return 'VM : '+(c.running??'—')+' démarrées · '+(c.stopped??'—')+' arrêtées';
 if(s.provider==='Zabbix')return (c.monitored??'—')+' hôtes surveillés · '+(s.problems_count??'—')+' problèmes visibles';
 if(s.provider==='Wazuh')return 'Démons manager : '+(c.running??'—')+' actifs · '+(c.failed??'—')+' en échec · '+(c.stopped??'—')+' arrêtés (parfois optionnels)';
 if(s.provider==='Bacula')return 'Dernier résultat par job et client dans Batch ; historique détaillé dans Sauvegardes.';
 return '';
}
// Regroupe les priorites par cause plutot que par hote.
// Mesure avant : 30 lignes, toutes « Connexion SSH indisponible », occupant 944 px
// et masquant les 6 anomalies reellement mesurees. Une panne qui touche 26 serveurs
// est UN evenement, pas 26 : l'afficher 26 fois n'ajoute aucune information et
// repousse hors de l'ecran ce sur quoi on peut agir.
const dailyRang={critical:0,unreachable:1,warning:2,unknown:3};
function dailyGroupes(priorites){
 const groupes=new Map();
 for(const p of priorites||[]){
  const cle=(p.source||'SSH')+'|'+p.severity+'|'+p.title;
  if(!groupes.has(cle))groupes.set(cle,{severity:p.severity,title:p.title,domain:p.domain,source:p.source||'SSH',hotes:[],anciens:0,recent:null});
  const g=groupes.get(cle);
  g.hotes.push(p);
  if(p.stale)g.anciens++;
  if(p.collected_at&&(!g.recent||p.collected_at>g.recent))g.recent=p.collected_at;
 }
 return [...groupes.values()].sort((a,b)=>(dailyRang[a.severity]??9)-(dailyRang[b.severity]??9)||b.hotes.length-a.hotes.length);
}
function dailyGroupeMarkup(g){
 // Deux origines possibles : le serveur (total exact + echantillon borne) ou le
 // regroupement client de secours. On affiche TOUJOURS le total reel, jamais le
 // nombre d'echantillons recus — annoncer « 12 serveurs » quand il y en a 26
 // serait exactement le genre de chiffre tronque que cette plateforme refuse.
 const hotes=g.hosts||g.hotes||[];
 const n=g.total??hotes.length;
 const anciens=g.stale_total??g.anciens??0;
 // Un seul hote : pas de depliant, la ligne se suffit.
 const entete='<small>'+esc(g.source||'SSH')+'</small><span class="daily-groupe-titre">'+esc(g.title)+'</span>'+
   (n>1?'<span class="state-count">'+n+' observations</span>':'')+
   (anciens?'<small>'+anciens+' preuve(s) ancienne(s)</small>':'');
 const lignes=hotes.map(p=>'<div class="row"><button class="link" data-host="'+esc(p.host_key)+'">'+esc(p.host_name)+'</button>'+
   '<small>'+stamp(p.collected_at)+'</small>'+
   '<span class="daily-actions">'+((g.source||'SSH')==='SSH'?'<button data-daily-audit="'+esc(p.host_key)+'">Réauditer</button><button data-daily-net="'+esc(p.host_key)+'">Tester le réseau</button>':'<button data-go="'+esc(sourcePages[g.source]||'Connexions API')+'">Ouvrir '+esc(g.source)+'</button>')+'</span></div>').join('');
 const reste=n-hotes.length;
 return '<details class="daily-groupe"'+(n>1?'':' open')+'><summary>'+badge(g.severity)+entete+'</summary>'+
   (n>1?'<p class="note">Même libellé dans '+n+' observations ; vérifier les preuves avant de conclure à une cause commune.</p>':'')+
   lignes+
   (reste>0?'<p class="note">'+reste+' autre(s) serveur(s) concerné(s), non listés ici. <button class="link" data-go="Problèmes">Voir tous les problèmes</button></p>':'')+
   '</details>';
}
// Nombre de causes affichees d'emblee. Corriger la troncature cote serveur a
// fait passer les priorites de 1 cause visible a 34 : sans cette borne, la page
// repassait a 4,7 ecrans. On montre les plus graves, le reste reste accessible
// en un clic — jamais masque, jamais compte a part.
const DAILY_GROUPES_VISIBLES=8;
let dailyToutVoir=false;
function dailyGroupesVisibles(groupes){
 const liste=groupes||[];
 const montres=dailyToutVoir?liste:liste.slice(0,DAILY_GROUPES_VISIBLES);
 const reste=liste.length-montres.length;
 const serveursRestants=liste.slice(montres.length).reduce((n,g)=>n+(g.total??(g.hotes||[]).length),0);
 return montres.map(dailyGroupeMarkup).join('')+
  (reste>0?'<button class="daily-plus" data-daily-plus>Voir les '+reste+' autre(s) cause(s) · '+serveursRestants+' serveur(s)</button>':'')+
  (dailyToutVoir&&liste.length>DAILY_GROUPES_VISIBLES?'<button class="daily-plus" data-daily-moins>Réduire</button>':'');
}
// Serveurs sans audit, regroupes par cause. L'ancienne liste affichait 35 lignes
// portant chacune 200 caracteres de sortie OpenSSH identique : le detail complet
// reste dans la fiche de chaque serveur, ou il a un sens.
function dailyAttention(d){
 const groupes=d.attention_groups;
 if(!groupes) return (d.attention||[]).slice(0,12).map(h=>'<div class="row"><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+' · '+esc(h.ip)+'</button><span>'+esc((h.issues||[])[0]||'Audit initial requis')+'</span></div>').join('');
 return groupes.map(g=>{
  const reste=g.total-g.hosts.length;
  return '<details class="daily-groupe"><summary><span class="daily-groupe-titre">'+esc(g.cause)+'</span>'+
   '<span class="state-count">'+g.total+' serveurs</span></summary>'+
   g.hosts.map(h=>'<div class="row"><button class="link" data-host="'+esc(h.key)+'">'+esc(h.name)+' · '+esc(h.ip)+'</button>'+
     '<span class="daily-actions"><button data-daily-audit="'+esc(h.key)+'">Réauditer</button>'+
     '<button data-daily-net="'+esc(h.key)+'">Tester le réseau</button></span></div>').join('')+
   (reste>0?'<p class="note">'+reste+' autre(s) serveur(s) avec la même cause.</p>':'')+
   '</details>';
 }).join('');
}
function dailyMarkup(d){
 const c=d.counts||{},b=d.batches||{},bc=b.counts||{};
 return '<div class="stats">'+dailyCard('Parc enregistré',c.registered,'Sur '+c.inventory+' hôtes inventoriés','Serveurs')+
 dailyCard('En ligne confirmé',c.online,'Proxmox démarré et ping récent','Réseau')+
 dailyCard('Audits à compléter',c.audit_missing,'SSH absent ou sans mesures','Audit')+
 dailyCard('Critiques associées',c.critical_total??c.critical_recent,
   (c.critical_stale?(c.critical_recent??0)+' récente(s) · '+c.critical_stale+' à réactualiser':'Observations SSH et API récentes'),'Problèmes')+
 dailyCard('API récentes',c.api_fresh+' / '+c.api_total,'Collectes réussies et récentes','Connexions API')+
 dailyCard('Batch en échec',b.fresh_failures||0,'Dernier état observé · inventaire récent','Batch / Planification')+'</div>'+
 '<p class="note">'+esc(d.policy)+' Synthèse : '+stamp(d.generated_at)+'.</p>'+
 '<div class="daily-columns"><section class="panel"><div class="panel-head"><h2>Priorités du jour</h2><button data-go="Alertes">Alertes globales</button></div><p class="note">Observations associées aux serveurs, gravité de chaque source. Le centre Alertes regroupe aussi les cibles hors inventaire et applique sa politique affichée.</p>'+
 dailyGroupesVisibles(d.priority_groups||dailyGroupes(d.priorities))+
 (!(d.priorities||[]).length?'<p>Aucun problème associé à un serveur dans les observations disponibles. Vérifiez la couverture avant de conclure.</p>':'')+
 '</section><section class="panel"><h2>Traitements et sauvegardes</h2><p><b>'+esc(bc.running||0)+'</b> en cours · <b>'+esc(bc.scheduled||0)+'</b> planifications cron</p><p>'+esc(b.fresh_hosts||0)+' / '+esc(b.hosts_total||0)+' serveurs avec un inventaire Batch récent.</p><p>Les échecs Bacula portent sur le dernier job connu par nom et client ; ils peuvent être historiques.</p><div class="filters"><button data-go="Batch / Planification">Voir les horaires et états</button><button data-go="Sauvegardes">Voir les sauvegardes</button></div></section></div>'+
 '<section class="panel"><div class="panel-head"><h2>Sources de supervision</h2><button data-go="Synchronisation">Synchronisation</button></div><div class="daily-sources">'+(d.sources||[]).map(s=>'<article class="card"><h3>'+esc(s.name)+'</h3><span class="badge '+(s.fresh?'observed':'unknown')+'">'+(s.fresh?'Collecte récente':'Ancienne ou indisponible')+'</span><p>'+freshnessMarkup(s.collected_at,'Lecture API',s.provider==='Zabbix'?30:120)+'</p>'+(s.error?'<p class="form-error">'+esc(s.error)+'</p>':'')+(s.provider==='Elasticsearch'?'<p>Cluster : '+esc(s.indicators?.cluster_status||'Non mesuré')+' · '+esc(s.indicators?.unassigned_shards??'—')+' shards non affectés</p>':'')+'<p>'+esc(dailySourceSummary(s))+'</p><p>'+esc(Object.values(s.secondary_errors||{}).join(' · '))+'</p><button data-go="'+esc(sourcePages[s.provider]||'Connexions API')+'">Ouvrir '+esc(s.provider)+'</button></article>').join('')+'</div></section>'+
 '<details class="panel"><summary><b>Couverture à compléter</b> — '+esc((d.attention||[]).length)+' serveurs sans audit mesuré</summary><div class="panel-head"><button data-go="Audit">Détail des contrôles</button></div><p>'+esc(c.audit_recorded)+' audits enregistrés. Les mesures anciennes restent consultables et datées.</p>'+dailyAttention(d)+'<p class="note">'+esc((d.attention||[]).length)+' serveurs sans audit mesuré. Les clés SSH inconnues doivent être vérifiées manuellement.</p></details>';
}

overview=function(){return '<div id="home-critical"></div><div id="daily-data">'+(dailyData?dailyMarkup(dailyData):'<div class="panel">Chargement de la synthèse quotidienne…</div>')+'</div>';};
async function loadDaily(){
 const target=$('#daily-data');if(!target)return;
 try{const d=await api('/api/daily');if(!target.isConnected)return;dailyData=d;target.innerHTML=dailyMarkup(d);}
 catch(e){if(target.isConnected)target.innerHTML='<p role="alert">'+esc(e.message)+'</p>';}
}
sourceLoaders['Vue globale']=loadDaily;

// The daily refresh preserves existing SSH audits, per the operator's policy.
$('#refresh').textContent='↻ Actualiser les données';
$('#refresh').onclick=async()=>{try{await post('/api/daily/refresh');await load();}catch(e){$('#error').textContent=e.message;}};

function batchTable(jobs){
 return '<div class="table"><table><caption class="note">Horaires dans le fuseau indiqué par chaque source. Aucun traitement ne peut être exécuté depuis cette page.</caption><thead><tr>'+['Traitement / source','Serveur','Planification / fuseau','État observé','Dernier passage / fin','Prochain passage','Collecte'].map(x=>'<th scope="col">'+x+'</th>').join('')+'</tr></thead><tbody>'+jobs.map(j=>'<tr><td><b>'+esc(j.name)+'</b><small>'+esc(j.kind)+' · '+esc(j.source)+(j.line?' : ligne '+esc(j.line):'')+'</small><small>Compte : '+esc(j.owner)+'</small></td><td>'+(j.host_key?'<button class="link" data-host="'+esc(j.host_key)+'">'+esc(j.host_name)+'</button>':esc(j.host_name))+'</td><td class="batch-wrap">'+esc(j.schedule)+'<small>'+esc(j.timezone)+'</small></td><td><span class="badge '+(j.fresh?batchColors[j.state]||'unknown':'unknown')+'">'+esc(batchLabels[j.state]||'Non mesuré')+'</span>'+(!j.fresh?'<small>Observation ancienne</small>':'')+'<small>'+esc(j.evidence)+'</small></td><td>'+esc(j.last_run||'Non mesuré')+'</td><td>'+esc(j.next_run||'Non mesuré')+'</td><td>'+stamp(j.collected_at)+'</td></tr>').join('')+'</tbody></table></div>';
}
function batchShell(){return '<section class="panel"><div class="panel-head"><h2>Batch / Planification</h2><button id="batch-refresh" class="primary">Actualiser les tâches par SSH</button></div><p>Lecture seule : crontab du compte, /etc/crontab, fichiers accessibles de /etc/cron.d, timers systemd chargés et derniers jobs Bacula.</p><p>Les autres comptes, les ordonnanceurs applicatifs et les logs cron ne sont pas intégralement couverts. Un horaire configuré ne prouve pas une exécution.</p><div class="filters"><label>Rechercher<input id="batch-search" value="'+esc(batchSearch)+'" placeholder="Serveur, tâche ou horaire"></label><label>Source<select id="batch-kind"><option value="">Toutes</option><option value="cron">Cron</option><option value="systemd">Systemd</option><option value="bacula">Bacula</option></select></label><label>État<select id="batch-state"><option value="">Tous</option>'+Object.entries(batchLabels).map(([k,v])=>'<option value="'+k+'">'+v+'</option>').join('')+'</select></label></div><p id="batch-progress" role="status"></p></section><div id="batch-results"></div>';}
function renderBatchRows(){
 const target=$('#batch-results');if(!target||!batchData)return;
 const filtered=(batchData.jobs||[]).filter(j=>(!batchKind||j.kind===batchKind)&&(!batchState||j.state===batchState)&&(!batchSearch||[j.name,j.host_name,j.schedule,j.source].join(' ').toLowerCase().includes(batchSearch.toLowerCase())));
 const rank={failed:0,warning:1,running:2,unknown:3,scheduled:4,success:5};
 filtered.sort((a,b)=>Number(b.fresh)-Number(a.fresh)||(rank[a.state]??6)-(rank[b.state]??6)||String(a.host_name).localeCompare(String(b.host_name)));
 if(batchOffset>=filtered.length)batchOffset=0;
 target.innerHTML='<section class="panel"><p>'+filtered.length+' traitements · lignes '+(filtered.length?batchOffset+1:0)+' à '+Math.min(batchOffset+50,filtered.length)+'</p>'+batchTable(filtered.slice(batchOffset,batchOffset+50))+'<div class="filters"><button data-batch-page="-1" '+(!batchOffset?'disabled':'')+'>Précédent</button><button data-batch-page="1" '+(batchOffset+50>=filtered.length?'disabled':'')+'>Suivant</button></div></section><details class="panel"><summary>Couverture et limites par serveur</summary>'+(batchData.coverage||[]).map(c=>'<p><button class="link" data-host="'+esc(c.host_key)+'">'+esc(c.name)+'</button> · '+(c.fresh?'Récent':'Ancien ou non mesuré')+' · '+stamp(c.collected_at)+'<br>'+esc((c.limitations||[]).join(' · '))+'</p>').join('')+'</details>';
 const job=batchData.job||{};$('#batch-progress').textContent=job.running?'Collecte SSH : '+job.completed+' / '+job.total:job.error||'Dernier inventaire enregistré affiché';
 $('#batch-refresh').disabled=!!job.running;
}
async function loadBatches(){
 const target=$('#batch-results');if(!target)return;
 try{const data=await api('/api/batches');if(!target.isConnected)return;batchData=data;renderBatchRows();}
 catch(e){if(target.isConnected)target.textContent=e.message;}
}
sourceLoaders['Batch / Planification']=loadBatches;

// Explain what each existing page establishes and what an operator should check.
const pageGuides={
 'Serveurs':['Ouvrir une fiche pour voir les preuves SSH, les données API associées et les tâches planifiées.','Un serveur arrêté reste enregistré ; son audit conservé n’est pas un état temps réel.'],
 'Audit':['Examiner les contrôles non mesurés, les accès refusés et les preuves de chaque anomalie.','Un audit partiel n’est pas un audit complet. Utiliser Auditer ce serveur pour actualiser volontairement ses preuves.'],
 'Problèmes':['Trier les anomalies par gravité et confirmer leur date avant une intervention.','Les commandes proposées sont à vérifier manuellement ; OpsControl ne les exécute pas.'],
 'Services':['Vérifier les unités failed et documenter les services critiques par serveur.','Un outil ponctuel peut être inactif normalement ; son résultat se vérifie dans Batch.'],
 'Réseau':['Comparer ping, port SSH et confiance dans la clé hôte.','Un ping sans réponse peut venir du filtrage ICMP ; ce n’est pas à lui seul une preuve de panne.'],
 'Proxmox':['Contrôler nœuds, quorum, VM démarrées et rapprochements avec les serveurs SSH.','VM démarrée ne signifie pas application disponible.'],
 'Wazuh':['Vérifier le manager, les agents associés aux fiches et les collectes secondaires.','Manager disponible ne signifie pas que chaque serveur est protégé.'],
 'Zabbix':['Lire les problèmes actifs, leur gravité et les serveurs associés.','Un hôte déclaré surveillé n’est pas nécessairement joignable.'],
 'Elasticsearch':['Vérifier l’état du cluster, les nœuds et les shards non affectés.','La collecte actuelle ne prouve pas la réception des logs de chaque serveur.'],
 'Sauvegardes':['Comparer les derniers jobs par client dans Batch, puis les détails des sauvegardes.','Un job terminé ne prouve pas qu’une restauration est possible. Les compteurs historiques ne décrivent pas seulement la nuit dernière.'],
 'Sécurité':['Examiner la politique SSH, les permissions et les contrôles accessibles.','Les droits insuffisants restent signalés ; aucune élévation automatique.'],
 'WAF / HA':['Contrôler les alertes WAF, les certificats et les preuves de disponibilité.','Aucun blocage ni changement de règle n’est exécuté par OpsControl.'],
 'Inventaire':['Compléter rôle, environnement, services critiques et identités ambiguës.','Les ajouts automatiques exigent des sources concordantes ; aucune IP n’est inventée.'],
 'Synchronisation':['Vérifier la fraîcheur des sources et les VM non rapprochées.','L’automatisation conserve les audits existants ; le bouton de réaudit complet est une action explicite.'],
 'Connexions API':['Vérifier les collectes et les permissions de lecture des comptes.','Les secrets restent dans le coffre Windows du compte utilisé pour lancer OpsControl.'],
 'Connexion':['Vérifier le compte, le client SSH, les clés et le bastion utilisés.','Une clé inconnue doit être comparée à une source de confiance avant enregistrement.']
};
const beforeDailyRender=render;
render=function(){
 beforeDailyRender();if(!state)return;
 if(selected)return;
 if(page==='Vue globale'){loadDaily();return;}
 if(page==='Batch / Planification'){
   $('#content').innerHTML=batchShell();$('#batch-kind').value=batchKind;$('#batch-state').value=batchState;renderBatchRows();loadBatches();return;
 }
 if(pageGuides[page])$('#content').insertAdjacentHTML('beforeend','<details class="panel page-guide"><summary>Repères pour exploiter cette page</summary><p>'+esc(pageGuides[page][0])+'</p><p>'+esc(pageGuides[page][1])+'</p></details>');
};
const detailBeforeBatch=detailView;
detailView=function(host){return detailBeforeBatch(host)+'<section class="panel"><div class="panel-head"><h2>Tâches de ce serveur</h2><button data-go="Batch / Planification">Vue de toute l’infrastructure</button></div><p>'+esc((host.batch_coverage?.limitations||['Inventaire Batch non collecté']).join(' · '))+'</p>'+batchTable((host.batches||[]).slice(0,50))+'</section>';};
$('#content').addEventListener('input',e=>{if(e.target.id==='batch-search'){batchSearch=e.target.value;batchOffset=0;renderBatchRows();}});
$('#content').addEventListener('change',e=>{if(e.target.id==='batch-kind')batchKind=e.target.value;else if(e.target.id==='batch-state')batchState=e.target.value;else return;batchOffset=0;renderBatchRows();});
// Actions rapides depuis la Vue globale : les deux endpoints existent deja, il
// n'y avait simplement aucun moyen de les declencher sans changer de page.
// Le bouton porte son propre etat : on ne bloque pas toute l'interface pour
// l'audit d'un seul serveur.
async function dailyAction(bouton, url, libelle){
 const initial=bouton.textContent;
 bouton.disabled=true;bouton.textContent='En cours…';
 try{
  await post(url);
  bouton.textContent=libelle;
  await loadDaily();
 }catch(error){
  $('#error').textContent=error.message;
  if(bouton.isConnected){bouton.disabled=false;bouton.textContent=initial;}
 }
}
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-daily-plus')||b.hasAttribute('data-daily-moins')){dailyToutVoir=b.hasAttribute('data-daily-plus');$('#daily-data').innerHTML=dailyMarkup(dailyData);return;}
 if(b.dataset.dailyAudit){e.preventDefault();await dailyAction(b,'/api/hosts/'+encodeURIComponent(b.dataset.dailyAudit)+'/refresh','Audit lancé');return;}
 if(b.dataset.dailyNet){e.preventDefault();await dailyAction(b,'/api/network/hosts/'+encodeURIComponent(b.dataset.dailyNet)+'/refresh','Test lancé');return;}
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.dataset.batchPage){batchOffset=Math.max(0,batchOffset+Number(b.dataset.batchPage)*50);renderBatchRows();}
 if(b.id==='batch-refresh'){b.disabled=true;try{await post('/api/batches/refresh');await loadBatches();}catch(error){$('#error').textContent=error.message;}finally{if(b.isConnected)b.disabled=!!batchData?.job?.running;}}
});
setInterval(()=>{if(!document.hidden&&!selected&&page==='Batch / Planification'&&batchData?.job?.running)loadBatches();},5000);
