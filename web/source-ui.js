// Shared source status: collection success and freshness are separate facts.
function sourceResult(connection){
  const last=connection.last_result||{};
  if(last.status==='observed'||!connection.last_success_result)return last;
  // Preserve the observation date; failure never turns old data green.
  return {...connection.last_success_result,status:'unknown',error:last.error,
    last_attempt_at:last.collected_at,retained:true};
}
function sourceFresh(result){
  const age=Date.now()-Date.parse(result.collected_at);
  return result.status==='observed' && Number.isFinite(age) && age>=0 && age<=900000;
}
function sourceStatus(connection){
  const r=sourceResult(connection);
  const auth=connection.auth_configured===false?'Identifiants absents : rechargez cette source dans le lanceur.':'';
  const freshness=sourceFresh(r)?'Données récentes':'Données anciennes, absentes ou collecte en échec';
  return '<div class="source-state" role="status"><span class="badge '+(sourceFresh(r)?'observed':'unknown')+'">'+freshness+'</span><span>'+freshnessMarkup(r.collected_at,'Lecture API',connection.provider==='Zabbix'?30:120)+'</span>'+(r.retained?'<p class="instruction">Dernières données conservées. Tentative en échec : '+esc(stamp(r.last_attempt_at))+'.</p>':'')+(auth?'<p class="instruction">'+esc(auth)+'</p>':'')+'</div>';
}
function linkedServer(names){
  const values=new Set(names.filter(Boolean).map(x=>String(x).toLowerCase().replace(/\.$/,'')));
  const matches=(state?.hosts||[]).filter(h=>[h.key,h.name,h.fqdn,h.ip].some(v=>v&&values.has(String(v).toLowerCase().replace(/\.$/,''))));
  return matches.length===1?'<button class="link" data-host="'+esc(matches[0].key)+'">'+esc(matches[0].name)+' · détail serveur</button>':(matches.length?'Association ambiguë':'Non rapproché');
}

// Host details retain source identities instead of mixing API and SSH health.
const detailBeforeSources=detailView;
detailView=function(host){
 const linked=state?.hosts.find(h=>h.key===host.key);
 let html=detailBeforeSources(host);
 const attempt=host.last_attempt;
 if(attempt)html+='<section class="panel" role="status"><h2>Dernière tentative SSH en échec</h2><p>'+stamp(attempt.collected_at)+' · Les mesures affichées restent celles du '+stamp(host.collected_at)+'.</p>'+(attempt.issues||[]).map(issue=>'<p>'+esc(issue)+'</p>').join('')+'</section>';
 if(host.configuration_changed)html+='<section class="panel" role="status"><h2>Configuration modifiée depuis cet audit</h2><p>Les anciennes mesures sont conservées. Un nouvel audit est nécessaire pour valider la configuration actuelle.</p></section>';
 // VM measurements are independently attributed, never substituted for SSH metrics.
 const guests=host.proxmox_matches||linked?.proxmox_matches||[];
 if(guests.length===1){
   const g=guests[0];
   html+='<section class="panel"><h2>Mesures API Proxmox de ce serveur</h2><p>'+esc(g.cluster)+' / '+esc(g.node)+' · VM '+esc(g.vmid)+' · '+esc(g.status)+' · '+stamp(g.collected_at)+' · '+(g.fresh?'Récent':'Ancien ou collecte en échec')+'</p><div class="stats">'+[
     ['CPU VM',pct(g.cpu_pct)],['RAM utilisée / allouée',pveSize(g.memory_bytes)+' / '+pveSize(g.memory_total_bytes)],['Capacité disque allouée',pveSize(g.disk_capacity_bytes)]
   ].map(([label,value])=>'<div class="card"><small>'+esc(label)+'</small><strong>'+esc(value)+'</strong></div>').join('')+'</div><p class="note">Source : hyperviseur Proxmox. La capacité allouée ne mesure pas le remplissage des disques dans le serveur. Les contrôles système nécessitent un audit SSH.</p></section>';
 }else if(guests.length>1)html+='<section class="panel"><h2>Mesures API Proxmox</h2><p>Plusieurs VM correspondent à ce serveur : association à vérifier.</p></section>';
 html+='<section class="panel"><h2>Audit SSH enregistré</h2><p>'+esc(host.audit_recorded?'Conservé ; actualisation manuelle disponible.':'Audit initial à réaliser ou couverture non mesurée.')+' · '+stamp(host.collected_at)+'</p><p>Les données SSH décrivent cette date, pas nécessairement l’état actuel.</p><p>'+esc((host.audit_versions||[]).length)+' version(s) conservée(s).</p></section>';
 html+='<section class="panel"><h2>Données API de ce serveur</h2>'+(host.source_details||[]).map(s=>{
   const e=s.evidence||{};
   let content='<p>'+esc(s.scope)+'</p>';
   if(e.agent)content+='<p>Agent Wazuh : '+esc(e.agent.name)+' · '+esc(e.agent.status)+' · version '+esc(e.agent.version||'Non mesurée')+'</p>';
   if(e.host)content+='<p>Zabbix : '+esc(e.host.status)+' · '+esc(e.problems_measured===false?'Non mesuré':(e.problems||[]).length)+' problème(s)</p>'+(e.problems||[]).map(p=>'<p>'+esc(p.description)+'</p>').join('');
   if(e.recent_jobs)content+='<p>'+esc(e.jobs_count)+' jobs distincts associés. Dernier passage des dix plus récents :</p>'+e.recent_jobs.map(j=>'<p>'+esc(j.name)+' · '+esc(j.status_label)+' · '+esc(j.endtime||'Fin non mesurée')+'</p>').join('');
   return '<article><h3>'+esc(s.provider)+'</h3><p>'+stamp(s.collected_at)+' · '+(s.fresh?'Récent':'Ancien ou collecte en échec')+'</p>'+content+(s.error?'<p>'+esc(s.error)+'</p>':'')+'</article>';
 }).join('')+'<p class="note">Une source absente ici est non rapprochée ou non mesurée. La santé globale Elastic ne prouve pas la réception des logs de ce serveur.</p></section>';
 if(!linked)return html;
 const net=linked.network_evidence||{};
 const pve=(linked.proxmox_matches||[]).map(g=>g.cluster+' / '+g.node+' / '+g.vmid+' · '+g.status+(g.fresh?'':' · ancien')).join('; ');
 return html+'<section class="panel"><h2>Sources de ce serveur</h2><p>Proxmox : '+esc(pve||'Non rapproché')+'</p><p>Ping : '+esc(net.fresh?(net.ping===true?'Réussi':net.ping===false?'Sans réponse':'Non mesuré'):'Ancien ou non mesuré')+' · '+stamp(net.collected_at)+'</p><p>Périmètre actif : '+esc(linked.active_scope?'Inclus':linked.scope_reason)+'</p><p>Sources associées : '+esc((linked.source_links||[]).map(s=>s.provider+(s.fresh?'':' · ancien')).join(', ')||'Aucune association documentée')+'</p></section>';
};
