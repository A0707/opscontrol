subtitles.Synchronisation='Inventaire rapproché, fraîcheur des sources et collecte API, SSH et réseau.';
navGroups[1][1].push(['Synchronisation','network']);
navigation();
const beforeSyncRender=render;
render=function(){
 beforeSyncRender();
 if(page!=='Synchronisation'||selected)return;
 $('#content').innerHTML='<section class="panel"><div class="panel-head"><h2>Synchroniser l’infrastructure</h2><button id="sync-all" class="primary">Collecter API + SSH + réseau</button></div><p>Actualisation : API et réseau périodiques ; SSH initial uniquement pour les serveurs sans audit enregistré. Ce bouton relance volontairement tous les audits. Les accès SSH utilisent la configuration et les empreintes déjà vérifiées.</p></section><div id="sync-data">Chargement…</div>';
 loadSync();
};
async function loadSync(){
 const target=$('#sync-data');if(!target)return;
 try{
  const d=await api('/api/sync');if(!target.isConnected)return;
  target.innerHTML='<section class="panel"><h2>Sources</h2><p>'+esc('SSH : '+(d.ssh_job?.running?'en cours':'au repos')+' · Réseau : '+(d.network_job?.running?'en cours':'au repos'))+'</p><p>'+ (d.job.running?'Collecte API en cours : ':'Dernier lot API : ')+d.job.completed+' / '+d.job.total+'</p>'+d.sources.map(s=>'<p><b>'+esc(s.name)+'</b> · '+esc(s.provider)+' · '+stamp(s.collected_at)+' · '+(s.fresh?'Récent':'À actualiser')+(s.error?' · '+esc(s.error):'')+'</p>').join('')+'<p>À raccorder : '+esc(d.missing_providers.join(', ')||'Aucune source manquante')+'</p>'+d.job.errors.map(e=>'<p role="alert">'+esc(e.key)+' : '+esc(e.error)+'</p>').join('')+'</section><section class="panel"><h2>Serveurs et VM associés</h2><p>Rapprochement par nom exact ou couple nœud / VMID documenté. Les associations sont à confirmer ; aucune adresse SSH n’est inventée.</p><div class="table"><table><thead><tr><th>Serveur / IP SSH</th><th>Cluster / nœud / VMID</th><th>État API</th><th>Audit SSH / WAF</th><th>Ping / périmètre actif</th><th>Sources associées</th><th>Accès</th></tr></thead><tbody>'+d.assets.map(h=>'<tr><td>'+esc(h.name)+'<br>'+esc(h.ip)+'</td><td>'+ (h.proxmox_matches.map(g=>esc(g.cluster+' / '+g.node+' / '+g.vmid)).join('<br>')||'Non rapproché')+(h.association==='ambiguous'?'<br>Association ambiguë':'')+'</td><td>'+h.proxmox_matches.map(g=>esc(g.status)+(g.fresh?'':' · Ancien')).join('<br>')+'</td><td>'+badge(h.status)+'<br>'+stamp(h.collected_at)+'</td><td>'+esc(h.active_scope?'VM démarrée · ping réussi':h.scope_reason)+'<br>'+stamp(h.network_evidence?.collected_at)+'</td><td>'+esc((h.source_links||[]).map(s=>s.provider+(s.fresh?'':' · ancien')).join(', ')||'Non rapproché')+'</td><td><button data-host="'+esc(h.key)+'">Détails et SSH</button></td></tr>').join('')+'</tbody></table></div></section><section class="panel"><h2>VM à rapprocher ('+d.unmatched_guests.length+')</h2>'+d.unmatched_guests.map(g=>'<p>'+esc(g.cluster+' / '+g.node+' / '+g.vmid+' · '+g.name+' — '+g.reason)+'</p>').join('')+'</section>';
 }catch(e){if(target.isConnected)target.textContent=e.message}
}
$('#content').addEventListener('click',async e=>{
 if(!e.target.closest('#sync-all'))return;
 const b=e.target.closest('button');b.disabled=true;
 try{await post('/api/sync');await loadSync()}catch(e){$('#error').textContent=e.message}finally{b.disabled=false}
});
$('#refresh').onclick=async()=>{try{await post('/api/sync');await load()}catch(e){$('#error').textContent=e.message}};
setInterval(()=>{if(!document.hidden&&page==='Synchronisation'&&!selected)loadSync()},5000);
