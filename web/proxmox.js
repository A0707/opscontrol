subtitles.Proxmox='Sources Proxmox, nœuds et machines virtuelles collectés par API.';
let proxmoxSources=[],proxmoxQuery='';
const proxmoxExpanded=new Map();
function pveSize(bytes){return bytes==null?'Non mesuré':(bytes/1073741824).toLocaleString('fr-FR',{maximumFractionDigits:1})+' Gio'}
function pveStatus(status,stale){const names={online:'En ligne',offline:'Hors ligne',running:'Démarrée',stopped:'Arrêtée',unknown:'Inconnu'};const classes={online:'ok',offline:'critical',running:'active',stopped:'inactive',unknown:'unknown'};return '<span class="badge '+(stale?'unknown':classes[status]||'unknown')+'">'+(stale?'Ancien · ':'')+esc(names[status]||'Inconnu')+'</span>'}
function proxmoxMarkup(){
 const query=proxmoxQuery.trim().toLowerCase();
 return proxmoxSources.map(c=>{
  const r=sourceResult(c),inv=r.inventory;
  const stale=!sourceFresh(r);
  let html='<section class="panel"><div class="panel-head"><div><h2>'+esc(inv?.cluster?.name||c.name)+'</h2><p>Source : '+esc(c.name)+' · '+esc(c.url)+'</p></div><button class="primary" data-pve-collect="'+esc(c.key)+'">Collecter ce cluster</button></div><p>Dernière collecte : '+stamp(r.collected_at)+(stale?' · À actualiser':'')+'</p>';
  html+=sourceStatus(c);
  if(r.error)html+='<p role="alert" class="instruction">'+esc(r.error)+'</p>';
  if(!inv)return html+'<p>Aucun inventaire API disponible. Vérifier la connexion puis collecter /api2/json/cluster/resources.</p><button data-go="Connexions API">Configurer la connexion</button></section>';
  html+='<div class="service-summary"><span>'+inv.nodes_count+' nœud(s)</span><span>'+inv.counts.qemu+' VM QEMU</span><span>'+inv.counts.lxc+' conteneur(s) LXC</span><span>'+inv.counts.running+' démarré(s)</span><span>'+inv.counts.stopped+' arrêté(s)</span></div><p class="note">'+esc(inv.scope)+'</p>';
  if(inv.cluster)html+='<p>Quorum du cluster : '+(inv.cluster.quorate===true?'Oui':inv.cluster.quorate===false?'Non':'Non mesuré')+'</p>';
  if(inv.cluster_error)html+='<p class="note">Métadonnées du cluster indisponibles : '+esc(inv.cluster_error)+'</p>';
  if(r.warning)html+='<p class="instruction">'+esc(r.warning)+'</p>';
  let matches=0;
  for(const n of inv.nodes){
   const matchGroup=(c.name+' '+n.name).toLowerCase().includes(query);
   const guests=n.guests.filter(g=>!query||matchGroup||(g.name+' '+g.vmid+' '+g.type).toLowerCase().includes(query));
   if(query&&!matchGroup&&!guests.length)continue;
   matches++;
   const id=c.key+'|'+n.name;
   html+='<details class="panel pve-node" data-pve-node="'+esc(id)+'" '+(proxmoxExpanded.get(id)===false?'':'open')+'><summary><b>'+esc(n.name)+'</b> '+pveStatus(n.status,stale)+' · '+n.guests.length+' VM / CT</summary><div class="service-summary"><span>CPU : '+pct(n.cpu_pct)+'</span><span>RAM : '+pveSize(n.memory_bytes)+' / '+pveSize(n.memory_total_bytes)+'</span><span>Uptime : '+(n.uptime_seconds==null?'Non mesuré':Math.floor(n.uptime_seconds/86400)+' j')+'</span></div>'+(n.reported?'':'<p class="note">Nœud déduit de l’affectation des VM ; ses mesures ne sont pas visibles.</p>')+'<div class="table"><table><thead><tr>'+['VMID','Nom','Type','État','CPU','RAM utilisée / allouée','Capacité disque','Pool'].map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>'+guests.map(g=>'<tr><td>'+esc(g.vmid)+'</td><td>'+esc(g.name)+'</td><td>'+esc(g.type==='qemu'?'VM QEMU':'CT LXC')+'</td><td>'+pveStatus(g.status,stale)+'</td><td>'+pct(g.cpu_pct)+'</td><td>'+pveSize(g.memory_bytes)+' / '+pveSize(g.memory_total_bytes)+'</td><td>'+pveSize(g.disk_capacity_bytes)+'</td><td>'+esc(g.pool||'—')+'</td></tr>').join('')+'</tbody></table></div>'+(guests.length?'':'<p>Aucune VM visible sur ce nœud pour ces critères.</p>')+'</details>';
  }
  if(!matches)html+='<p>Aucun nœud ou VM visible pour ces critères.</p>';
  return html+'</section>';
 }).join('')||'<section class="panel"><h2>Aucune connexion Proxmox configurée</h2><p>Ajouter une connexion vers /api2/json/cluster/resources.</p><button data-go="Connexions API">Ajouter une connexion API</button></section>';
}
async function loadProxmox(){
 const target=$('#pve-data');if(!target)return;
 try{
  const sources=await api('/api/connections');if(!target.isConnected)return;
  proxmoxSources=sources.filter(c=>c.provider==='Proxmox');const signature=JSON.stringify(proxmoxSources)+String(proxmoxSources.map(c=>sourceFresh(sourceResult(c))));if(target.dataset.signature!==signature){target.dataset.signature=signature;target.innerHTML=proxmoxMarkup();}
 }catch(e){if(target.isConnected)target.textContent=e.message}
}
const renderBeforeProxmox=render;
render=function(){
 document.querySelectorAll('[data-pve-node]').forEach(n=>proxmoxExpanded.set(n.dataset.pveNode,n.open));
 renderBeforeProxmox();
 if(page!=='Proxmox'||selected)return;
 $('#content').innerHTML='<section class="panel"><div class="panel-head"><h2>Cluster → Nœuds → VM</h2><button data-go="Connexions API">Connexions API</button></div><label>Rechercher un nœud, une VM ou un VMID <input id="pve-search" value="'+esc(proxmoxQuery)+'" placeholder="Ex. pve01, 101, application…"></label><p class="note">Le nom et le quorum proviennent de /cluster/status lorsque accessible. Sinon le nom de la connexion identifie la source. Les droits du jeton peuvent limiter les ressources visibles.</p></section><div id="pve-data">Chargement de l’inventaire API…</div>';
 loadProxmox();
};
$('#content').addEventListener('input',e=>{
 if(e.target.id!=='pve-search')return;
 document.querySelectorAll('[data-pve-node]').forEach(n=>proxmoxExpanded.set(n.dataset.pveNode,n.open));
 proxmoxQuery=e.target.value;$('#pve-data').innerHTML=proxmoxMarkup();
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('[data-pve-collect]');if(!b)return;
 b.disabled=true;b.textContent='Collecte…';
 try{await post('/api/connections/'+encodeURIComponent(b.dataset.pveCollect)+'/collect');await loadProxmox()}
 catch(error){$('#error').textContent=error.message}
 finally{b.disabled=false;b.textContent='Collecter ce cluster'}
});

// Enregistrement aupres du socle : app.js n'a pas a connaitre ce module.
sourceLoaders['Proxmox']=loadProxmox;
