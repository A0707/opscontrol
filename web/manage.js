// Inventory forms live outside the polling area so refreshes never erase edits.
navGroups[2][1].push(['Connexions API','network']);
subtitles['Connexions API']='Sources de collecte HTTPS : Proxmox, Wazuh, Elasticsearch et Bacula.';
const modal=document.createElement('dialog');
modal.id='management-dialog';
document.body.append(modal);
function field(label,name,value='',extra=''){
 return '<label>'+label+'<input name="'+name+'" value="'+esc(value)+'" '+extra+'></label>';
}
function openServer(key){
 const h=state.hosts.find(h=>h.key===key)||{key:'',name:'',ip:'',role:'',environment:'PROD',services:[],port:22};
 modal.innerHTML='<form id="server-form"><div class="panel-head"><h2>'+(key?'Modifier '+esc(h.name):'Ajouter un serveur')+'</h2><button type="button" data-close>Fermer</button></div><p>Configuration du cockpit. La suppression retire le serveur et son historique local du suivi.</p><div class="edit-grid">'+
 field('Identifiant unique','key',h.key,'required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,79}" '+(key?'readonly':''))+
 field('Nom du serveur','name',h.name,'required maxlength="120"')+field('Adresse IP','ip',h.ip,'required')+
 field('Rôle','role',h.role)+field('Environnement','environment',h.environment)+
 '<label>Importance<select name="criticality"><option value="standard">Standard</option><option value="critical" '+(h.criticality==='critical'?'selected':'')+'>Critique</option></select></label>'+
 field('Compte SSH (vide : configuration globale)','user',h.user||'')+field('Port SSH','port',h.port||22,'type="number" min="1" max="65535" required')+
 '</div><label>Services critiques — un nom d’unité par ligne<textarea name="services" rows="5">'+esc((h.services||[]).join('\n'))+'</textarea></label><p class="note">ModSecurity : renseigner nginx ou apache2/httpd selon le serveur installé. Ajouter keepalived seulement si utilisé. ModSecurity est un module, pas nécessairement un service systemd.</p><label><input type="checkbox" name="collect_enabled" '+(h.collect_enabled===false?'':'checked')+'> Collecte SSH activée</label><p class="form-error" role="alert"></p><div class="panel-head"><button class="primary" type="submit">Enregistrer</button>'+(key?'<button type="button" data-delete-server="'+esc(key)+'">Supprimer du suivi</button>':'')+'</div></form>';
 modal.showModal();
}
const providerHints={Proxmox:'/api2/json/cluster/resources',Wazuh:'/manager/status',Zabbix:'/api_jsonrpc.php',Elasticsearch:'/_cluster/health',Bacula:'Chemin de lecture selon votre édition de Bacula',JSON:'Chemin de votre endpoint JSON'};
const authHints={Proxmox:'Format attendu : PVEAPIToken=USER@REALM!TOKENID=SECRET',Wazuh:'Format attendu : utilisateur:mot_de_passe — un jeton JWT est ré-obtenu automatiquement à chaque collecte, jamais à coller ici',Zabbix:'Format attendu : le jeton API seul (Administration → API tokens). Requêtes JSON-RPC de lecture uniquement.',Elasticsearch:'Format attendu : ApiKey CLE_ENCODEE',Bacula:'Format selon votre édition de l’API Bacula',JSON:'Valeur complète de l’en-tête Authorization'};
function openConnection(item={}){
 modal.innerHTML='<form id="connection-form"><div class="panel-head"><h2>Connexion API</h2><button type="button" data-close>Fermer</button></div><div class="edit-grid">'+field('Identifiant','key',item.key||'','required '+(item.key?'readonly':''))+field('Nom','name',item.name||'','required')+'<label>Produit<select name="provider">'+Object.keys(providerHints).map(p=>'<option '+(item.provider===p?'selected':'')+'>'+p+'</option>').join('')+'</select></label><label>Serveur associé<select name="host_key"><option value="">Source globale</option>'+state.hosts.map(h=>'<option value="'+esc(h.key)+'" '+(h.key===item.host_key?'selected':'')+'>'+esc(h.name)+'</option>').join('')+'</select></label></div>'+field('URL HTTPS complète de lecture','url',item.url||'','required type="url"')+field('Variable d’environnement contenant les identifiants','token_env',item.token_env||'','placeholder="OPSCONTROL_PROXMOX_AUTH"')+'<p id="auth-hint" class="note"></p>'+
 '<label>Certificat CA (chemin .pem local, ou contenu PEM de l’autorité vérifiée — vide : autorités reconnues du système)<textarea name="ca_bundle" rows="3" placeholder="C:\\chemin\\vers\\proxmox-ca.pem">'+esc(item.ca_bundle||'')+'</textarea></label>'+
 '<div class="filters"><button type="button" data-check-cert>Vérifier le certificat du serveur</button><span id="cert-status" class="mini">'+(item.ca_bundle?.startsWith('-----BEGIN')?'Certificat PEM renseigné':'')+'</span></div><div id="cert-result"></div>'+
 '<p class="note">Le lanceur mémorise les identifiants chiffrés avec votre compte Windows et les charge automatiquement. Aucun secret dans ce formulaire ni dans le fichier de connexions. Certificat TLS vérifié ; requêtes GET uniquement. Pour Proxmox : copier le certificat public /etc/pve/pve-root-ca.pem depuis sa console de confiance. Le certificat présenté par le nœud ne remplace pas son autorité. Le bouton de vérification permet seulement de l’inspecter.</p><p id="provider-hint"></p><p class="form-error" role="alert"></p><button class="primary" type="submit">Enregistrer la connexion</button></form>';
 const select=modal.querySelector('[name=provider]');
 const hint=()=>{modal.querySelector('#provider-hint').textContent='Endpoint : '+providerHints[select.value];modal.querySelector('#auth-hint').textContent=authHints[select.value]};
 select.onchange=hint;hint();modal.showModal();
}
let connectionItems=[];
async function connectionView(){
 const target=$('#connections-list');if(!target)return;
 try{
 connectionItems=await api('/api/connections');
 if(!target.isConnected)return;
 target.innerHTML=connectionItems.map(c=>'<article class="panel"><div class="panel-head"><h2>'+esc(c.name)+'</h2>'+badge(c.last_result?.status||'unknown')+'</div><p>Identifiants ('+esc(c.token_env||'—')+') dans cette instance : '+(c.auth_configured===true?'Disponibles':c.auth_configured===false?'Absents — lancez LANCER-OPSCONTROL.ps1 pour charger les identifiants mémorisés':'Non vérifié')+'</p><p>'+esc(c.provider)+' · '+esc(c.url)+'</p><p>Dernière collecte : '+stamp(c.last_result?.collected_at)+'</p><pre>'+esc(JSON.stringify(c.last_result||{message:'Aucune collecte effectuée'},null,2))+'</pre><div class="filters"><button data-collect-api="'+esc(c.key)+'">Collecter</button><button data-edit-api="'+esc(c.key)+'">Modifier</button><button data-delete-api="'+esc(c.key)+'">Supprimer</button></div></article>').join('')||'<div class="panel empty">Ajoutez une source avec son URL de lecture. Aucun produit n’est encore raccordé.</div>';
 }catch(e){target.textContent=e.message}
}
const originalRender=render;
render=function(){
 originalRender();
 if(!state)return;
 if(selected&&hostDetail){
  const banner=$('.detail-banner');
  banner?.insertAdjacentHTML('beforeend','<button data-edit-server="'+esc(selected)+'">Modifier le serveur et ses services critiques</button>');
 }else if(page==='Serveurs'){
  $('#content').insertAdjacentHTML('afterbegin','<div class="panel-head"><p>Gérer le parc et les services critiques surveillés.</p><button class="primary" data-add-server>＋ Ajouter un serveur</button></div>');
 }else if(page==='Connexions API'){
  $('#content').innerHTML='<section class="panel"><div class="panel-head"><h2>Sources de données</h2><button class="primary" data-add-api>＋ Ajouter une connexion</button></div><p>Collecte manuelle JSON et indicateurs disponibles. Une réponse API reçue ne prouve pas la conformité du produit.</p><p>Proxmox · Wazuh · Elasticsearch · Bacula</p></section><div id="connections-list">Chargement…</div>';
  connectionView();
 }
};
modal.addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-close'))modal.close();
 if(b.dataset.deleteServer&&confirm('Retirer ce serveur du suivi et supprimer son historique local ?')){
  try{await post('/api/manage/hosts/'+encodeURIComponent(b.dataset.deleteServer)+'/delete');modal.close();selected=null;hostDetail=null;await load()}catch(e){modal.querySelector('.form-error').textContent=e.message}
 }
 if(b.hasAttribute('data-check-cert')){
  const url=modal.querySelector('[name=url]').value;
  const result=modal.querySelector('#cert-result');
  b.disabled=true;result.innerHTML='Vérification…';
  try{
   const cert=await post('/api/connections/certificate',{url});
   result.innerHTML='<p class="note">Empreinte SHA-256 : <code>'+esc(cert.sha256_fingerprint)+'</code>'+(cert.subject_cn?'<br>Sujet : '+esc(cert.subject_cn):'')+(cert.issuer_cn?' · Émetteur : '+esc(cert.issuer_cn):'')+(cert.not_after?'<br>Valide jusqu’au '+esc(cert.not_after):'')+'<br>Comparez cette empreinte à celle affichée par le produit avant de continuer.</p>'+(cert.usable_anchor?'<p class="note">'+(cert.is_ca?'Certificat d’autorité : il couvrira aussi les autres serveurs qu’il a signés.':'Certificat auto-signé de ce serveur : l’épingler ne vaudra que pour lui, et il faudra recommencer à son renouvellement. La vérification TLS complète reste active.')+'</p>'+'<button type="button" class="primary" data-pin-cert>Épingler ce certificat après vérification</button>':'<p>Ce certificat ne permet pas à lui seul de valider la connexion : le nom de l’URL ne lui correspond pas, ou il est hors de sa période de validité. Corriger l’URL, ou renseigner le certificat de son autorité.</p>');
   result.dataset.pem=cert.pem;
  }catch(err){result.textContent=err.message}
  finally{b.disabled=false}
 }
 if(b.hasAttribute('data-pin-cert')){
  const result=modal.querySelector('#cert-result');
  modal.querySelector('[name=ca_bundle]').value=result.dataset.pem;
  modal.querySelector('#cert-status').textContent='Certificat PEM renseigné';
  result.innerHTML='';
 }
});
modal.addEventListener('submit',async e=>{
 e.preventDefault();const form=e.target;const values=Object.fromEntries(new FormData(form));
 const button=form.querySelector('[type=submit]');if(button)button.disabled=true;
 try{
  if(form.id==='server-form'){
   values.port=Number(values.port);values.services=values.services.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);values.collect_enabled=form.elements.collect_enabled.checked;
   await post('/api/manage/hosts',values);
  }else await post('/api/connections',values);
  modal.close();await load();toast('Configuration enregistrée');
 }catch(error){form.querySelector('.form-error').textContent=error.message}finally{if(button)button.disabled=false}
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-add-server'))openServer();
 if(b.dataset.editServer)openServer(b.dataset.editServer);
 if(b.hasAttribute('data-add-api'))openConnection();
 if(b.dataset.editApi)openConnection(connectionItems.find(c=>c.key===b.dataset.editApi));
 try{
  if(b.dataset.collectApi){b.disabled=true;b.textContent='Collecte…';await post('/api/connections/'+encodeURIComponent(b.dataset.collectApi)+'/collect');await connectionView()}
  if(b.dataset.deleteApi&&confirm('Supprimer cette connexion API ?')){await post('/api/connections/'+encodeURIComponent(b.dataset.deleteApi)+'/delete');await connectionView()}
 }catch(error){$('#error').textContent=error.message}finally{b.disabled=false}
});
navigation();
