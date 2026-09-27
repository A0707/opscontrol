// Evidence-first view of the Apache/ModSecurity probe derived from waf_monitor.py.
subtitles['WAF / HA']='Apache, ModSecurity et Fail2ban : mesures, événements et preuves de collecte.';
const wafNames={services:'Services système',apache_modules:'Module ModSecurity',vhosts:'Virtual hosts Apache',engine:'Déclarations SecRuleEngine',fail2ban:'Jail apache-modsecurity',maxretry:'Seuil de tentatives',findtime:'Fenêtre de détection (s)',bantime:'Durée de ban (s)',tcp:'Connexions TCP',conntrack:'Conntrack utilisé',conntrack_max:'Capacité conntrack',iptables:'Compteurs INPUT',traffic:'Échantillon HTTP',modsecurity:'Alertes ModSecurity'};
const wafValue=v=>v==null?'Non mesuré':esc(v);
let wafIpFilter='';
let wafKey=null;
function wafHosts(){return state.hosts.filter(h=>h.role==='WAF ModSecurity')}
function currentWaf(){
 const hosts=wafHosts();
 if(!hosts.length)return null;
 if(!hosts.some(h=>h.key===wafKey))wafKey=hosts[0].key;
 return hosts.find(h=>h.key===wafKey);
}
function wafSelector(hosts){return hosts.length<2?'':'<div class="filters"><label>Serveur WAF <select id="waf-host-select">'+hosts.map(h=>'<option value="'+esc(h.key)+'" '+(h.key===wafKey?'selected':'')+'>'+esc(h.name)+' · '+esc(h.ip)+'</option>').join('')+'</select></label></div>'}
function wafEmpty(){return '<div class="panel empty">Aucun serveur avec le rôle exact « WAF ModSecurity » n’est configuré.<br>Attribuer ce rôle à un serveur (Serveurs → Modifier) pour activer cette page et sa collecte.</div>'}
function wafTable(headers,rows){return '<div class="table waf-table"><table><thead><tr>'+headers.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(x=>'<td>'+esc(x??'—')+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>'+(rows.length?'':'<p class="note">Aucune donnée dans la collecte disponible.</p>')}
function wafPanel(title,body){return '<section class="panel"><h2>'+title+'</h2>'+body+'</section>'}
function advancedWaf(h){
 const w=h.waf||{},s=w.sections||{},data=k=>s[k]?.data;
 const jail=data('fail2ban')||{},traffic=data('traffic')||{},mod=data('modsecurity')||{};
 let html='<section class="panel"><div class="panel-head"><div><h2>WAF ModSecurity · '+esc(h.ip)+'</h2><p>Apache · Fail2ban · HTTP · Réseau</p></div><button class="primary" data-audit-host="'+esc(h.key)+'" '+(state.job.running?'disabled':'')+'>'+(state.job.running?'Collecte en cours…':'Actualiser le WAF')+'</button></div><p>'+esc(h.name)+' · '+stamp(w.collected_at)+(h.stale?' · MESURES ANCIENNES':'')+'</p><p>Contrôles renseignés : '+(w.coverage?esc(w.coverage.measured)+' / '+esc(w.coverage.total):'aucun')+' · '+wafValue(w.duration_ms)+' ms</p><div class="filters"><button data-edit-server="'+esc(h.key)+'">Services critiques</button><button data-host="'+esc(h.key)+'">Audit système et SSH</button><button data-export-waf>Exporter les preuves JSON</button></div>'+(w.error?'<p role="alert">'+esc(w.error)+'</p>':'')+'<p class="note">Collecte en lecture seule via SSH. L’actualisation automatique du cockpit inclut ce WAF. Les règles CRS, le certificat réellement présenté en HTTPS, la VIP et le mode effectif par vhost restent à vérifier.</p></section>';
 html+='<div class="stats waf-stats">'+[['IPs bannies',jail.currently_banned],['Échecs Fail2ban cumulés',jail.total_failed],['Requêtes échantillonnées',traffic.requests],['Réponses 5xx (%)',traffic.errors_5xx_pct],['Lignes ModSecurity',mod.alert_lines],['Score anomalie max',mod.anomaly_max]].map(([k,v])=>'<div class="card"><small>'+k+'</small><strong>'+wafValue(v)+'</strong></div>').join('')+'</div>';
 html+=(w.recommendations||[]).map(t=>'<p class="panel instruction">'+esc(t)+'</p>').join('');
 html+='<div class="waf-columns">'+wafPanel('Protection et services',wafTable(['Service','Chargement','État','Sous-état'],(data('services')||[]).map(x=>[x.name,x.LoadState,x.ActiveState,x.SubState]))+'<p>Module ModSecurity chargé : '+(data('apache_modules')?.security_module_loaded===true?'Oui':data('apache_modules')?.security_module_loaded===false?'Non':'Inconnu')+'</p>')+
 wafPanel('Politique Fail2ban',wafTable(['Contrôle','Valeur'],[['Maxretry',data('maxretry')],['Findtime (secondes)',data('findtime')],['Bantime (secondes)',data('bantime')],['Échecs actuels',jail.currently_failed],['Bans cumulés',jail.total_banned]])+'<p class="note">Valeurs lues sur apache-modsecurity. Les compteurs cumulés peuvent être remis à zéro au redémarrage.</p>')+'</div>';
 html+='<div class="waf-columns">'+wafPanel('Distribution HTTP',wafTable(['Code','Occurrences'],Object.entries(traffic.http_codes||{}))+'<p class="note">Échantillon : '+esc(traffic.first_event||'date inconnue')+' → '+esc(traffic.last_event||'date inconnue')+'. '+wafValue(traffic.unparsed_lines)+' lignes non reconnues. Aucun débit extrapolé.</p>')+wafPanel('Règles ModSecurity',wafTable(['ID de règle','Lignes'],mod.rules||[])+'<p class="note">'+esc(mod.note||'Collecte requise')+'</p>')+'</div>';
 html+='<div class="waf-columns">'+wafPanel('Chemins les plus demandés',wafTable(['Chemin sans paramètres','Occurrences'],traffic.top_urls||[]))+wafPanel('Adresses observées dans les accès',wafTable(['IP','Occurrences'],traffic.top_ips||[])+'<p class="note">Une IP fréquente n’est pas nécessairement hostile. La configuration du proxy peut affecter l’adresse journalisée.</p>')+'</div>';
 html+=wafPanel('Bans actuellement listés','<label>Filtrer les IP bannies <input id="waf-ip-filter" value="'+esc(wafIpFilter)+'" placeholder="Adresse IP…"></label><div id="waf-bans">'+wafTable(['IP'],(jail.banned_ips||[]).filter(ip=>ip.includes(wafIpFilter)).map(ip=>[ip]))+'</div><p class="note">Liste limitée à 500 adresses. Date de ban, pays et organisation non collectés. Aucun déblocage ou ajout de liste blanche depuis ce cockpit.</p>');
 html+=wafPanel('Événements ModSecurity — 60 lignes reconnues, ordre de lecture',wafTable(['Horodatage du journal','Fichier','IP','Règles','Action rapportée','Score'],(mod.events||[]).map(e=>[e.timestamp_raw,e.source,e.client,e.rules.join(', '),e.action,e.score])));
 html+=wafPanel('Réseau L3/L4',wafTable(['Mesure','Valeur'],[['Conntrack',data('conntrack')],['Limite conntrack',data('conntrack_max')],['Paquets DROP/REJECT INPUT',data('iptables')?.packets]])+'<pre>'+esc(data('tcp')?.summary||'Non mesuré')+'</pre><p class="note">'+esc(data('iptables')?.scope||'Compteurs inconnus')+'</p>');
 html+=wafPanel('Déclarations et couverture',Object.entries(s).map(([k,v])=>'<details><summary>'+badge(v.status)+' '+esc(wafNames[k]||k)+'</summary><pre>'+esc(JSON.stringify(v,null,2))+'</pre></details>').join('')||'<p>Aucune preuve collectée.</p>');
 html+=wafPanel('Historique des collectes', '<p class="note">Échantillons successifs susceptibles de se recouvrir ; ne pas sommer les requêtes ou alertes.</p><div id="waf-history">Chargement…</div>');
 return html;
}
const renderBeforeWaf=render;
render=function(){
 renderBeforeWaf();
 if(page!=='WAF / HA'||selected||!state)return;
 const hosts=wafHosts();
 const h=currentWaf();
 if(!h){$('#content').innerHTML=wafEmpty();return}
 $('#content').innerHTML=wafSelector(hosts)+advancedWaf(h);
 const target=$('#waf-history');
 api('/api/hosts/'+encodeURIComponent(h.key)).then(detail=>{if(target.isConnected)target.innerHTML=wafTable(['Collecte','IPs bannies','Requêtes (échantillon)','5xx (%)','Alertes (lignes)'],(detail.history||[]).filter(x=>x.waf).map(x=>[stamp(x.ts),x.waf.banned,x.waf.requests,x.waf.errors_5xx_pct,x.waf.alerts]))}).catch(e=>{if(target.isConnected)target.textContent=e.message});
};
$('#content').addEventListener('change',e=>{
 if(e.target.id!=='waf-host-select')return;
 wafKey=e.target.value;render();
});
$('#content').addEventListener('input',e=>{
 if(e.target.id!=='waf-ip-filter')return;
 wafIpFilter=e.target.value;
 const h=currentWaf();if(!h)return;
 $('#waf-bans').innerHTML=wafTable(['IP'],(h?.waf?.sections?.fail2ban?.data?.banned_ips||[]).filter(ip=>ip.includes(wafIpFilter)).map(ip=>[ip]));
});
$('#content').addEventListener('click',e=>{
 if(!e.target.closest('[data-export-waf]'))return;
 const h=currentWaf();if(!h)return;
 const url=URL.createObjectURL(new Blob([JSON.stringify({server:h.name,ip:h.ip,stale:h.stale,...h.waf},null,2)],{type:'application/json'}));
 const link=document.createElement('a');link.href=url;link.download='waf-audit-'+h.key+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
