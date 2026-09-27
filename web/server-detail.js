// Per-host monitoring overview. Each duration retains its source and time basis.
const serverAlertFilters=new Map();
function alertDuration(seconds){
 if(seconds==null||!Number.isFinite(seconds))return 'Non mesurée';
 const minutes=Math.floor(seconds/60),hours=Math.floor(minutes/60),days=Math.floor(hours/24);
 return days?days+' j '+hours%24+' h':hours?hours+' h '+minutes%60+' min':minutes?minutes+' min':'Moins d’une minute';
}
function serverAlertRows(host){
 const filter=serverAlertFilters.get(host.key)||{query:'',source:'',severity:''};
 const all=host.alerts?.items||[];
 const matches=all.filter(a=>(!filter.source||a.source===filter.source)&&(!filter.severity||a.severity===filter.severity)&&
  (!filter.query||(a.title+' '+(a.evidence||'')).toLowerCase().includes(filter.query.toLowerCase())));
 return '<p role="status">'+matches.length+' alerte(s) correspondant aux filtres · '+Math.min(50,matches.length)+' affichée(s)</p>'+
  '<div class="table"><table><caption>Alertes de '+esc(host.name)+' · dates affichées dans le fuseau du navigateur</caption><thead><tr>'+['Gravité / source','Problème','Depuis / base de temps','Durée','Dernière observation'].map(s=>'<th scope="col">'+s+'</th>').join('')+'</tr></thead><tbody>'+
  matches.slice(0,50).map(a=>'<tr><td>'+badge(a.severity)+'<p>'+esc(a.source)+'</p></td><td><strong>'+esc(a.title)+'</strong>'+(a.evidence?'<details><summary>Preuve / détail</summary><pre>'+esc(a.evidence)+'</pre></details>':'')+'</td><td>'+stamp(a.started_at)+'<p class="note">'+esc(a.time_basis)+'</p></td><td>'+alertDuration(a.duration_seconds)+(a.fresh?'':'<p class="note">À la dernière observation</p>')+'</td><td>'+stamp(a.observed_at)+'<p class="badge '+(a.fresh?'observed':'unknown')+'">'+(a.fresh?'Observation récente':'À reconfirmer')+'</p></td></tr>').join('')+'</tbody></table></div>'+
  (matches.length?'':'<p>Aucune alerte dans cette sélection. Une source absente ou un contrôle incomplet ne prouve pas que le serveur est sain.</p>');
}
function serverMonitoring(host){
 const counts=host.alerts?.counts||{};
 const filter=serverAlertFilters.get(host.key)||{query:'',source:'',severity:''};
 const sources=[...new Set((host.alerts?.items||[]).map(a=>a.source))];
 const net=host.network_evidence||{};
 return '<section class="panel server-monitoring"><div class="panel-head"><div><h2>Supervision de ce serveur</h2><p>Alertes, ancienneté et couverture des sources</p></div><span class="badge unknown">'+(counts.total??0)+' alerte(s) documentée(s)</span></div>'+
 '<dl class="server-facts">'+[['Système',host.os||'Non mesuré'],['Uptime SSH',host.uptime||'Non mesuré'],['Accès SSH observé',host.ssh_user?host.ssh_user+':'+host.ssh_port:'Non établi'],['Disponibilité réseau',net.fresh?(net.ping===true?'Ping réussi':net.ping===false?'Sans réponse':'Non mesuré'):'Ancienne ou non mesurée'],['Dernier audit SSH',stamp(host.collected_at)],['Alertes à reconfirmer',counts.old??0]].map(([label,value])=>'<div><dt>'+esc(label)+'</dt><dd>'+esc(value)+'</dd></div>').join('')+'</dl>'+
 '<details><summary>Couverture et fraîcheur par source</summary><div class="server-source-list">'+(host.source_details||[]).map(s=>'<article><h3>'+esc(s.provider)+'</h3><p>'+stamp(s.collected_at)+' · '+(s.fresh?'Récente':'Ancienne ou collecte en échec')+'</p><p>'+esc(s.scope)+'</p>'+(s.evidence?.host?'<p>'+(s.evidence.problems_measured?'Alertes Zabbix collectées':'Alertes Zabbix non mesurées')+'</p>':'')+(s.evidence?.problems_scope?'<p>'+esc(s.evidence.problems_scope)+'</p>':'')+(s.error?'<p>'+esc(s.error)+'</p>':'')+'</article>').join('')+'<p>SSH : '+esc(host.coverage?.measured??0)+' / '+esc(host.coverage?.total??0)+' contrôles mesurés. Wazuh décrit ici l’agent ; les événements de sécurité ne sont pas collectés. La santé globale Elasticsearch ne prouve pas la présence des logs de ce serveur.</p></div></details>'+
 '<h3>Alertes et chronologie</h3><p class="note">'+esc(host.alerts?.scope||'Chronologie non disponible : recharger la fiche après mise à jour du serveur OpsControl.')+'</p><div class="filters server-alert-filters"><label>Rechercher<input id="server-alert-query" type="search" value="'+esc(filter.query)+'" placeholder="Disque, service, agent…"></label><label>Source<select id="server-alert-source"><option value="">Toutes</option>'+sources.map(s=>'<option '+(filter.source===s?'selected':'')+' value="'+esc(s)+'">'+esc(s)+'</option>').join('')+'</select></label><label>Gravité<select id="server-alert-severity">'+[['','Toutes'],['critical','Critique'],['warning','Avertissement'],['unreachable','Injoignable'],['unknown','Information / non classée']].map(([v,label])=>'<option value="'+v+'" '+(v===filter.severity?'selected':'')+'>'+label+'</option>').join('')+'</select></label></div><div id="server-alert-results">'+serverAlertRows(host)+'</div></section>';
}
const detailBeforeMonitoring=detailView;
detailView=function(host){
 const html=detailBeforeMonitoring(host), marker='<div class="tabs">';
 return html.includes(marker)?html.replace(marker,serverMonitoring(host)+marker):html+serverMonitoring(host);
};
function updateServerAlertFilter(event){
 const field={'server-alert-query':'query','server-alert-source':'source','server-alert-severity':'severity'}[event.target.id];
 if(!field||!hostDetail)return;
 const filter=serverAlertFilters.get(hostDetail.key)||{query:'',source:'',severity:''};
 filter[field]=event.target.value;serverAlertFilters.set(hostDetail.key,filter);
 const target=document.getElementById('server-alert-results');if(target)target.innerHTML=serverAlertRows(hostDetail);
}
document.getElementById('content').addEventListener('input',updateServerAlertFilter);
document.getElementById('content').addEventListener('change',updateServerAlertFilter);
