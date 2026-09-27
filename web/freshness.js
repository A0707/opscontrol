// Age advances locally; a page refresh never becomes a new observation.
function ageSeconds(value, now=Date.now()) {
  if (!value) return null;
  const ms=Date.parse(value);
  return Number.isFinite(ms) ? Math.floor((now-ms)/1000) : null;
}
function ageText(value, now=Date.now()) {
  const age=ageSeconds(value,now);
  if(age===null)return 'Date inconnue';
  if(age<0)return 'Horloge à vérifier';
  if(age<60)return 'il y a '+age+' s';
  if(age<3600)return 'il y a '+Math.floor(age/60)+' min '+age%60+' s';
  if(age<86400)return 'il y a '+Math.floor(age/3600)+' h';
  return 'il y a '+Math.floor(age/86400)+' j';
}
function freshnessMarkup(value, label='Mesure', budget=30) {
  const age=ageSeconds(value), old=age===null||age<0||age>budget;
  return '<time class="data-age'+(old?' overdue':'')+'" data-observed-at="'+esc(value||'')+
    '" data-age-label="'+esc(label)+'" data-age-budget="'+budget+'" title="'+esc(stamp(value))+'">'+
    esc(label+' : '+ageText(value)+(old?' · À actualiser':''))+'</time>';
}
function updateAges() {
  if(document.hidden)return;
  document.querySelectorAll('[data-observed-at]').forEach(el=>{
    const value=el.dataset.observedAt, age=ageSeconds(value);
    const old=age===null||age<0||age>Number(el.dataset.ageBudget);
    el.textContent=el.dataset.ageLabel+' : '+ageText(value)+(old?' · À actualiser':'');
    el.classList.toggle('overdue',old);
  });
}
setInterval(updateAges,1000);
document.addEventListener('visibilitychange',updateAges);
