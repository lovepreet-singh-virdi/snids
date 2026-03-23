async function pollStatus(){
  try{
    const r = await fetch('/api/status/');
    const j = await r.json();
    const el = document.getElementById('sniffer-status');
    if(el){
      el.innerText = j.active ? `Monitoring on ${j.interface}` : 'Stopped';
    }
  }catch(e){
    // ignore
  }
}
setInterval(pollStatus, 5000);
