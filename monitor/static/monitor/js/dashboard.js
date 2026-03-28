async function updateStatusUI(j){
  const statusEl = document.getElementById('sniffer-status');
  if(statusEl){
    statusEl.innerText = j.active ? `Monitoring on ${j.interface ?? 'unknown'}` : 'Stopped';
  }
  const badge = document.getElementById('mon-state');
  if(badge){
    badge.innerText = j.active ? `Running on ${j.interface ?? ''}` : 'Stopped';
    badge.classList.remove('bg-success','bg-secondary');
    badge.classList.add(j.active ? 'bg-success' : 'bg-secondary');
  }
}

async function pollStatus(){
  try{
    const r = await fetch('/api/status/');
    const j = await r.json();
    updateStatusUI(j);
  }catch(e){
    // ignore errors in background poll
  }
}

document.addEventListener('DOMContentLoaded', pollStatus);
setInterval(pollStatus, 5000);