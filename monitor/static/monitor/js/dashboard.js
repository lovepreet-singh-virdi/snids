async function updateStatusUI(j){
  const statusEl = document.getElementById('sniffer-status');
  if(statusEl){
    statusEl.innerText = j.active ? `Monitoring on ${j.interface ?? 'unknown'}` : 'Stopped';
    statusEl.classList.remove('bg-success','bg-secondary');
    statusEl.classList.add(j.active ? 'bg-success' : 'bg-secondary');
  }
  const badge = document.getElementById('mon-state');
  if(badge){
    badge.innerText = j.active ? `Running on ${j.interface ?? ''}` : 'Stopped';
    badge.classList.remove('bg-success','bg-secondary');
    badge.classList.add(j.active ? 'bg-success' : 'bg-secondary');
  }
  const startBtn = document.getElementById('btn-start');
  const stopBtn = document.getElementById('btn-stop');
  if(startBtn){ startBtn.disabled = !!j.active; }
  // Keep Stop usable even if status looks stale so users can force-stop
  if(stopBtn){ stopBtn.disabled = false; }
  const liveIface = document.getElementById('live-interface');
  const livePackets = document.getElementById('live-packets');
  const liveAlerts = document.getElementById('live-alerts');
  if(liveIface && j.interface){ liveIface.innerText = `Interface: ${j.interface}`; }
  if(livePackets && typeof j.packet_count !== 'undefined'){ livePackets.innerText = j.packet_count; }
  if(liveAlerts && typeof j.alert_count !== 'undefined'){ liveAlerts.innerText = j.alert_count; }
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
setInterval(pollStatus, 2000);
