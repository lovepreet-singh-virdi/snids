async function updateStatusUI(j){
  const statusEl = document.getElementById('sniffer-status');
  if(statusEl){
    statusEl.innerText = j.active ? `Monitoring on ${j.interface ?? 'unknown'}` : 'Stopped';
    statusEl.classList.remove('bg-success','bg-secondary');
    statusEl.classList.add(j.active ? 'bg-success' : 'bg-secondary');
  }
  const badge = document.getElementById('mon-state');
  if(badge){
    badge.classList.remove('d-none');
    if(j.active){
      badge.innerText = `Running on ${j.interface ?? ''}`;
      badge.classList.remove('bg-secondary');
      badge.classList.add('bg-success');
    }else if(j.interface){
      badge.innerText = `Stopped on ${j.interface}`;
      badge.classList.remove('bg-success');
      badge.classList.add('bg-secondary');
    }else{
      badge.innerText = 'Status: --';
      badge.classList.remove('bg-success');
      badge.classList.add('bg-secondary');
    }
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

function notify(message, variant="info", duration=2500){
  const stack = document.getElementById('snackbar-stack');
  if(!stack) return;
  const el = document.createElement('div');
  el.className = `snackbar ${variant}`;
  el.textContent = message;
  stack.appendChild(el);
  requestAnimationFrame(()=>el.classList.add('show'));
  setTimeout(()=>{
    el.classList.remove('show');
    setTimeout(()=>el.remove(), 300);
  }, duration);
}

// Packet detail modal handler (Traffic page)
document.addEventListener('click', (e)=>{
  const row = e.target.closest('.packet-row');
  if(!row) return;
  const fields = [
    ["Flow", row.dataset.flow],
    ["Time", row.dataset.time],
    ["Source", row.dataset.src],
    ["Destination", row.dataset.dst],
    ["Src Port", row.dataset.sport],
    ["Dst Port", row.dataset.dport],
    ["Flags", row.dataset.flags],
    ["Length", row.dataset.len],
  ];
  const dl = document.getElementById('pktFields');
  if(!dl) return;
  dl.innerHTML = fields.map(([k,v])=>`<dt class="col-sm-4">${k}</dt><dd class="col-sm-8 mb-2">${v || '--'}</dd>`).join('');
  const modalEl = document.getElementById('pktModal');
  if(modalEl){
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();
  }
});
