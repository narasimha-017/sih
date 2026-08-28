const API=(localStorage.getItem('API_BASE')||'').replace(/\/$/,'');
const file=document.getElementById('file'), btn=document.getElementById('analyze'), status=document.getElementById('status'), result=document.getElementById('result');
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});
const uploadLabel = document.querySelector('.upload span');
if (file && uploadLabel) {
  file.addEventListener('change', () => {
    if (file.files && file.files[0]) {
      uploadLabel.textContent = `Selected: ${file.files[0].name}`;
    } else {
      uploadLabel.textContent = 'Choose an .eml or .pdf email';
    }
  });
}

function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function levelClass(l){return l==='High Risk'?'high':l==='Suspicious'?'suspicious':l==='Moderate'?'moderate':'low';}
function render(d){
 result.classList.remove('hidden');
 result.innerHTML=`<div class="score ${levelClass(d.risk_level)}"><div><small>RISK</small><strong>${d.risk_score}/100</strong><span>${esc(d.risk_level)}</span></div><div><small>CONFIDENCE</small><strong>${d.confidence}%</strong><span>Evidence support</span></div></div>
 <div class="grid"><article><h3>Case</h3><p><b>${esc(d.case_id)}</b></p><p>${esc(d.threat)}</p><p>Evidence: ${esc(d.evidence_id)}</p><p>SHA-256: <code>${esc(d.evidence_sha256)}</code></p></article>
 <article><h3>Sender</h3><p>${esc(d.sender.display_name)} &lt;${esc(d.sender.address)}&gt;</p><p>Reply-To: ${esc(d.reply_to)||'—'}</p><p>Return-Path: ${esc(d.return_path)||'—'}</p><p>Subject: ${esc(d.subject)||'—'}</p></article></div>
 <div class="grid"><article><h3>Authentication</h3><div class="chips">${Object.entries(d.authentication).map(([k,v])=>`<span class="chip ${v==='pass'?'ok':v==='fail'?'bad':''}">${k.toUpperCase()}: ${esc(v)}</span>`).join('')}</div><p>Received headers: ${d.received_count}</p><p>Relay IPs: ${d.relay_ips.map(esc).join(' → ')||'Not observed'}</p></article>
 <article><h3>URLs & attachments</h3><p>${d.urls.length} URL(s), ${d.attachments.length} attachment(s)</p>${d.url_details.map(u=>`<div class="ioc"><code>${esc(u.url)}</code>${u.flags.length?`<span>${esc(u.flags.join(', '))}</span>`:''}</div>`).join('')}${d.attachments.map(a=>`<div class="ioc"><b>${esc(a.filename)}</b> · ${a.size} bytes · SHA-256 <code>${esc(a.sha256)}</code></div>`).join('')}</article></div>
 <article><h3>Evidence findings</h3>${d.findings.length?d.findings.map(f=>`<div class="finding"><b>+${f.points} · ${esc(f.category)}</b><span>${esc(f.evidence)}</span></div>`).join(''):'<p>No weighted suspicious indicators were found.</p>'}</article>
 <article class="notice"><h3>Forensic limitations</h3><ul>${d.limitations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></article>`;
}
btn.onclick=async()=>{if(!file.files[0]){status.textContent='Select an .eml or .pdf file first.';return;} status.textContent='Analyzing locally through the server…';btn.disabled=true;try{const fd=new FormData();fd.append('file',file.files[0]);const r=await fetch(`${API}/api/analyze`,{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Analysis failed');render(d);status.textContent='Analysis complete. No suspicious URL was fetched.';}catch(e){status.textContent=e.message;}finally{btn.disabled=false;}};

