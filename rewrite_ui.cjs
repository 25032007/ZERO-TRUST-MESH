const fs = require('fs');
let html = fs.readFileSync('public/index.html', 'utf8');

// 1. Sidebar redesign
html = html.replace('<div class="nav-group-label">Command</div>', '<div class="nav-group-label">1. MONITOR</div>');
html = html.replace('<div class="nav-group-label">Threat Intelligence</div>', '<div class="nav-group-label">2. INVESTIGATE</div>');
html = html.replace('<div class="nav-group-label">Zero-Trust Mesh</div>', '<div class="nav-group-label">3. UNDERSTAND</div>');
html = html.replace('<div class="nav-group-label">Security Control</div>', '<div class="nav-group-label">4. CONTROL</div>');
html = html.replace('<div class="nav-group-label">Response</div>', '<div class="nav-group-label">5. RESPOND</div>');

// CSS updates for Sidebar
html = html.replace(
`.nav-group-label{
  padding:8px 10px 3px;
  font-size:9px;
  font-weight:700;
  letter-spacing:1.1px;
  text-transform:uppercase;
  color:var(--sidebar-group-label);
}`,
`.nav-group-label{
  padding:16px 10px 6px 12px;
  font-size:10px;
  font-weight:700;
  letter-spacing:1.5px;
  text-transform:uppercase;
  color:var(--sidebar-group-label);
  position: relative;
}
.nav-group-label::before {
  content: '';
  position: absolute;
  top: 22px;
  left: 0;
  width: 4px;
  height: 1px;
  background: var(--sidebar-divider);
}`);

// 2. Overview Redesign
html = html.replace(
/<!-- Top command row: posture \+ attention -->[\s\S]*?<!-- ============================================================/m,
`<!-- OVERVIEW REDESIGN -->
      <div class="overview-grid">
        <!-- Main Column -->
        <div class="overview-col-main">
          <div class="overview-section">
            <h2 class="section-h">Security Posture</h2>
            <div id="stats-container" class="posture-metrics" style="padding:16px;">
              <div class="metrics-loading">Loading telemetry…</div>
            </div>
          </div>
          <div class="overview-section">
            <h2 class="section-h" style="display:flex; justify-content:space-between;">
              <span>Live Decision Stream</span>
              <span class="section-meta" id="overview-count">Awaiting activity</span>
            </h2>
            <div id="overview-timeline" class="activity-empty" style="border-top:none;">
              Live decision activity will appear here as the pipeline evaluates requests.
            </div>
          </div>
        </div>
        
        <!-- Side Column -->
        <div class="overview-col-side">
          <div class="overview-section">
            <h2 class="section-h">Attention Queue</h2>
            <div style="padding:16px;">
              <div class="attention-empty">
                <div class="attention-mark" aria-hidden="true">i</div>
                <div>
                  <p class="attention-empty-title">No active threat findings</p>
                  <p class="attention-empty-body">Correlated findings will appear here when the intelligence event contract is connected.</p>
                  <div class="data-boundary">Authoritative pipeline activity remains available</div>
                </div>
              </div>
            </div>
          </div>
          
          <div class="overview-section">
            <h2 class="section-h">Analyst Advisory</h2>
            <div id="recs-overview" style="padding:16px; font-size:12px; line-height:1.55;">
              Loading recommendations…
            </div>
          </div>
        </div>
      </div>
      
    </section>

    <!-- ============================================================`);

// Add CSS for Overview Redesign
html = html.replace(
`/* Two-column command area */`,
`/* Overview Redesign */
.overview-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.8fr) minmax(300px, 1.2fr);
  gap: 20px;
}
.overview-section {
  background: var(--surface);
  border: 1px solid var(--border);
  margin-bottom: 20px;
}
.overview-section .section-h {
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--table-header-bg);
  margin: 0;
}
.overview-col-main { min-width:0; }
.overview-col-side { min-width:0; }

/* Two-column command area */`);

// Fix Activity row border
html = html.replace(
`.activity-empty{
  padding:18px 0;
  color:var(--muted);
  font-size:12px;
  border-top:1px solid var(--border);
}`,
`.activity-empty{
  padding:18px 16px;
  color:var(--muted);
  font-size:12px;
}`);

html = html.replace(
`.activity-row{
  display:grid;
  grid-template-columns:72px minmax(0,1fr) 90px;
  gap:8px;
  align-items:center;
  padding:9px 0;
  border-bottom:1px solid var(--border);
  font-size:12px;
}`,
`.activity-row{
  display:grid;
  grid-template-columns:72px minmax(0,1fr) 90px;
  gap:8px;
  align-items:center;
  padding:9px 16px;
  border-bottom:1px solid var(--border);
  font-size:12px;
}`);

// 3. Live Operations Feed Redesign
html = html.replace(
`.event-row{
  display:grid;
  grid-template-columns:78px minmax(0,1fr) minmax(0,1.3fr) 62px;
  border-bottom:1px solid var(--border);
  border-left:3px solid transparent;
  align-items:start;
  font-size:12px;
  transition:background 0.1s;
  cursor:default;
  background:transparent;
  text-align:left;
  width:100%;
  letter-spacing:0;
  text-transform:none;
  padding:0;
  border-top:0;
  border-right:0;
}`,
`.event-row{
  display:grid;
  grid-template-columns:65px 75px minmax(180px,1fr) minmax(180px,1fr) 45px;
  border-bottom:1px solid var(--border);
  border-left:3px solid transparent;
  align-items:center;
  font-size:11px;
  font-family:var(--mono);
  transition:background 0.1s;
  cursor:default;
  background:transparent;
  text-align:left;
  width:100%;
  letter-spacing:0;
  text-transform:none;
  padding:6px 12px;
  border-top:0;
  border-right:0;
  gap: 12px;
}`);

// Update renderFeed in JS
html = html.replace(
`row.innerHTML=
      '<div class="event-col-decision">'+badge(r.decision)+'<span class="event-time">'+new Date(r.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'</span></div>'+
      '<div class="event-col-service"><span class="event-service">'+esc(r.source||'Unknown')+'<span class="event-arrow"> → </span>'+esc(r.destination||'Unknown')+'</span></div>'+
      '<div class="event-col-detail"><span class="event-reason">'+esc(r.reason)+'</span><span class="event-path">'+esc(r.method)+' '+esc(r.path)+'</span></div>'+
      '<div class="event-col-risk">'+(r.riskScore>0?'<span class="risk-score '+(r.riskScore>=50?'risk-high':'risk-medium')+'">'+esc(r.riskScore)+'</span>':'')+' </div>';`,
`row.innerHTML=
      '<div class="event-time">'+new Date(r.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'</div>'+
      '<div>'+badge(r.decision)+'</div>'+
      '<div class="event-service" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><span style="color:var(--text-primary);font-weight:600;">'+esc(r.source||'Unknown')+'</span> <span class="event-arrow">→</span> <span style="color:var(--text-primary);font-weight:600;">'+esc(r.destination||'Unknown')+'</span></div>'+
      '<div class="event-path" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><span style="color:var(--text-primary);font-weight:700;margin-right:6px;">'+esc(r.reason)+'</span><span style="color:var(--text-secondary);">'+esc(r.method)+' '+esc(r.path)+'</span></div>'+
      '<div class="event-col-risk">'+(r.riskScore>0?'<span class="risk-score '+(r.riskScore>=50?'risk-high':'risk-medium')+'">'+esc(r.riskScore)+'</span>':'')+'</div>';`);

// Hide unused CSS rules from old event feed
html = html.replace(`.event-col-decision{padding:9px 10px 9px 9px;display:flex;flex-direction:column;gap:4px;align-items:flex-start;}`, ``);
html = html.replace(`.event-col-service{padding:9px 8px 9px 0;display:flex;align-items:flex-start;min-width:0;}`, ``);
html = html.replace(`.event-col-detail{padding:9px 8px 9px 0;display:flex;flex-direction:column;gap:2px;min-width:0;}`, ``);

// 4. Investigation Redesign
html = html.replace(
`/* Investigation panel */
.investigation-panel{
  background:var(--surface);
  border:1px solid var(--border);
  position:sticky;
  top:0;
  min-height:360px;
}
.investigation-empty{
  padding:28px 16px;
  color:var(--muted);
  font-size:12px;
  line-height:1.55;
}
.investigation-head{
  padding:12px 15px;
  border-bottom:1px solid var(--border);
  display:flex;
  justify-content:space-between;
  gap:8px;
  align-items:flex-start;
}
.investigation-id{margin:0 0 2px;font:700 11.5px var(--mono);color:var(--text-primary);word-break:break-all;}
.investigation-route{font-size:11px;color:var(--text-secondary);margin:0;}
.investigation-body{padding:13px 15px;display:flex;flex-direction:column;gap:14px;}
.inv-group{display:flex;flex-direction:column;gap:7px;}
.inv-label{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);}

/* Decision context grid */
.decision-context{
  display:grid;
  grid-template-columns:1fr 1fr;
  border:1px solid var(--border);
}
.context-cell{
  padding:8px 10px;
  border-right:1px solid var(--border);
  border-bottom:1px solid var(--border);
}
.context-cell:nth-child(2n){border-right:none;}
.context-cell:nth-last-child(-n+2){border-bottom:none;}
.context-key{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);}
.context-val{font-size:12px;font-weight:700;color:var(--text-primary);margin-top:2px;word-break:break-word;}`,
`/* Investigation panel */
.investigation-panel{
  background:var(--surface);
  border:1px solid var(--border);
  position:sticky;
  top:0;
  min-height:360px;
}
.investigation-empty{
  padding:28px 16px;
  color:var(--muted);
  font-size:12px;
  line-height:1.55;
}
.inv-workspace {
  display:flex; flex-direction:column;
}
.inv-header {
  padding:16px;
  border-bottom:1px solid var(--border);
  background:var(--table-header-bg);
}
.inv-id { font:700 12px var(--mono); color:var(--text-primary); word-break:break-all; margin-bottom: 4px; }
.inv-meta { font-size:11px; color:var(--text-secondary); font-family:var(--mono); }

.inv-section {
  padding: 16px;
  border-bottom: 1px dashed var(--border);
}
.inv-section:last-child { border-bottom: none; }
.inv-h {
  font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:1px;
  color:var(--text-secondary); margin-bottom:12px;
}
.inv-data { font-size:12px; line-height:1.5; color:var(--text-primary); }

.inv-identity-grid {
  display: grid;
  grid-template-columns: 80px 1fr;
  gap: 8px 12px;
  font-size: 12px;
}
.inv-grid-label { color: var(--muted); font-family: var(--mono); font-size:11px; text-transform:uppercase; }
.inv-grid-val { color: var(--text-primary); font-family: var(--mono); font-weight:600; word-break:break-all; }`);

html = html.replace(
`$('investigation-panel').innerHTML=
    '<div class="investigation-head"><div><p class="investigation-id">'+esc(r.requestId||'Unknown request')+'</p><p class="investigation-route">'+esc(r.source||'?')+' → '+esc(r.destination||'?')+' · '+esc(r.method)+' '+esc(r.path)+'</p></div>'+badge(r.decision)+'</div>'+
    '<div class="investigation-body">'+
      '<div class="inv-group"><div class="inv-label">Decision context</div>'+
        '<div class="decision-context">'+
          '<div class="context-cell"><div class="context-key">Final risk</div><div class="context-val">'+esc(r.riskScore)+'/100</div></div>'+
          '<div class="context-cell"><div class="context-key">Reason</div><div class="context-val">'+esc(r.reason)+'</div></div>'+
          '<div class="context-cell"><div class="context-key">Risk level</div><div class="context-val">'+esc(r.riskLevel||'—')+'</div></div>'+
          '<div class="context-cell"><div class="context-key">MFA</div><div class="context-val">'+(r.mfaSatisfied?'Satisfied':'Not satisfied')+'</div></div>'+
        '</div>'+
      '</div>'+
      '<div class="inv-group"><div class="inv-label">Risk factors</div>'+factorHtml+'</div>'+
      '<div class="inv-group"><div class="inv-label">Pipeline stage trace</div>'+timelineHtml+'</div>'+
      '<div class="assessment-boundary"><strong>Threat assessment boundary.</strong> Confidence, severity, category, and correlated evidence are not displayed while the backend threat findings API is unavailable.</div>'+
    '</div>';`,
`$('investigation-panel').innerHTML=
    '<div class="inv-workspace">'+
      '<div class="inv-header">'+
        '<div class="inv-id">Event: '+esc(r.requestId||'Unknown')+'</div>'+
        '<div class="inv-meta">'+new Date(r.timestamp).toLocaleString()+' • '+badge(r.decision)+'</div>'+
      '</div>'+
      
      '<div class="inv-section">'+
        '<div class="inv-h">Event Identity</div>'+
        '<div class="inv-identity-grid">'+
          '<div class="inv-grid-label">Source</div><div class="inv-grid-val">'+esc(r.source||'?')+'</div>'+
          '<div class="inv-grid-label">Dest</div><div class="inv-grid-val">'+esc(r.destination||'?')+'</div>'+
          '<div class="inv-grid-label">Route</div><div class="inv-grid-val">'+esc(r.method)+' '+esc(r.path)+'</div>'+
        '</div>'+
      '</div>'+
      
      '<div class="inv-section">'+
        '<div class="inv-h">Decision Context</div>'+
        '<div class="inv-identity-grid">'+
          '<div class="inv-grid-label">Decision</div><div class="inv-grid-val">'+badge(r.decision)+'</div>'+
          '<div class="inv-grid-label">Reason</div><div class="inv-grid-val" style="color:var(--text-primary); font-weight:700;">'+esc(r.reason)+'</div>'+
          '<div class="inv-grid-label">Risk</div><div class="inv-grid-val">'+esc(r.riskScore)+'/100 ('+esc(r.riskLevel||'—')+')</div>'+
          '<div class="inv-grid-label">Auth Context</div><div class="inv-grid-val">'+(r.mfaSatisfied?'MFA Satisfied':'MFA Not Satisfied')+'</div>'+
        '</div>'+
      '</div>'+
      
      '<div class="inv-section">'+
        '<div class="inv-h">Why did this happen?</div>'+
        '<div class="inv-data">'+factorHtml+'</div>'+
      '</div>'+
      
      '<div class="inv-section">'+
        '<div class="inv-h">Pipeline Timeline</div>'+
        '<div class="inv-data">'+timelineHtml+'</div>'+
      '</div>'+
      
      '<div class="inv-section" style="background:var(--surface-elevated); border-bottom:none;">'+
        '<div class="assessment-boundary" style="border:none; padding:0;"><strong>Data Boundary:</strong> Confidence, severity, and correlated evidence are not displayed while the backend threat intelligence API is unavailable.</div>'+
      '</div>'+
    '</div>';`);

// 5. Threat Intelligence Empty States
html = html.replace(
`.intel-empty-state{
  padding:32px 0 28px;
  border-bottom:1px solid var(--border);
}`,
`.intel-empty-state{
  padding:48px 32px;
  border:1px dashed var(--border);
  background: var(--surface-elevated);
  text-align: center;
  border-radius: 4px;
  margin-bottom: 24px;
}
.intel-empty-state .intel-state-body {
  margin: 0 auto 16px;
}`);

// Ensure dark mode isn't "neon cyberpunk" by tweaking a color slightly if needed, but the current tokens seem "deep forest".

// Fix the "investigation-empty" wording to be more analyst-like
html = html.replace(
`Select a live decision to inspect source, destination, final risk score, decision factors, pipeline stage trace, and decision context.<br><br>Threat-finding confidence, severity, and correlated evidence are not displayed while their API contract is unavailable.`,
`<strong>Awaiting Selection</strong><br><br>Select an event from the live decision stream to begin investigation.<br><br>Event identity, decision context, risk factors, and pipeline traces will be populated here. Correlated threat findings require external intelligence feed connection.`);

fs.writeFileSync('public/index.html', html, 'utf8');
console.log('UI redesigned.');
