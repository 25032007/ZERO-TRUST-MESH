
/* =====================================================
   THEME SYSTEM
   ===================================================== */
function getTheme(){
  var s=localStorage.getItem('zt-theme');
  if(s==='light'||s==='dark')return s;
  return window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
}
function setTheme(theme){
  document.documentElement.setAttribute('data-theme',theme);
  localStorage.setItem('zt-theme',theme);
  var btn=document.getElementById('theme-toggle');
  if(btn)btn.textContent=theme==='dark'?'☀ Light':'☾ Dark';
}
function toggleTheme(){
  setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
}
(function(){
  var btn=document.getElementById('theme-toggle');
  if(btn)btn.textContent=getTheme()==='dark'?'☀ Light':'☾ Dark';
})();

/* =====================================================
   UTILITIES
   ===================================================== */
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s??'').replace(/[&<>"]/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const keyHeader=()=>($('key').value?{'x-admin-key':$('key').value}:{});
const api=(path,opts={})=>fetch(path,{...opts,headers:{...keyHeader(),...(opts.headers||{})}}).then((r)=>r.json());
const badge=(decision)=>{
  const cls='bg-'+decision;
  return '<span class="badge '+cls+'">'+esc(decision).replace(/_/g,' ')+'</span>';
};

/* =====================================================
   NAVIGATION — sub-view aware routing
   ===================================================== */
const viewMeta={
  overview:  ['Security Command Center','Monitor authoritative pipeline outcomes, validate controls, and investigate activity across the mesh.'],
  operations:['Live Operations','Review the current stream of authoritative pipeline decisions. Select a row to open its evidence and pipeline trace.'],
  intelligence:['Threat Intelligence','Correlated findings with confidence, severity, and category exposure. Data boundary active — backend contract not yet exposed.'],
  mesh:      ['Zero-Trust Mesh','Registered service relationships derived from active policy. Default-deny for any unlisted service pair.'],
  controls:  ['Security Controls','Validate enforcement policies, containment state, audit integrity, and run the attack simulator.'],
  response:  ['Response Recommendations','Advisory least-privilege guidance from observed policy use. Enforcement remains with the backend policy engine.']
};

// Sub-view tab state: which sub-view tab is active per parent view
const activeSubViews={
  intelligence:'findings',
  mesh:'map',
  controls:'policies'
};

function activateSubView(parentViewId, subViewId){
  // Update in-view tabs
  const tabContainer=document.getElementById(parentViewId+'-tabs');
  if(tabContainer){
    tabContainer.querySelectorAll('.view-tab').forEach((t)=>{
      t.classList.toggle('active',t.dataset.sub===subViewId);
    });
  }
  // Show/hide sub-views
  const panel=document.querySelector('[data-view-panel="'+parentViewId+'"]');
  if(panel){
    panel.querySelectorAll('.sub-view').forEach((sv)=>{
      sv.classList.toggle('active',sv.id===parentViewId+'-'+subViewId||sv.id===parentViewId.replace('controls','controls')+'-'+subViewId);
    });
    // Also match by checking all sub-view IDs in that panel
    panel.querySelectorAll('.sub-view').forEach((sv)=>{
      const matchId=parentViewId+'-'+subViewId;
      sv.classList.toggle('active',sv.id===matchId);
    });
  }
  activeSubViews[parentViewId]=subViewId;
}

function activateView(view, trigger, subView){
  // Show correct console view panel
  document.querySelectorAll('[data-view-panel]').forEach((panel)=>{
    panel.classList.toggle('active',panel.dataset.viewPanel===view);
  });

  // Update nav active state — only the clicked item is active
  document.querySelectorAll('.nav-item[data-view]').forEach((item)=>{
    item.classList.remove('active');
  });
  if(trigger){trigger.classList.add('active');}

  // Update page masthead
  const meta=viewMeta[view]||viewMeta.overview;
  $('page-title').textContent=meta[0];
  $('page-description').textContent=meta[1];
  $('workspace').scrollTop=0;

  // Activate sub-view if specified, else restore last active sub-view
  const hasSubs=['intelligence','mesh','controls'].includes(view);
  if(hasSubs){
    const sub=subView||activeSubViews[view]||{intelligence:'findings',mesh:'map',controls:'policies'}[view];
    activateSubView(view,sub);
  }
}

// Sidebar nav click handlers
document.querySelectorAll('.nav-item[data-view]').forEach((item)=>{
  item.addEventListener('click',()=>{
    const view=item.dataset.view;
    const sub=item.dataset.sub||null;
    activateView(view,item,sub);
  });
});

// In-view tab click handlers (set up once globally via delegation)
document.querySelectorAll('.view-tabs').forEach((tabContainer)=>{
  tabContainer.querySelectorAll('.view-tab').forEach((tab)=>{
    tab.addEventListener('click',()=>{
      // Determine parent view from tab container ID
      const containerId=tabContainer.id; // e.g. "intel-tabs", "mesh-tabs", "controls-tabs"
      const viewMap={'intel-tabs':'intelligence','mesh-tabs':'mesh','controls-tabs':'controls'};
      const parentView=viewMap[containerId];
      if(parentView){
        activateSubView(parentView,tab.dataset.sub);
        // Also update the sidebar nav to reflect sub-view
        document.querySelectorAll('.nav-item[data-view="'+parentView+'"]').forEach((ni)=>{
          ni.classList.toggle('active',ni.dataset.sub===tab.dataset.sub);
        });
      }
    });
  });
});

/* =====================================================
   FEED COUNTER & LIVE DECISIONS
   ===================================================== */
let feedEventCount=0;
let liveDecisions=[];
let selectedDecisionId='';

function updateFeedCount(){
  const el=$('feed-count');
  if(el)el.textContent=feedEventCount+(feedEventCount===1?' event':' events');
  // Update nav badge
  const badge=$('nav-badge-ops');
  if(badge)badge.textContent=feedEventCount>0?feedEventCount:'0';
}

function filteredDecisions(){
  const decision=$('decision-filter')?.value||'';
  const query=($('decision-search')?.value||'').trim().toLowerCase();
  return liveDecisions.filter((r)=>{
    const matchesDecision=!decision||r.decision===decision;
    const text=[r.source,r.destination,r.reason,r.method,r.path].join(' ').toLowerCase();
    return matchesDecision&&(!query||text.includes(query));
  });
}

function renderFeed(){
  const feed=$('feed');
  const decisions=filteredDecisions();
  updateFeedCount();
  if(!decisions.length){
    feed.innerHTML='<div class="feed-empty">'+(liveDecisions.length?'No live decisions match this filter.':'Awaiting live traffic…')+'</div>';
    return;
  }
  feed.innerHTML='';
  decisions.forEach((r)=>{
    let borderColor='transparent';
    if(r.decision==='BLOCK')borderColor='var(--block)';
    else if(r.decision==='STEP_UP_AUTH'||r.decision==='MONITOR')borderColor='var(--warning)';
    const row=document.createElement('button');
    row.type='button';
    row.className='event-row'+(r.requestId===selectedDecisionId?' selected':'');
    row.style.borderLeftColor=borderColor;
    row.setAttribute('aria-label','Inspect '+r.decision+' decision for '+(r.source||'unknown')+' to '+(r.destination||'unknown'));
    row.innerHTML=
      '<div class="event-col-decision">'+badge(r.decision)+'<span class="event-time">'+new Date(r.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'</span></div>'+
      '<div class="event-col-service"><span class="event-service">'+esc(r.source||'Unknown')+'<span class="event-arrow"> → </span>'+esc(r.destination||'Unknown')+'</span></div>'+
      '<div class="event-col-detail"><span class="event-reason">'+esc(r.reason)+'</span><span class="event-path">'+esc(r.method)+' '+esc(r.path)+'</span></div>'+
      '<div class="event-col-risk">'+(r.riskScore>0?'<span class="risk-score '+(r.riskScore>=50?'risk-high':'risk-medium')+'">'+esc(r.riskScore)+'</span>':'')+' </div>';
    row.addEventListener('click',()=>selectDecision(r.requestId));
    feed.appendChild(row);
  });
}

function renderOverviewTimeline(){
  const timeline=$('overview-timeline');
  const count=$('overview-count');
  if(!timeline||!count)return;
  const recent=liveDecisions.slice(0,7);
  count.textContent=recent.length?(recent.length+' event'+(recent.length===1?'':'s')):'Awaiting activity';
  if(!recent.length){
    timeline.className='activity-empty';
    timeline.textContent='Live decision activity will appear here as the pipeline evaluates requests.';
    return;
  }
  timeline.className='activity-timeline';
  timeline.innerHTML=recent.map((r)=>
    '<div class="activity-row">'+
      '<span class="activity-time">'+new Date(r.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})+'</span>'+
      '<span class="activity-route">'+esc(r.source||'?')+' → '+esc(r.destination||'?')+'</span>'+
      badge(r.decision)+
    '</div>'
  ).join('');
}

function renderMeshActivityLive(){
  const el=$('mesh-activity-live');
  if(!el)return;
  if(!liveDecisions.length){el.innerHTML='';return;}
  // Summarize by source→destination pairs
  const pairs={};
  liveDecisions.forEach((r)=>{
    const key=(r.source||'?')+' → '+(r.destination||'?');
    if(!pairs[key])pairs[key]={allow:0,block:0,monitor:0,stepup:0,total:0};
    pairs[key].total++;
    if(r.decision==='ALLOW')pairs[key].allow++;
    else if(r.decision==='BLOCK')pairs[key].block++;
    else if(r.decision==='MONITOR')pairs[key].monitor++;
    else if(r.decision==='STEP_UP_AUTH')pairs[key].stepup++;
  });
  const rows=Object.entries(pairs).sort((a,b)=>b[1].total-a[1].total).slice(0,10);
  el.innerHTML=
    '<div style="margin-top:20px;"><div class="section-header"><h2 class="section-h">Live session traffic (this session)</h2><span class="section-meta">'+liveDecisions.length+' decisions observed</span></div>'+
    '<div class="table-container"><table>'+
    '<thead><tr><th>Service pair</th><th>Allow</th><th>Block</th><th>Monitor</th><th>Step-Up</th><th>Total</th></tr></thead>'+
    '<tbody>'+
    rows.map(([pair,counts])=>
      '<tr>'+
        '<td><span class="mono" style="font-size:11.5px;">'+esc(pair)+'</span></td>'+
        '<td class="ALLOW">'+counts.allow+'</td>'+
        '<td class="BLOCK">'+counts.block+'</td>'+
        '<td class="MONITOR">'+counts.monitor+'</td>'+
        '<td class="STEP_UP_AUTH">'+counts.stepup+'</td>'+
        '<td style="font-weight:700;">'+counts.total+'</td>'+
      '</tr>'
    ).join('')+
    '</tbody></table></div></div>';
}

function selectDecision(requestId){
  selectedDecisionId=requestId;
  const r=liveDecisions.find((item)=>item.requestId===requestId);
  if(!r)return;
  const factors=Array.isArray(r.factors)?r.factors:[];
  const stages=Array.isArray(r.stages)?r.stages:[];
  const factorHtml=factors.length
    ?'<div class="factor-list">'+factors.map((factor)=>'<span class="factor-chip" title="'+esc(factor.detail)+'">'+esc(factor.code)+' +'+esc(factor.points)+'</span>').join('')+'</div>'
    :'<span class="sub">No soft-risk factors recorded for this decision.</span>';
  const timelineHtml=stages.length
    ?'<ol class="stage-timeline">'+stages.map((stage)=>'<li class="stage-row"><span class="stage-name">'+esc(stage.stage)+'</span><strong>'+esc(stage.outcome).toUpperCase()+'</strong> · '+esc(stage.detail)+'</li>').join('')+'</ol>'
    :'<span class="sub">No stage trace included in this event.</span>';
  $('investigation-panel').innerHTML=
    '<div class="investigation-head"><div><p class="investigation-id">'+esc(r.requestId||'Unknown request')+'</p><p class="investigation-route">'+esc(r.source||'?')+' → '+esc(r.destination||'?')+' · '+esc(r.method)+' '+esc(r.path)+'</p></div>'+badge(r.decision)+'</div>'+
    '<div class="investigation-body">'+
      '<div class="inv-group"><div class="inv-label">Decision context</div>'+
        '<div class="decision-context">'+
          '<div class="context-cell"><div class="context-key">Final risk</div><div class="context-val">'+esc(r.riskScore)+'/100</div></div>'+
          '<div class="context-cell"><div class="context-key">Reason</div><div class="context-val">'+esc(r.reason)+'</div></div>'+
          '<div class="context-cell"><div class="context-key">Risk level</div><div class="context-val">'+esc(r.riskLevel||'—')</div></div>'+
          '<div class="context-cell"><div class="context-key">MFA</div><div class="context-val">'+(r.mfaSatisfied?'Satisfied':'Not satisfied')+'</div></div>'+
        '</div>'+
      '</div>'+
      '<div class="inv-group"><div class="inv-label">Risk factors</div>'+factorHtml+'</div>'+
      '<div class="inv-group"><div class="inv-label">Pipeline stage trace</div>'+timelineHtml+'</div>'+
      '<div class="assessment-boundary"><strong>Threat assessment boundary.</strong> Confidence, severity, category, and correlated evidence are not displayed while the backend threat findings API is unavailable.</div>'+
    '</div>';
  renderFeed();
}

function addDecision(r){
  liveDecisions=[r,...liveDecisions].slice(0,100);
  feedEventCount=liveDecisions.length;
  renderFeed();
  renderOverviewTimeline();
  renderMeshActivityLive();
}

/* =====================================================
   HEALTH BAR
   ===================================================== */
function updateHealthBar(m,v,ps){
  const chainOk=v.valid;
  const hasBlocks=m.byDecision&&(m.byDecision.BLOCK||0)>0;
  const dryRun=ps&&!ps.error&&ps.dryRun;
  let dotClass,statusClass,statusText;
  if(!chainOk){dotClass='status-dot-crit';statusClass='crit';statusText='INTEGRITY COMPROMISED';}
  else if(hasBlocks){dotClass='status-dot-warn';statusClass='warn';statusText='THREATS DETECTED';}
  else{dotClass='status-dot-ok';statusClass='ok';statusText='OPERATIONAL';}
  const dot=$('health-dot');
  const statusEl=$('health-status');
  if(dot)dot.className='status-dot-sm '+dotClass;
  if(statusEl){statusEl.className='status-state '+statusClass;statusEl.textContent=statusText;}
  const pageState=$('page-state');
  const pageStateDot=$('page-state-dot');
  if(pageState)pageState.textContent=statusText;
  if(pageStateDot)pageStateDot.className='status-dot-sm '+dotClass;
  const totalEl=$('health-total');
  if(totalEl)totalEl.textContent=(m.total||0).toLocaleString()+' evaluated';
  const chainEl=$('health-chain');
  if(chainEl){
    chainEl.textContent=chainOk
      ?'Audit chain intact ('+v.checked+' entries)'
      :'⚠ Integrity broken at #'+v.brokenAtSeq;
    chainEl.style.color=chainOk?'':'var(--block)';
    chainEl.style.fontWeight=chainOk?'':'700';
  }
  const polEl=$('health-policies');
  if(polEl)polEl.textContent=(ps&&!ps.error?ps.policyCount:'—')+' policies';
  const dryEl=$('health-dryrun');
  if(dryEl)dryEl.style.display=dryRun?'inline-flex':'none';

  // Update audit status display in Controls > Audit sub-view
  const auditStatusEl=$('audit-status-display');
  if(auditStatusEl){
    if(chainOk){
      auditStatusEl.innerHTML='<div class="audit-chain-bar" style="padding:0 0 10px;"><div class="status-dot live"></div><span style="color:var(--allow);font-weight:700;">AUDIT CHAIN: INTACT</span><span class="sub" style="margin-left:6px;">'+v.checked+' entries verified</span></div>';
    } else {
      auditStatusEl.innerHTML='<div class="audit-chain-bar" style="padding:0 0 10px;"><div class="status-dot" style="background:var(--block);"></div><span style="color:var(--block);font-weight:700;">AUDIT CHAIN: COMPROMISED</span><span class="sub" style="margin-left:6px;">Broken at #'+v.brokenAtSeq+'</span></div>';
    }
  }
}

/* =====================================================
   REFRESH METRICS
   ===================================================== */
async function refreshMetrics(){
  try{
    const [m,v,q,ps,recs,jwks]=await Promise.all([
      api('/api/metrics'),
      api('/api/audit/verify'),
      api('/api/quarantine'),
      api('/api/policies/status'),
      api('/api/policies/recommendations'),
      api('/.well-known/jwks.json')
    ]);

    if(m.error){
      $('stats-container').innerHTML='<div class="sub" style="color:var(--block);font-size:12px;">'+esc(m.error)+' — enter the admin key in the sidebar</div>';
      return;
    }

    updateHealthBar(m,v,ps);

    const l=m.pipelineLatency;
    const dryRunBadge=(ps&&!ps.error&&ps.dryRun)
      ?'<span class="badge bg-MONITOR">DRY RUN</span>'
      :'<span style="font-size:13px;font-weight:700;color:var(--muted);">—</span>';

    $('stats-container').innerHTML=
      '<div class="posture-block">'+
        '<div class="posture-group-label">Decisions</div>'+
        '<div class="posture-row">'+
          '<div class="metric-item"><div class="metric-value ALLOW">'+(m.byDecision.ALLOW||0)+'</div><div class="metric-label">Allow</div></div>'+
          '<div class="metric-item"><div class="metric-value STEP_UP_AUTH">'+(m.byDecision.STEP_UP_AUTH||0)+'</div><div class="metric-label">Step-Up</div></div>'+
          '<div class="metric-item"><div class="metric-value BLOCK">'+(m.byDecision.BLOCK||0)+'</div><div class="metric-label">Block</div></div>'+
        '</div>'+
      '</div>'+
      '<div class="posture-block">'+
        '<div class="posture-group-label">Operational</div>'+
        '<div class="posture-row">'+
          '<div class="metric-item"><div class="metric-value">'+m.total+'</div><div class="metric-label">Total</div></div>'+
          '<div class="metric-item"><div class="metric-value">'+m.requestsPerMinute+'</div><div class="metric-label">Req/Min</div></div>'+
          '<div class="metric-item"><div class="metric-value">'+l.p50Ms+'<span class="metric-value-unit">ms</span></div><div class="metric-label">P50</div></div>'+
          '<div class="metric-item"><div class="metric-value">'+l.p99Ms+'<span class="metric-value-unit">ms</span></div><div class="metric-label">P99</div></div>'+
        '</div>'+
      '</div>'+
      '<div class="posture-block">'+
        '<div class="posture-group-label">Configuration</div>'+
        '<div class="posture-row">'+
          '<div class="metric-item"><div class="metric-value">'+(ps&&!ps.error?ps.policyCount:'—')+'</div><div class="metric-label">Policies</div></div>'+
          '<div class="metric-item"><div class="metric-value">'+(jwks&&!jwks.error&&jwks.keys?jwks.keys.length:'—')+'</div><div class="metric-label">Pub. Keys</div></div>'+
          '<div class="metric-item" style="padding-top:2px;">'+dryRunBadge+'<div class="metric-label" style="margin-top:5px;">Dry Run</div></div>'+
        '</div>'+
      '</div>';

    /* Audit chain bar (Containment sub-view) */
    const chainBar=$('audit-chain-bar');
    if(chainBar){
      if(v.valid){
        chainBar.innerHTML='<div class="status-dot live"></div><span style="color:var(--allow);font-weight:700;">AUDIT CHAIN: INTACT</span><span class="sub" style="margin-left:6px;">'+v.checked+' entries verified</span>';
      } else {
        chainBar.innerHTML='<div class="status-dot" style="background:var(--block);"></div><span style="color:var(--block);font-weight:700;">AUDIT CHAIN: COMPROMISED</span><span class="sub" style="margin-left:6px;">Broken at #'+v.brokenAtSeq+'</span>';
      }
    }

    /* Quarantine */
    if(q&&q.length){
      $('quar-container').innerHTML=
        '<div class="table-container"><table>'+
        '<thead><tr><th>Quarantined Service</th><th>Reason</th><th>Until</th></tr></thead>'+
        '<tbody>'+q.map((e)=>
          '<tr>'+
            '<td><strong style="font-family:var(--mono);font-size:12px;">'+esc(e.serviceId)+'</strong></td>'+
            '<td>'+badge('BLOCK')+' '+esc(e.reason).replace(/_/g,' ')+'</td>'+
            '<td style="color:var(--text-secondary);font-size:12px;">'+new Date(e.until).toLocaleTimeString()+'</td>'+
          '</tr>').join('')+
        '</tbody></table></div>';
    } else {
      $('quar-container').innerHTML=
        '<div class="containment-empty">'+
          '<div class="status-dot live" style="flex-shrink:0;"></div>'+
          'No Active Containment Actions'+
        '</div>';
    }

    /* Recommendations — full view */
    if(recs&&!recs.error){
      const recsHtml=buildRecsHtml(recs);
      const recsEl=$('recs');
      if(recsEl)recsEl.innerHTML=recsHtml;
      // Overview mini-recs
      const overviewRecs=$('recs-overview');
      if(overviewRecs){
        if(recs.recommendations&&recs.recommendations.length>0){
          overviewRecs.innerHTML=recs.recommendations.slice(0,3).map((r)=>
            '<div style="display:flex;gap:8px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--border);">'+
              badge(r.type==='INSUFFICIENT_DATA'?'MONITOR':'INFO')+
              '<span style="font-size:12px;color:var(--text-primary);">'+esc(r.message)+'</span>'+
            '</div>'
          ).join('')+
          (recs.recommendations.length>3?'<div style="padding-top:8px;font-size:11px;color:var(--muted);">+'+(recs.recommendations.length-3)+' more in Response → Recommendations</div>':'');
        } else {
          overviewRecs.textContent='No recommendations at this time. All observed traffic is within expected policy scope.';
        }
      }
    }

  } catch(e){ console.error(e); }
}

function buildRecsHtml(recs){
  if(recs.recommendations&&recs.recommendations.length>0){
    return '<div class="recs-table">'+
      '<div class="recs-header-row"><div class="recs-header-cell">Type</div><div class="recs-header-cell">Finding</div></div>'+
      recs.recommendations.map((r)=>
        '<div class="rec-row">'+
          '<div class="rec-type-cell">'+badge(r.type==='INSUFFICIENT_DATA'?'MONITOR':'INFO')+'</div>'+
          '<div class="rec-finding">'+esc(r.message)+'</div>'+
        '</div>').join('')+
      '</div>';
  } else {
    return '<div class="recs-table"><div class="recs-empty">No recommendations at this time. All observed traffic is within expected policy scope.</div></div>';
  }
}

/* =====================================================
   LOAD STATIC DATA (policies, services, simulator)
   ===================================================== */
async function loadStatic(){
  try{
    const [svc,pol]=await Promise.all([api('/api/services'),api('/api/policies')]);
    if(!Array.isArray(pol))return;

    const meshPolicyCount=$('mesh-policy-count');
    const meshServiceCount=$('mesh-service-count');
    if(meshPolicyCount)meshPolicyCount.textContent=pol.length;
    if(meshServiceCount)meshServiceCount.textContent=Array.isArray(svc)?svc.length:'—';

    // Policy meta for controls view
    const ctrlMeta=$('ctrl-policy-meta');
    if(ctrlMeta)ctrlMeta.textContent=pol.length+' policies · '+(Array.isArray(svc)?svc.length:'—')+' services';

    // Policy table HTML
    const policyTableHtml=
      '<thead><tr>'+
        '<th style="width:106px;">Policy ID</th>'+
        '<th>Source → Destination</th>'+
        '<th style="width:100px;">Methods</th>'+
        '<th>Allowed Paths</th>'+
      '</tr></thead><tbody>'+
      pol.map((p)=>
        '<tr>'+
          '<td style="font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap;">'+esc(p.id||'—')+'</td>'+
          '<td>'+
            '<div style="font-weight:700;font-size:12.5px;margin-bottom:2px;font-family:var(--mono);">'+
              esc(p.source)+' <span style="color:var(--muted);font-weight:400;">→</span> '+esc(p.destination)+
            '</div>'+
            '<div class="sub">'+esc(p.description)+'</div>'+
          '</td>'+
          '<td><code>'+esc(p.methods.join(', '))+'</code></td>'+
          '<td>'+
            '<code>'+esc((p.allowPaths||['*']).join(' '))+'</code>'+
            (p.denyPaths?'<div style="margin-top:5px;"><span class="deny-label">Deny:</span> <code>'+esc(p.denyPaths.join(' '))+'</code></div>':'')+
          '</td>'+
        '</tr>').join('')+
      '<tr><td colspan="4" style="text-align:center;color:var(--muted);font-size:11px;padding:10px 15px;">'+
        (Array.isArray(svc)?svc.length:'—')+' registered services · Any unlisted pair is blocked'+
      '</td></tr></tbody>';

    // Populate both policy tables (mesh view + controls view)
    const meshTable=$('policies');
    if(meshTable)meshTable.innerHTML=policyTableHtml;
    const ctrlTable=$('ctrl-policies-table');
    if(ctrlTable)ctrlTable.innerHTML=policyTableHtml;

    // Load simulator scenarios
    const sc=await api('/api/simulator/scenarios');
    let html='';
    let attackHeaderAdded=false;
    sc.forEach((s)=>{
      const isNormal=s.id==='normal-traffic';
      if(isNormal){html+='<div class="sim-group-label">Normal Traffic</div>';}
      else if(!attackHeaderAdded){html+='<div class="sim-group-label">Attack Scenarios — executed against the live pipeline</div>';attackHeaderAdded=true;}
      html+=
        '<div class="sim-scenario '+(isNormal?'sim-scenario--normal':'sim-scenario--attack')+'" id="s-'+s.id+'">'+
          '<div class="sim-row">'+
            '<div class="sim-info">'+
              '<div class="sim-title">'+esc(s.title)+'</div>'+
              '<div class="sim-desc">'+esc(s.description)+'</div>'+
              '<div class="sim-expected">Expected: <span>'+esc(s.expected).toUpperCase()+'</span></div>'+
            '</div>'+
            '<button class="btn btn-secondary btn-sm" data-id="'+s.id+'">Run</button>'+
          '</div>'+
          '<div class="sim-result" style="display:none;"></div>'+
        '</div>';
    });
    $('scenarios').innerHTML=html;
    $('scenarios').querySelectorAll('button[data-id]').forEach((b)=>(b.onclick=()=>run(b.dataset.id)));

  } catch(e){ console.error(e); }
}

/* =====================================================
   SIMULATOR
   ===================================================== */
function renderSim(r){
  const scEl=$('s-'+r.id);
  if(!scEl)return;
  const box=scEl.querySelector('.sim-result');
  box.style.display='block';
  box.innerHTML=
    '<div class="sim-result-verdict '+(r.passed?'ALLOW':'BLOCK')+'">'+(r.passed?'✔ Defence worked as expected':'✖ Unexpected Result')+'</div>'+
    r.steps.map((s)=>
      '<div class="sim-step">'+
        '<span style="width:90px;flex-shrink:0;">'+badge(s.decision)+'</span>'+
        '<span class="sim-step-label">'+esc(s.label)+'</span>'+
        '<span class="sim-step-reason">'+esc(s.reason)+'</span>'+
        (s.riskScore!=null&&s.riskScore>0?'<span class="sim-step-risk '+(s.riskScore>=50?'BLOCK':'MONITOR')+'">Risk '+s.riskScore+'</span>':'')+
      '</div>').join('');
}

async function run(id){renderSim(await api('/api/simulator/'+id,{method:'POST'}));refreshMetrics();}

$('runAll').onclick=async()=>{
  const results=await api('/api/simulator/run-all',{method:'POST'});
  results.forEach(renderSim);
  refreshMetrics();
  const total=results.length;
  const passed=results.filter((r)=>r.passed).length;
  const failed=total-passed;
  const summaryEl=$('sim-summary');
  if(summaryEl){
    summaryEl.style.display='block';
    summaryEl.className='sim-summary '+(failed===0?'sim-summary--pass':'sim-summary--fail');
    summaryEl.textContent=failed===0
      ?'✔ '+passed+' of '+total+' scenarios passed'
      :'✖ '+failed+' of '+total+' scenarios failed — review highlighted results';
  }
};

/* =====================================================
   WEBSOCKET
   ===================================================== */
function connect(){
  const url=(location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws'+
    ($('key').value?'?key='+encodeURIComponent($('key').value):'');
  const ws=new WebSocket(url);

  ws.onopen=()=>{
    $('ws-text').textContent='Feed Connected';
    $('ws-dot').classList.add('live');
    const hwDot=$('health-ws-dot');
    const hwText=$('health-ws-text');
    if(hwDot){hwDot.className='status-dot-sm status-dot-ok';}
    if(hwText)hwText.textContent='Feed Connected';
  };

  ws.onclose=()=>{
    $('ws-text').textContent='Reconnecting…';
    $('ws-dot').classList.remove('live');
    const hwDot=$('health-ws-dot');
    const hwText=$('health-ws-text');
    if(hwDot){hwDot.className='status-dot-sm status-dot-warn';}
    if(hwText)hwText.textContent='Reconnecting…';
    setTimeout(connect,2000);
  };

  ws.onmessage=(e)=>{
    const r=JSON.parse(e.data).data;
    if(!r||r.type&&r.type!=='decision')return;
    addDecision(r);
  };
}

/* =====================================================
   INIT
   ===================================================== */
$('key').addEventListener('change',()=>location.reload());
$('decision-filter').addEventListener('change',renderFeed);
$('decision-search').addEventListener('input',renderFeed);
loadStatic();
refreshMetrics();
connect();
setInterval(refreshMetrics,3000);
