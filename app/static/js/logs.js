
// ── Sub-nav ──
function switchLogsView(view){
  ["security","audit","profiles","policy-activity","logins"].forEach(function(v){
    var el=$("lcv-"+v);if(el)el.classList[v===view?"remove":"add"]("hidden");
    var btn=$("lcnav-"+v);
    if(btn){if(v===view){btn.style.background="#334155";btn.style.color="#f1f5f9";}
      else{btn.style.background="";btn.style.color="#94a3b8";}}
  });
  if(view==="audit"&&_auditRaw.length===0) loadAuditLogs();
  if(view==="profiles"&&_profilesRaw.length===0) loadArmorProfiles();
  if(view==="policy-activity"&&_policyActivityRaw.length===0) loadPolicyActivity();
  if(view==="logins"&&_loginHistoryRaw.length===0) loadLoginHistory();
  closeEvDrawer();
}

// ── Time range filter ──
function setSecTimeRange(range){
  _secTimeRange=range;
  document.querySelectorAll(".sf-time-btn").forEach(function(b){
    var active=b.dataset.range===range;
    b.style.background=active?"#1e3a5f":"";
    b.style.color=active?"#60a5fa":"";
    if(active)b.classList.add("sf-time-active"); else b.classList.remove("sf-time-active");
  });
  applySecFilters();
}

// ── Advanced filters panel toggle ──
var _advFiltersOpen=false;
function toggleAdvFilters(){
  _advFiltersOpen=!_advFiltersOpen;
  var panel=$("adv-filters-panel");
  var btn=$("btn-adv-filters");
  if(panel)panel.classList[_advFiltersOpen?"remove":"add"]("hidden");
  if(btn){btn.style.background=_advFiltersOpen?"#1e3a5f":"";btn.style.color=_advFiltersOpen?"#60a5fa":"";}
}

// ── Search debounce ──
var _debounceTimer=null;
function debounceSecFilter(){
  if(_debounceTimer)clearTimeout(_debounceTimer);
  _debounceTimer=setTimeout(applySecFilters,250);
}

// ── Clear all filters ──
function clearSecFilters(){
  var el;
  if(el=$("sf-search"))el.value="";
  if(el=$("sf-action"))el.value="";
  if(el=$("sf-enforcer"))el.value="";
  if(el=$("sf-ns"))el.value="";
  if(el=$("sf-pod"))el.value="";
  if(el=$("sf-container"))el.value="";
  setSecTimeRange(""); // resets _secTimeRange, re-styles buttons, calls applySecFilters
}

// ── Remove a single filter chip ──
function clearSecFilter(field){
  if(field==="time"){setSecTimeRange("");return;}
  var map={action:"sf-action",enforcer:"sf-enforcer",ns:"sf-ns",pod:"sf-pod",container:"sf-container"};
  var el=$(map[field]);if(el)el.value="";
  applySecFilters();
}

// ── Render active filter chips ──
function _renderFilterChips(){
  var chips=[];
  var action=(($("sf-action")||{}).value||"");
  var enforcer=(($("sf-enforcer")||{}).value||"");
  var ns=(($("sf-ns")||{}).value||"").trim();
  var pod=(($("sf-pod")||{}).value||"").trim();
  var cont=(($("sf-container")||{}).value||"").trim();
  if(_secTimeRange) chips.push({label:_secTimeRange,clear:"time"});
  if(ns) chips.push({label:"ns="+ns,clear:"ns"});
  if(pod) chips.push({label:"pod="+pod,clear:"pod"});
  if(cont) chips.push({label:"ctr="+cont,clear:"container"});
  if(action) chips.push({label:"action="+action,clear:"action"});
  if(enforcer) chips.push({label:"enforcer="+enforcer,clear:"enforcer"});
  // Orange dot on Filters button when any advanced filter is active
  var dot=$("adv-filter-dot");
  var hasAdv=!!(_secTimeRange||ns||pod||cont||enforcer);
  if(dot)dot.classList[hasAdv?"remove":"add"]("hidden");
  var fc=$("filter-chips");
  if(!fc)return;
  if(!chips.length){fc.innerHTML="";fc.classList.add("hidden");return;}
  fc.classList.remove("hidden");
  fc.innerHTML=chips.map(function(c){
    return '<span style="display:inline-flex;align-items:center;gap:.2rem;background:#1e293b;color:#94a3b8;font-size:.68rem;padding:.12rem .45rem;border-radius:999px;border:1px solid #334155">'
      +esc(c.label)
      +'<button onclick="clearSecFilter(\''+c.clear+'\')" style="color:#64748b;cursor:pointer;background:none;border:none;padding:0;font-size:.85rem;line-height:1" title="Remove">&#x2715;</button></span>';
  }).join("");
}

// Set a filter programmatically (from summary chip clicks)
function applySecFilter(field,value){
  var el=$({"action":"sf-action","ns":"sf-ns","pod":"sf-pod","enforcer":"sf-enforcer"}[field]);
  if(el)el.value=value;
  applySecFilters();
}

// ── Parse timestamp → ms ──
var _MONTHS={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
function _parseTsMs(s){
  if(!s) return 0;
  var d=new Date(s);
  if(!isNaN(d.getTime())) return d.getTime();
  // syslog: "Jun  7 12:34:56"
  var m=/^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)/.exec(s);
  if(m){
    var mo=_MONTHS[m[1]];if(mo===undefined)return 0;
    var now=new Date();
    var d2=new Date(now.getFullYear(),mo,parseInt(m[2]),parseInt(m[3]),parseInt(m[4]),parseInt(m[5]));
    if(d2.getTime()>Date.now()+60000) d2.setFullYear(now.getFullYear()-1);
    return d2.getTime();
  }
  return 0;
}

// ── Normalize raw events into unified schema ──
function _normalizeViolEvent(ev,idx){
  var sev=(ev.action||"").toUpperCase()||"INFO";
  // resource: AppArmor uses name, BPF path uses path
  var resource=ev.name||ev.path||"";
  return {
    _idx:idx,_src:"viol",
    ts:ev.ts||"",tsMs:_parseTsMs(ev.ts||""),
    severity:sev,
    namespace:ev.namespace||"",pod:ev.pod||"",container:ev.container||"",
    node:ev.node||"",
    enforcer:ev.enforcer||"",operation:ev.operation||"",
    resource:resource,profile:ev.profile||"",
    // AppArmor
    comm:ev.comm||"",deniedMask:ev.deniedMask||"",requestedMask:ev.requestedMask||"",
    // BPF path
    path:ev.path||"",permissions:ev.permissions||"",
    // BPF capability
    capability:ev.capability||"",
    // BPF network
    ip:ev.ip||"",port:ev.port||"",domain:ev.domain||"",protocol:ev.protocol||"",
    // Seccomp
    syscall:ev.syscall||"",exe:ev.exe||"",subj:ev.subj||"",
    // Process
    pid:ev.pid||"",
    raw:ev.raw||JSON.stringify(ev),
  };
}

function _parseAaLine(line){
  var fields={};
  var kv=/(\w+)=("([^"]*)"|(\S+))/g,m;
  while((m=kv.exec(line))!==null){fields[m[1]]=m[3]!==undefined?m[3]:m[4];}
  var tsM=/^(\w{3}\s+\d+\s+\d+:\d+:\d+)/.exec(line);
  return {
    ts:tsM?tsM[1]:"",disp:fields.apparmor||"",
    op:fields.operation||fields.op||"",name:fields.name||fields.path||"",
    prof:fields.profile||"",comm:fields.comm||"",pid:fields.pid||"",
  };
}

function _normalizeAaEvent(line,idx){
  var p=_parseAaLine(line);
  var sev=p.disp.toUpperCase()||"INFO";
  return {
    _idx:idx,_src:"aa",
    ts:p.ts,tsMs:_parseTsMs(p.ts),
    severity:sev,
    namespace:"",pod:"",container:"",
    enforcer:"AppArmor",operation:p.op,
    resource:p.name,profile:p.prof,
    comm:p.comm,pid:p.pid,node:"",raw:line,
  };
}

// ── Load Security Events (Violation + AppArmor merged) ──
async function loadSecurityEvents(){
  hide("sec-err");hide("sec-warn");hide("sec-empty");
  var sb=$("sec-body");if(sb)sb.innerHTML="";
  show("sec-loading");
  var violEvts=[],aaLines=[],warnMsgs=[];
  var nsF=(($("sf-ns")||{}).value||"").trim();
  var actF=(($("sf-action")||{}).value||"").trim();
  var p1=hasPerm("logs:violations")?api("/api/violation-events?limit=500"+(nsF?"&namespace="+encodeURIComponent(nsF):"")+(actF?"&action="+encodeURIComponent(actF):""))
    .then(function(r){return r.json().then(function(d){if(r.ok){violEvts=d.events||[];if(d.warn)warnMsgs.push(d.warn);}});}).catch(function(){})
    :Promise.resolve();
  var p2=hasPerm("logs:apparmor")?api("/api/apparmor-events?limit=500")
    .then(function(r){return r.json().then(function(d){if(r.ok){aaLines=d.events||[];if(d.warn)warnMsgs.push(d.warn);}});}).catch(function(){})
    :Promise.resolve();
  await Promise.all([p1,p2]);
  hide("sec-loading");
  var idx=0;
  var all=violEvts.map(function(e){return _normalizeViolEvent(e,idx++);})
    .concat(aaLines.map(function(l){return _normalizeAaEvent(l,idx++);}));
  all.sort(function(a,b){return b.tsMs-a.tsMs;});
  _secEventsRaw=all;
  if(warnMsgs.length) showEl($("sec-warn"),warnMsgs.join(" | "));
  updateLogsSummary();
  applySecFilters();
}

// ── Apply filters to _secEventsRaw ──
function applySecFilters(){
  var ns=(($("sf-ns")||{}).value||"").trim().toLowerCase();
  var pod=(($("sf-pod")||{}).value||"").trim().toLowerCase();
  var cont=(($("sf-container")||{}).value||"").trim().toLowerCase();
  var act=(($("sf-action")||{}).value||"").toUpperCase();
  var enf=(($("sf-enforcer")||{}).value||"").toLowerCase();
  var srch=(($("sf-search")||{}).value||"").toLowerCase();
  var cutMs=_secTimeRange?Date.now()-{
    "15m":15*60e3,"1h":60*60e3,"24h":24*3600e3,"7d":7*24*3600e3
  }[_secTimeRange]:0;
  var filtered=_secEventsRaw.filter(function(e){
    if(cutMs&&e.tsMs&&e.tsMs<cutMs) return false;
    if(ns&&e.namespace.toLowerCase().indexOf(ns)<0) return false;
    if(pod&&e.pod.toLowerCase().indexOf(pod)<0) return false;
    if(cont&&e.container.toLowerCase().indexOf(cont)<0) return false;
    if(act){
      // AUDIT filter includes AUDIT|ALLOWED (both are audit-type events)
      var actMatch=act==="AUDIT"
        ?(e.severity==="AUDIT"||e.severity==="AUDIT|ALLOWED")
        :e.severity===act;
      if(!actMatch) return false;
    }
    if(enf&&e.enforcer.toLowerCase().indexOf(enf)<0) return false;
    if(srch){
      var haystack=(e.namespace+" "+e.pod+" "+e.container+" "+e.enforcer
        +" "+e.operation+" "+e.resource+" "+e.profile
        +" "+e.syscall+" "+e.capability+" "+e.path+" "+e.comm
        +" "+e.raw).toLowerCase();
      if(haystack.indexOf(srch)<0) return false;
    }
    return true;
  });
  _renderFilterChips();
  renderSecurityEvents(filtered);
}

// ── Render security events table ──
var _SEV_BG={DENIED:"rgba(239,68,68,.07)",AUDIT:"rgba(251,191,36,.05)",ALLOWED:"rgba(74,222,128,.04)","AUDIT|ALLOWED":"rgba(251,191,36,.04)"};
var _SEV_BADGE={DENIED:"badge-red",AUDIT:"badge-amber",ALLOWED:"badge-green","AUDIT|ALLOWED":"badge-amber"};
function _sevBadgeHtml(severity,small){
  var fs=small?"font-size:.58rem":"font-size:.62rem";
  if(severity==="AUDIT|ALLOWED"){
    return '<span class="badge badge-amber" style="'+fs+'">AUDIT</span><span class="badge badge-green" style="'+fs+';margin-left:2px">ALLOWED</span>';
  }
  return '<span class="badge '+(_SEV_BADGE[severity]||"badge-gray")+'" style="'+fs+'">'+esc(severity||"?")+'</span>';
}
function renderSecurityEvents(events){
  var body=$("sec-body");if(!body)return;
  if(!events.length){body.innerHTML="";show("sec-empty");return;}
  hide("sec-empty");
  var rows=events.map(function(e){
    var bg=_SEV_BG[e.severity]||"";
    var sev=_sevBadgeHtml(e.severity,true);
    var srcBadge=e._src==="aa"?'<span style="font-size:.62rem;color:#93c5fd;background:#1e3a5f;padding:1px 5px;border-radius:4px">AA</span>':'<span style="font-size:.62rem;color:#a78bfa;background:#2d1b69;padding:1px 5px;border-radius:4px">VL</span>';
    var tsDisp=e.ts?(e.tsMs?new Date(e.tsMs).toLocaleTimeString("vi-VN",{hour:"2-digit",minute:"2-digit",second:"2-digit"}):e.ts):"—";
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b;cursor:pointer;background:"+bg;
    tr.onmouseover=function(){tr.style.filter="brightness(1.15)";};
    tr.onmouseout=function(){tr.style.filter="";};
    tr.onclick=function(){openEvDrawer(e);};
    tr.innerHTML='<td class="td" style="font-size:.68rem;color:#475569;white-space:nowrap;font-family:monospace">'+esc(tsDisp)+'</td>'
      +'<td class="td">'+sev+'</td>'
      +'<td class="td">'+srcBadge+'</td>'
      +'<td class="td" style="font-size:.72rem;color:#64748b">'+esc(e.namespace||"—")+'</td>'
      +'<td class="td" style="font-family:monospace;font-size:.7rem;color:#93c5fd;max-width:8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(e.pod)+'">'+esc(e.pod||"—")+'</td>'
      +'<td class="td" style="font-size:.7rem;color:#94a3b8">'+esc(e.container||"—")+'</td>'
      +'<td class="td" style="font-size:.7rem;color:#38bdf8">'+esc(e.enforcer||"—")+'</td>'
      +'<td class="td" style="font-size:.7rem;color:#94a3b8">'+esc(e.operation||"—")+'</td>'
      +'<td class="td" style="font-family:monospace;font-size:.68rem;color:#e2e8f0;max-width:12rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(e.resource)+'">'+esc(e.resource||"—")+'</td>'
      +'<td class="td" style="font-family:monospace;font-size:.68rem;color:#7dd3fc;max-width:10rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(e.profile)+'">'+esc(e.profile||"—")+'</td>';
    return tr;
  });
  body.innerHTML="";
  rows.forEach(function(r){body.appendChild(r);});
}

// ── Event detail drawer ──
function openEvDrawer(ev){
  _drawerEvent=ev;
  var sd=$("ev-drawer-sev");
  if(sd){
    if(ev.severity==="AUDIT|ALLOWED"){
      sd.className="";
      sd.innerHTML='<span class="badge badge-amber" style="font-size:.65rem">AUDIT</span><span class="badge badge-green ml-1" style="font-size:.65rem">ALLOWED</span>';
    } else {
      sd.className="badge "+(_SEV_BADGE[ev.severity]||"badge-gray");
      sd.textContent=ev.severity||"?";
    }
  }
  var body=$("ev-drawer-body");if(!body)return;
  var srcLabel=ev._src==="aa"?"AppArmor Kernel (kern.log)":"Violation Log (violations.log)";
  var tsFormatted=ev.tsMs?new Date(ev.tsMs).toLocaleString("vi-VN"):ev.ts||"—";
  function row(label,val,mono){
    if(val===null||val===undefined||val==="") return "";
    return '<div class="flex gap-2 py-1 border-b" style="border-color:#1e293b">'
      +'<span class="text-xs flex-shrink-0" style="color:#475569;width:5.5rem">'+esc(label)+'</span>'
      +'<span class="text-xs break-all'+(mono?" font-mono":"")+'" style="color:#cbd5e1">'+esc(String(val))+'</span></div>';
  }
  function section(title){
    return '<div class="text-xs font-semibold uppercase tracking-wider mt-3 mb-1" style="color:#475569;letter-spacing:.08em">'+title+'</div>';
  }
  // ── Event ──
  var html=section("Event")
    +'<div class="flex gap-2 py-1 border-b" style="border-color:#1e293b">'
    +'<span class="text-xs flex-shrink-0" style="color:#475569;width:5.5rem">Action</span>'
    +'<span>'+_sevBadgeHtml(ev.severity,false)+'</span></div>'
    +row("Time",tsFormatted)
    +row("Source",srcLabel);
  // ── Workload ──
  html+=section("Workload")
    +row("Namespace",ev.namespace)
    +row("Pod",ev.pod,true)
    +row("Container",ev.container)
    +row("Node",ev.node);
  // ── Security (enforcer-specific) ──
  html+=section("Security")
    +row("Enforcer",ev.enforcer)
    +row("Profile",ev.profile,true)
    +row("Operation",ev.operation);
  var enf=(ev.enforcer||"").toLowerCase();
  if(enf==="apparmor"||ev._src==="aa"){
    html+=row("Resource",ev.resource||ev.name,true)
      +row("Denied",ev.deniedMask,true)
      +row("Requested",ev.requestedMask,true);
  } else if(enf==="bpf"){
    html+=row("Path",ev.path||ev.resource,true)
      +row("Permissions",ev.permissions,true)
      +row("Capability",ev.capability)
      +row("IP",ev.ip)
      +(ev.port?row("Port",String(ev.port)):"")
      +row("Domain",ev.domain)
      +row("Protocol",ev.protocol);
  } else if(enf==="seccomp"){
    html+=row("Syscall",ev.syscall,true)
      +row("Executable",ev.exe,true)
      +row("Subject",ev.subj,true);
  } else {
    html+=row("Resource",ev.resource||ev.name,true);
  }
  // ── Process ──
  if(ev.pid||ev.comm||(enf!=="seccomp"&&ev.exe)){
    html+=section("Process")
      +row("PID",ev.pid)
      +row("Command",ev.comm,true)
      +(enf==="seccomp"?"":row("Executable",ev.exe,true));
  }
  // ── Raw JSON (collapsed by default) ──
  html+=section("Raw Log")
    +'<details style="margin-top:.25rem"><summary class="text-xs cursor-pointer select-none" style="color:#475569;padding:.2rem 0">Show raw ▸</summary>'
    +'<div class="mt-1 p-2 rounded text-xs font-mono break-all" style="background:#080f1a;color:#94a3b8;max-height:10rem;overflow-y:auto;border:1px solid #1e293b">'+esc(ev.raw||"")+'</div>'
    +'</details>';
  // ── Actions ──
  html+=section("Actions")
    +'<div class="flex flex-wrap gap-2 mt-1">'
    +(ev.namespace&&ev.pod?'<button onclick="switchTab(\'policy\');switchLogsView(\'security\')" class="btn btn-ghost btn-sm text-xs">&#x1F50D; Check Policy</button>':'')
    +(ev.profile?'<button onclick="switchLogsView(\'profiles\')" class="btn btn-ghost btn-sm text-xs">&#x1F6E1; Profile Status</button>':'')
    +'</div>';
  body.innerHTML=html;
  show("ev-drawer");
}

function closeEvDrawer(){hide("ev-drawer");_drawerEvent=null;}

function copyEvRaw(){
  if(!_drawerEvent)return;
  navigator.clipboard.writeText(_drawerEvent.raw||"").then(function(){
    var b=$("btn-copy-raw");if(!b)return;
    var orig=b.textContent;b.textContent="Copied!";b.style.color="#4ade80";
    setTimeout(function(){b.textContent=orig;b.style.color="";},1500);
  }).catch(function(){});
}

// ── Auto-refresh ──
function toggleAutoRefresh(){
  _autoRefreshActive=!_autoRefreshActive;
  var btn=$("btn-auto-refresh");
  if(btn){
    btn.style.background=_autoRefreshActive?"#1e3a5f":"";
    btn.style.color=_autoRefreshActive?"#60a5fa":"";
    btn.title=_autoRefreshActive?"Auto-refresh ON (30s) — click to disable":"Auto-refresh every 30s";
  }
  if(_autoRefreshActive){
    if(_autoRefreshTimer) clearInterval(_autoRefreshTimer);
    _autoRefreshTimer=setInterval(function(){
      if(CURRENT_TAB==="logs"&&!$("lcv-security").classList.contains("hidden")) loadSecurityEvents();
    },30000);
  } else {
    if(_autoRefreshTimer){clearInterval(_autoRefreshTimer);_autoRefreshTimer=null;}
  }
}

// ── Summary counters ──
function updateLogsSummary(){
  var denied=0,audit=0,allowed=0,aa=0;
  _secEventsRaw.forEach(function(e){
    if(e.severity==="DENIED") denied++;
    else if(e.severity==="AUDIT"||e.severity==="AUDIT|ALLOWED") audit++;
    else if(e.severity==="ALLOWED") allowed++;
    if(e._src==="aa") aa++;
  });
  var notReady=_profilesRaw.filter(function(p){return !p.ready;}).length;
  var auditFail=_auditRaw.filter(function(e){return e.status!=="SUCCESS";}).length;
  function sv(id,n){var el=$(id);if(el)el.textContent=n>=0?n:"—";}
  sv("sval-denied",denied);sv("sval-audit-evt",audit);sv("sval-allowed",allowed);
  sv("sval-aa",aa);sv("sval-not-ready",notReady);sv("sval-audit-fail",auditFail);
}

// ── Console Audit ──
async function loadAuditLogs(){
  setLoading("audit",true);hide("audit-empty");hide("audit-err");$("audit-body").innerHTML="";
  try{
    var r=await api("/api/audit-logs?limit=200"),data=await r.json();
    setLoading("audit",false);
    if(!r.ok){showEl($("audit-err"),data.error||"Failed");return;}
    _auditRaw=data.events||[];
    updateLogsSummary();
    renderAuditLogs(_auditRaw);
  }catch(err){setLoading("audit",false);showEl($("audit-err"),err.message);}
}

function renderAuditLogs(events){
  $("audit-body").innerHTML="";
  if(!events.length){show("audit-empty");return;}
  hide("audit-empty");
  var actionColor={CREATE:"#60a5fa",UPDATE:"#fbbf24",DELETE:"#f87171",CREATE_USER:"#60a5fa",
    DELETE_USER:"#f87171",UPDATE_ROLE:"#a78bfa",UPDATE_ROLE_DEF:"#a78bfa",
    ENABLE_PROTECTION:"#4ade80",DISABLE_PROTECTION:"#fb923c",APPROVE:"#4ade80",REJECT:"#f87171"};
  events.forEach(function(ev){
    var ok=ev.status==="SUCCESS";
    var sb=ok?'<span class="badge badge-green" style="font-size:.65rem">OK</span>':'<span class="badge badge-red" style="font-size:.65rem">FAIL</span>';
    var ac='<span style="font-size:.72rem;font-weight:600;color:'+(actionColor[ev.action]||"#94a3b8")+'">'+esc(ev.action)+'</span>';
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b"+(ok?""  :";background:rgba(239,68,68,.05)");
    tr.innerHTML='<td class="td" style="font-size:.68rem;color:#475569;white-space:nowrap;font-family:monospace">'+esc(ev.ts)+'</td>'
      +'<td class="td" style="font-size:.78rem;color:#94a3b8">'+esc(ev.user)+'</td>'
      +'<td class="td">'+ac+'</td>'
      +'<td class="td" style="font-family:monospace;font-size:.72rem;color:#93c5fd">'+esc(ev.policy)+'</td>'
      +'<td class="td" style="font-size:.72rem;color:#64748b">'+esc(ev.namespace)+'</td>'
      +'<td class="td">'+sb+'</td>'
      +'<td class="td" style="font-size:.68rem;color:#64748b;max-width:14rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(ev.details||"")+'">'+esc(ev.details||"—")+'</td>';
    $("audit-body").appendChild(tr);
  });
}

// ── Profile Models (ArmorProfileModel) ──
async function loadProfileModels(){
  setLoading("models",true);hide("models-empty");hide("models-err");$("models-body").innerHTML="";
  try{
    var r=await api("/api/namespaces/"+ns()+"/profile-models"),data=await r.json();
    setLoading("models",false);
    if(!r.ok){showEl($("models-err"),data.error||"Failed to load behavior models");return;}
    renderProfileModels(data.models||[]);
  }catch(err){setLoading("models",false);showEl($("models-err"),err.message);}
}

function renderProfileModels(models){
  $("models-body").innerHTML="";
  if(!models.length){show("models-empty");return;}
  hide("models-empty");
  models.forEach(function(m){
    var phaseColors={Completed:"badge-green",Ready:"badge-green",Modeling:"badge-purple",Unknown:"badge-gray"};
    var phBadge='<span class="badge '+(phaseColors[m.phase]||"badge-gray")+'">'+esc(m.phase)+'</span>';
    var cr=m.created_at?new Date(m.created_at).toLocaleDateString("vi-VN"):"&#8212;";
    var applyBtn=(canApplyModel()&&m.phase==="Completed")
      ?'<button onclick="applyModel(\''+esc(m.name)+'\',\''+esc(m.namespace)+'\')" class="btn btn-sm ml-1" style="background:#166534;color:#86efac;border:1px solid #166534" title="Apply as DefenseInDepth policy">Apply Armor</button>'
      :'<button disabled class="btn btn-ghost btn-sm ml-1" style="opacity:.4" title="'+(m.phase==="Completed"?"Insufficient permissions":"Modeling not yet complete")+'">Apply Armor</button>';
    var adviseBtn=m.phase==="Completed"
      ?'<button onclick="openAdvisorModal(\''+esc(m.name)+'\',\''+esc(m.namespace)+'\')" class="btn btn-ghost btn-sm ml-1" title="Get rule suggestions from behavior data">&#129302; Suggest Rules</button>'
      :'';
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b;transition:background 100ms";
    tr.onmouseover=function(){tr.style.background="#243552";};
    tr.onmouseout=function(){tr.style.background="";};
    tr.innerHTML='<td class="td" style="font-family:monospace;color:#4ade80;font-size:.8rem">'+esc(m.name)+'</td>'
      +'<td class="td">'+phBadge+'</td>'
      +'<td class="td" style="color:#94a3b8;font-size:.75rem">'+esc(m.storage_type||"")+'</td>'
      +'<td class="td" style="color:#475569;font-size:.75rem">'+cr+'</td>'
      +'<td class="td th-r" style="white-space:nowrap">'
        +'<button onclick="openModelModal(this)" data-name="'+esc(m.name)+'" data-ns="'+esc(m.namespace)+'" class="btn btn-ghost btn-sm">View</button>'
        +adviseBtn
        +applyBtn
      +'</td>';
    $("models-body").appendChild(tr);
  });
}

// ═══════════════════════════════════════════
// ── Policy Activity Log ──
// ═══════════════════════════════════════════

var _PA_ACTIONS = {
  CREATE_POLICY:"CREATE", CREATE_CLUSTER_POLICY:"CREATE",
  UPDATE_POLICY:"UPDATE", UPDATE_CLUSTER_POLICY:"UPDATE",
  DELETE_POLICY:"DELETE", DELETE_CLUSTER_POLICY:"DELETE",
  APPROVE:"APPROVE", REJECT:"REJECT",
  SUBMIT_POLICY:"SUBMIT", SUBMIT_RESTORE:"SUBMIT",
  RESTORE_POLICY:"CREATE", RESTORE_DIRECT:"CREATE",
  IMPORT_POLICY:"CREATE",
};

var _PA_COLOR = {
  CREATE:"#4ade80", UPDATE:"#fbbf24", DELETE:"#f87171",
  APPROVE:"#4ade80", REJECT:"#f87171", SUBMIT:"#a78bfa",
};

async function loadPolicyActivity(){
  setLoading("pa",true); hide("pa-empty"); hide("pa-err");
  $("pa-body").innerHTML="";
  try{
    var r=await api("/api/audit-logs?limit=500"), data=await r.json();
    setLoading("pa",false);
    if(!r.ok){showEl($("pa-err"),data.error||"Failed");return;}
    var POLICY_ACTIONS=Object.keys(_PA_ACTIONS);
    _policyActivityRaw=(data.events||[]).filter(function(e){
      return POLICY_ACTIONS.indexOf(e.action)>=0 || (e.action||"").indexOf("POLICY")>=0 || (e.action||"").indexOf("RESTORE")>=0;
    });
    renderPolicyActivity();
  }catch(err){setLoading("pa",false);showEl($("pa-err"),err.message);}
}

function renderPolicyActivity(){
  var body=$("pa-body"); if(!body)return;
  body.innerHTML="";
  var actFilter=(($("pa-filter-action")||{}).value||"").toUpperCase();
  var stFilter=(($("pa-filter-status")||{}).value||"").toUpperCase();
  var rows=_policyActivityRaw.filter(function(e){
    var cat=_PA_ACTIONS[e.action]||e.action||"";
    if(actFilter && cat!==actFilter) return false;
    if(stFilter && (e.status||"")!==stFilter) return false;
    return true;
  });
  if(!rows.length){show("pa-empty");return;}
  hide("pa-empty");
  rows.forEach(function(ev){
    var cat=_PA_ACTIONS[ev.action]||ev.action||"";
    var color=_PA_COLOR[cat]||"#94a3b8";
    var ok=ev.status==="SUCCESS";
    var sb=ok?'<span class="badge badge-green" style="font-size:.65rem">OK</span>':'<span class="badge badge-red" style="font-size:.65rem">FAIL</span>';
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b"+(ok?"":";background:rgba(239,68,68,.05)");
    tr.onmouseover=function(){tr.style.filter="brightness(1.12)";};
    tr.onmouseout=function(){tr.style.filter="";};
    tr.innerHTML=
      '<td class="td" style="font-size:.68rem;color:#475569;white-space:nowrap;font-family:monospace">'+esc(ev.ts||"—")+'</td>'
      +'<td class="td" style="font-size:.75rem;color:#94a3b8">'+esc(ev.user||"—")+'</td>'
      +'<td class="td"><span style="font-size:.7rem;font-weight:600;color:'+color+'">'+esc(ev.action||"?")+'</span></td>'
      +'<td class="td" style="font-family:monospace;font-size:.72rem;color:#93c5fd">'+esc(ev.policy||"—")+'</td>'
      +'<td class="td" style="font-size:.72rem;color:#64748b">'+esc(ev.namespace||"—")+'</td>'
      +'<td class="td">'+sb+'</td>'
      +'<td class="td" style="font-size:.68rem;color:#64748b;max-width:14rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(ev.details||"")+'">'+esc(ev.details||"—")+'</td>';
    body.appendChild(tr);
  });
}

// ═══════════════════════════════════════════
// ── Login History ──
// ═══════════════════════════════════════════

var _LOGIN_ACTIONS = ["LOGIN","LOGOUT","LOGIN_FAILED","CHANGE_PASSWORD","RESET_PASSWORD"];

async function loadLoginHistory(){
  setLoading("lh",true); hide("lh-empty"); hide("lh-err");
  $("lh-body").innerHTML="";
  var sumEl=$("lh-summary"); if(sumEl){sumEl.classList.add("hidden");sumEl.innerHTML="";}
  try{
    var r=await api("/api/audit-logs?limit=500"), data=await r.json();
    setLoading("lh",false);
    if(!r.ok){showEl($("lh-err"),data.error||"Failed");return;}
    _loginHistoryRaw=(data.events||[]).filter(function(e){
      return _LOGIN_ACTIONS.indexOf(e.action)>=0;
    });
    renderLoginHistory();
  }catch(err){setLoading("lh",false);showEl($("lh-err"),err.message);}
}

function renderLoginHistory(){
  var body=$("lh-body"); if(!body)return;
  body.innerHTML="";
  var stFilter=(($("lh-filter-status")||{}).value||"").toUpperCase();
  var rows=_loginHistoryRaw.filter(function(e){
    if(stFilter && (e.status||"")!==stFilter) return false;
    return true;
  });

  // Summary strip
  var total=_loginHistoryRaw.length;
  var success=_loginHistoryRaw.filter(function(e){return e.status==="SUCCESS"&&e.action==="LOGIN";}).length;
  var failed=_loginHistoryRaw.filter(function(e){return e.action==="LOGIN_FAILED"||e.status==="FAILURE";}).length;
  var sumEl=$("lh-summary");
  if(sumEl&&total>0){
    sumEl.classList.remove("hidden");
    sumEl.innerHTML=[
      {label:"Total Events",val:total,color:"#94a3b8"},
      {label:"Successful Logins",val:success,color:"#4ade80"},
      {label:"Failed Attempts",val:failed,color:"#f87171"},
    ].map(function(s){
      return '<div class="card flex flex-col items-center py-1 px-4" style="min-width:7rem">'
        +'<div class="text-xs" style="color:#64748b">'+s.label+'</div>'
        +'<div class="text-lg font-bold" style="color:'+s.color+'">'+s.val+'</div>'
        +'</div>';
    }).join("");
  }

  if(!rows.length){show("lh-empty");return;}
  hide("lh-empty");

  var _LH_ICON={
    LOGIN:'<svg class="w-3 h-3 inline-block mr-1" fill="none" stroke="#4ade80" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>',
    LOGOUT:'<svg class="w-3 h-3 inline-block mr-1" fill="none" stroke="#94a3b8" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>',
    LOGIN_FAILED:'<svg class="w-3 h-3 inline-block mr-1" fill="none" stroke="#f87171" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
    CHANGE_PASSWORD:'<svg class="w-3 h-3 inline-block mr-1" fill="none" stroke="#fbbf24" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>',
    RESET_PASSWORD:'<svg class="w-3 h-3 inline-block mr-1" fill="none" stroke="#fb923c" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>',
  };
  var _LH_COLOR={LOGIN:"#4ade80",LOGOUT:"#94a3b8",LOGIN_FAILED:"#f87171",CHANGE_PASSWORD:"#fbbf24",RESET_PASSWORD:"#fb923c"};

  rows.forEach(function(ev){
    var ok=ev.status==="SUCCESS";
    var icon=_LH_ICON[ev.action]||"";
    var color=_LH_COLOR[ev.action]||"#94a3b8";
    var sb=ok?'<span class="badge badge-green" style="font-size:.65rem">OK</span>':'<span class="badge badge-red" style="font-size:.65rem">FAIL</span>';
    var isFailed=ev.action==="LOGIN_FAILED"||ev.status==="FAILURE";
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b"+(isFailed?";background:rgba(239,68,68,.05)":"");
    tr.onmouseover=function(){tr.style.filter="brightness(1.12)";};
    tr.onmouseout=function(){tr.style.filter="";};
    tr.innerHTML=
      '<td class="td" style="font-size:.68rem;color:#475569;white-space:nowrap;font-family:monospace">'+esc(ev.ts||"—")+'</td>'
      +'<td class="td" style="font-size:.78rem;color:#e2e8f0;font-weight:500">'+esc(ev.user||"—")+'</td>'
      +'<td class="td"><span style="font-size:.72rem;font-weight:600;color:'+color+'">'+icon+esc(ev.action||"?")+'</span></td>'
      +'<td class="td">'+sb+'</td>'
      +'<td class="td" style="font-size:.68rem;color:#64748b;max-width:18rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(ev.details||"")+'">'+esc(ev.details||"—")+'</td>';
    body.appendChild(tr);
  });
}
