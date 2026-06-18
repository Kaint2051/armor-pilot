
// ── Dashboard ──
async function loadDashboardLegacy(){
  ["dash-ns","dash-cluster","dash-ready","dash-notready","dash-protected","dash-workloads"].forEach(function(id){
    var el=$(id);if(el)el.textContent="…";
  });
  $("dash-modes").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading…</div>';
  $("dash-enforcers").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading…</div>';
  $("dash-activity").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading…</div>';
  $("dash-agents").innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">Loading…</div>';
  $("dash-enforcement").innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">Loading…</div>';
  var namespace=ns();
  try{
    var [r1,r2,r3,r4]=await Promise.allSettled([
      api("/api/namespaces/"+namespace+"/policies"),
      api("/api/cluster-policies"),
      api("/api/namespaces/"+namespace+"/deployments"),
      api("/api/audit-logs?limit=10"),
    ]);
    var nsPols=[],clPols=[],deps=[],auditEvs=[];
    if(r1.status==="fulfilled"&&r1.value.ok){var d1=await r1.value.json();nsPols=d1.policies||[];}
    if(r2.status==="fulfilled"&&r2.value.ok){var d2=await r2.value.json();clPols=d2.policies||[];}
    if(r3.status==="fulfilled"&&r3.value.ok){var d3=await r3.value.json();deps=d3.deployments||[];}
    if(r4.status==="fulfilled"&&r4.value.ok){var d4=await r4.value.json();auditEvs=d4.events||[];}
    var allPols=nsPols.concat(clPols);
    var readyCnt=allPols.filter(function(p){return p.status==="Ready";}).length;
    var protCnt=deps.filter(function(d){return d.varmor_enabled;}).length;
    $("dash-ns").textContent=nsPols.length;
    $("dash-cluster").textContent=clPols.length;
    $("dash-ready").textContent=readyCnt;
    $("dash-notready").textContent=allPols.length-readyCnt;
    $("dash-protected").textContent=protCnt;
    $("dash-workloads").textContent=deps.length;
    // Mode chart
    var modeCounts={};
    allPols.forEach(function(p){var m=p.mode||"Unknown";modeCounts[m]=(modeCounts[m]||0)+1;});
    renderBarChart("dash-modes",modeCounts,{
      EnhanceProtect:"#3b82f6",AlwaysAllow:"#f59e0b",RuntimeDefault:"#64748b",
      BehaviorModeling:"#a78bfa",DefenseInDepth:"#34d399",Unknown:"#475569"
    });
    // Enforcer chart
    var enfCounts={};
    allPols.forEach(function(p){
      (p.enforcer||"AppArmor").split("|").filter(Boolean).forEach(function(e){enfCounts[e]=(enfCounts[e]||0)+1;});
    });
    renderBarChart("dash-enforcers",enfCounts,{
      AppArmor:"#60a5fa",BPF:"#34d399",Seccomp:"#f472b6",NetworkProxy:"#fb923c"
    });
    // Status donut (text only)
    renderDashActivity(auditEvs.slice(0,8));
    var upd=$("dash-updated");
    if(upd)upd.textContent="Updated "+new Date().toLocaleTimeString("vi-VN",{hour:"2-digit",minute:"2-digit",second:"2-digit"});
  }catch(err){console.error("Dashboard error:",err);}
  loadAgentHealth();
  loadEnforcementEvents();
}

async function loadDashboard(){
  ["dash-ns","dash-cluster","dash-ready","dash-notready","dash-protected","dash-workloads",
   "dash-workload-ready","dash-agent-health","dash-events-total","dash-model-total",
   "dash-policy-total","dash-policy-ns","dash-policy-cluster","dash-policy-ready","dash-policy-notready",
   "dash-workload-coverage","dash-workload-protected","dash-workload-total","dash-workload-ready-compact",
   "dash-replica-ready-compact","dash-agent-health-compact","dash-agent-restarts-compact",
   "dash-events-total-compact","dash-events-breakdown-compact","dash-model-total-compact",
   "dash-model-breakdown-compact"].forEach(function(id){
    var el=$(id);if(el)el.textContent="...";
  });
  $("dash-modes").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading...</div>';
  $("dash-enforcers").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading...</div>';
  $("dash-workload-kinds").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading...</div>';
  $("dash-models-summary").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading...</div>';
  $("dash-activity").innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">Loading...</div>';
  $("dash-agents").innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">Loading...</div>';
  $("dash-enforcement").innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">Loading...</div>';
  var namespace=ns();
  try{
    var res=await api("/api/dashboard-summary?namespace="+encodeURIComponent(namespace));
    var data=await res.json();
    if(!res.ok){throw new Error(data.error||"Dashboard summary failed");}
    var pol=data.policies||{},wl=data.workloads||{},agents=data.agents||{},events=data.enforcement||{},models=data.models||{};
    $("dash-ns").textContent=pol.namespace||0;
    $("dash-cluster").textContent=pol.cluster||0;
    $("dash-ready").textContent=pol.ready||0;
    $("dash-notready").textContent=pol.not_ready||0;
    $("dash-protected").textContent=wl.protected||0;
    $("dash-workloads").textContent=wl.total||0;
    $("dash-workload-ready").textContent=(wl.ready||0)+"/"+(wl.total||0);
    $("dash-replica-ready").textContent=(wl.ready_replicas||0)+"/"+(wl.desired_replicas||0)+" replicas ready";
    $("dash-agent-health").textContent=(agents.healthy||0)+"/"+(agents.total||0);
    $("dash-agent-restarts").textContent=(agents.restarts||0)+" restarts observed";
    $("dash-events-total").textContent=events.total||0;
    $("dash-events-breakdown").textContent=(events.apparmor||0)+" AppArmor / "+(events.bpf||0)+" BPF / "+(events.seccomp||0)+" Seccomp";
    $("dash-model-total").textContent=models.total||0;
    $("dash-model-breakdown").textContent=formatCounts(models.by_phase||{});
    setText("dash-policy-total",(pol.namespace||0)+(pol.cluster||0));
    setText("dash-policy-ns",pol.namespace||0);
    setText("dash-policy-cluster",pol.cluster||0);
    setText("dash-policy-ready",pol.ready||0);
    setText("dash-policy-notready",pol.not_ready||0);
    setText("dash-workload-coverage",(wl.protected||0)+"/"+(wl.total||0));
    setText("dash-workload-protected",wl.protected||0);
    setText("dash-workload-total",wl.total||0);
    setText("dash-workload-ready-compact",(wl.ready||0)+"/"+(wl.total||0));
    setText("dash-replica-ready-compact",(wl.ready_replicas||0)+"/"+(wl.desired_replicas||0)+" replicas");
    setText("dash-agent-health-compact",(agents.healthy||0)+"/"+(agents.total||0));
    setText("dash-agent-restarts-compact",(agents.restarts||0)+" restarts");
    setText("dash-events-total-compact",events.total||0);
    setText("dash-events-breakdown-compact",(events.apparmor||0)+" AA / "+(events.bpf||0)+" BPF / "+(events.seccomp||0)+" SC");
    setText("dash-model-total-compact",models.total||0);
    setText("dash-model-breakdown-compact",formatCounts(models.by_phase||{}));
    renderCompactStackedChart("dash-modes",pol.by_mode||{},{
      EnhanceProtect:"#3b82f6",AlwaysAllow:"#f59e0b",RuntimeDefault:"#64748b",
      BehaviorModeling:"#a78bfa",DefenseInDepth:"#34d399",Unknown:"#475569"
    });
    renderCompactStackedChart("dash-enforcers",pol.by_enforcer||{},{
      AppArmor:"#60a5fa",BPF:"#34d399",Seccomp:"#f472b6",NetworkProxy:"#fb923c"
    });
    renderWorkloadKinds(wl.by_kind||{});
    renderModelSummary(models);
    renderDashboardErrors(data.errors||[],events.warn);
    renderDashActivity((data.activity||[]).slice(0,8));
    var upd=$("dash-updated");
    if(upd)upd.textContent="Updated "+new Date().toLocaleTimeString("vi-VN",{hour:"2-digit",minute:"2-digit",second:"2-digit"});
  }catch(err){
    console.error("Dashboard error:",err);
    renderDashboardErrors([{section:"dashboard",error:err.message}],null);
  }
  loadAgentHealth();
  loadEnforcementEvents();
}

function formatCounts(counts){
  var entries=Object.entries(counts||{}).filter(function(kv){return kv[1];});
  if(!entries.length) return "No data";
  return entries.map(function(kv){return kv[0]+": "+kv[1];}).join(" / ");
}

function setText(id,value){
  var el=$(id);
  if(el) el.textContent=value;
}

function renderWorkloadKinds(byKind){
  var el=$("dash-workload-kinds");if(!el)return;
  var counts={};
  Object.entries(byKind||{}).forEach(function(kv){counts[kv[0]]=(kv[1]&&kv[1].total)||0;});
  renderCompactStackedChart("dash-workload-kinds",counts,{
    Deployment:"#22d3ee",StatefulSet:"#60a5fa",DaemonSet:"#34d399",Pod:"#fbbf24"
  },function(label,count){
    var s=(byKind||{})[label]||{};
    return count+" total, "+(s.ready||0)+" ready";
  });
}

function renderModelSummary(models){
  var el=$("dash-models-summary");if(!el)return;
  var phase=models.by_phase||{},storage=models.by_storage||{};
  var phaseHtml=compactMiniStackedChartHtml(phase,{
    Completed:"#34d399",Ready:"#22d3ee",Modeling:"#a78bfa",Unknown:"#64748b"
  });
  var storageHtml=compactMiniStackedChartHtml(storage,{
    CRDInternal:"#60a5fa",LocalDisk:"#fbbf24",Unknown:"#64748b"
  });
  el.innerHTML='<div style="margin-bottom:.6rem">'
    +'<div style="font-size:.65rem;color:#64748b;margin-bottom:.25rem;text-transform:uppercase;letter-spacing:.06em">Phase</div>'
    +phaseHtml+'</div>'
    +'<div><div style="font-size:.65rem;color:#64748b;margin-bottom:.25rem;text-transform:uppercase;letter-spacing:.06em">Storage</div>'
    +storageHtml+'</div>';
}

function renderDashboardErrors(errors,eventWarn){
  var el=$("dash-errors");if(!el)return;
  var all=(errors||[]).slice();
  if(eventWarn) all.push({section:"enforcement",error:eventWarn});
  if(!all.length){hide("dash-errors");el.innerHTML="";return;}
  show("dash-errors");
  el.innerHTML='<div class="text-sm font-semibold mb-2" style="color:#fca5a5">Dashboard warnings</div>'
    +all.map(function(e){return '<div class="text-xs" style="color:#fca5a5;margin:.25rem 0"><b>'+esc(e.section||"section")+'</b>: '+esc(e.error||"unknown")+'</div>';}).join("");
}

function compactStackedChartHtml(counts,colorMap,labelFormatter){
  var entries=Object.entries(counts||{}).filter(function(kv){return Number(kv[1])>0;})
    .sort(function(a,b){return b[1]-a[1];});
  if(!entries.length){return '<div class="text-xs py-3 text-center" style="color:#475569">No data</div>';}
  var total=entries.reduce(function(sum,kv){return sum+Number(kv[1]||0);},0);
  var segments=entries.map(function(kv){
    var label=kv[0],count=Number(kv[1]||0);
    var pct=total?Math.max(4,Math.round(count/total*100)):0;
    return '<div title="'+esc(label)+': '+count+'" style="height:100%;width:'+pct+'%;background:'+(colorMap[label]||"#64748b")+'"></div>';
  }).join("");
  var legend=entries.slice(0,5).map(function(kv){
    var label=kv[0],count=Number(kv[1]||0);
    var text=labelFormatter?labelFormatter(label,count):(count+"");
    return '<div style="display:flex;align-items:center;justify-content:space-between;gap:.5rem;min-width:0">'
      +'<span style="display:flex;align-items:center;gap:.35rem;min-width:0;color:#cbd5e1">'
      +'<span style="width:.45rem;height:.45rem;border-radius:999px;background:'+(colorMap[label]||"#64748b")+';flex-shrink:0"></span>'
      +'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(label)+'</span></span>'
      +'<span style="color:#94a3b8;font-weight:600;white-space:nowrap">'+esc(text)+'</span></div>';
  }).join("");
  if(entries.length>5){
    legend+='<div style="font-size:.65rem;color:#64748b;text-align:right">+'+(entries.length-5)+' more</div>';
  }
  return '<div style="display:flex;align-items:flex-end;justify-content:space-between;gap:.75rem;margin-bottom:.5rem">'
    +'<div style="font-size:1.65rem;line-height:1;font-weight:700;color:#e2e8f0">'+total+'</div>'
    +'<div style="font-size:.65rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">total</div>'
    +'</div>'
    +'<div style="height:.55rem;background:#0f172a;border-radius:999px;overflow:hidden;display:flex;margin-bottom:.55rem">'+segments+'</div>'
    +'<div style="display:grid;gap:.28rem;font-size:.68rem">'+legend+'</div>';
}

function compactMiniStackedChartHtml(counts,colorMap){
  var entries=Object.entries(counts||{}).filter(function(kv){return Number(kv[1])>0;})
    .sort(function(a,b){return b[1]-a[1];});
  if(!entries.length){return '<div class="text-xs py-2 text-center" style="color:#475569">No data</div>';}
  var total=entries.reduce(function(sum,kv){return sum+Number(kv[1]||0);},0);
  var segments=entries.map(function(kv){
    var label=kv[0],count=Number(kv[1]||0);
    var pct=total?Math.max(4,Math.round(count/total*100)):0;
    return '<div title="'+esc(label)+': '+count+'" style="height:100%;width:'+pct+'%;background:'+(colorMap[label]||"#64748b")+'"></div>';
  }).join("");
  var legend=entries.slice(0,3).map(function(kv){
    var label=kv[0],count=Number(kv[1]||0);
    return '<span style="display:inline-flex;align-items:center;gap:.25rem;margin-right:.5rem;color:#94a3b8;white-space:nowrap">'
      +'<span style="width:.4rem;height:.4rem;border-radius:999px;background:'+(colorMap[label]||"#64748b")+'"></span>'
      +esc(label)+' <b style="color:#cbd5e1">'+count+'</b></span>';
  }).join("");
  return '<div style="height:.45rem;background:#0f172a;border-radius:999px;overflow:hidden;display:flex;margin-bottom:.35rem">'+segments+'</div>'
    +'<div style="font-size:.65rem;line-height:1.5;overflow:hidden;text-overflow:ellipsis">'+legend+'</div>';
}

function renderCompactStackedChart(containerId,counts,colorMap,labelFormatter){
  var el=$(containerId);if(!el)return;
  el.innerHTML=compactStackedChartHtml(counts,colorMap,labelFormatter);
}

function renderBarChart(containerId,counts,colorMap){
  var el=$(containerId);if(!el)return;
  var entries=Object.entries(counts).sort(function(a,b){return b[1]-a[1];});
  if(!entries.length){el.innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">No data</div>';return;}
  var max=Math.max.apply(null,entries.map(function(e){return e[1];}));
  el.innerHTML=entries.map(function(kv){
    var label=kv[0],count=kv[1];
    var pct=max>0?Math.round(count/max*100):0;
    var color=colorMap[label]||"#64748b";
    return '<div style="margin-bottom:.625rem">'
      +'<div style="display:flex;justify-content:space-between;font-size:.75rem;margin-bottom:.25rem">'
      +'<span style="color:#cbd5e1">'+esc(label)+'</span>'
      +'<span style="color:#94a3b8;font-weight:600">'+count+'</span>'
      +'</div>'
      +'<div style="height:7px;background:#0f172a;border-radius:9999px;overflow:hidden">'
      +'<div style="height:7px;background:'+color+';border-radius:9999px;width:'+pct+'%;transition:width 700ms ease"></div>'
      +'</div></div>';
  }).join("");
}

function renderDashActivity(events){
  var el=$("dash-activity");if(!el)return;
  if(!events.length){el.innerHTML='<div class="text-xs py-4 text-center" style="color:#475569">No recent activity</div>';return;}
  var actionColor={
    CREATE:"#60a5fa",UPDATE:"#fbbf24",DELETE:"#f87171",
    ENABLE_PROTECTION:"#4ade80",DISABLE_PROTECTION:"#fb923c",
    CREATE_USER:"#60a5fa",DELETE_USER:"#f87171",CHANGE_PASSWORD:"#fbbf24",UPDATE_ROLE:"#a78bfa"
  };
  el.innerHTML=events.map(function(ev){
    var ok=ev.status==="SUCCESS";
    var ac=actionColor[ev.action]||"#94a3b8";
    var ts=ev.ts?new Date(ev.ts).toLocaleTimeString("vi-VN",{hour:"2-digit",minute:"2-digit",second:"2-digit"}):"";
    return '<div style="display:flex;align-items:center;gap:.75rem;padding:.5rem 0;border-bottom:1px solid #1e293b">'
      +'<span style="font-size:.7rem;color:#475569;min-width:4.5rem;white-space:nowrap;font-family:monospace">'+esc(ts)+'</span>'
      +'<span style="font-size:.7rem;font-weight:700;color:'+ac+';min-width:6rem;white-space:nowrap">'+esc(ev.action||"")+'</span>'
      +'<span style="font-size:.75rem;color:#94a3b8;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(ev.policy||"")+(ev.namespace&&ev.namespace!=="cluster"?'<span style="color:#475569"> / '+esc(ev.namespace)+'</span>':"")+'</span>'
      +'<span style="font-size:.7rem;color:#475569;white-space:nowrap">'+esc(ev.user||"")+'</span>'
      +'<span class="badge '+(ok?"badge-green":"badge-red")+'" style="font-size:.6rem;flex-shrink:0">'+(ok?"OK":"FAIL")+'</span>'
      +'</div>';
  }).join("")+'<div style="font-size:.7rem;color:#475569;padding-top:.5rem;text-align:right"><a href="#" onclick="switchTab(\'logs\');return false" style="color:#3b82f6;text-decoration:none">View all logs →</a></div>';
}

// ── Agent Health ──
async function loadAgentHealth(){
  var el=$("dash-agents");var sum=$("dash-agents-summary");
  if(!el)return;
  try{
    var r=await api("/api/agent-health"),d=await r.json();
    if(!r.ok){el.innerHTML='<div class="text-xs" style="color:#f87171">'+esc(d.error||"Error")+'</div>';return;}
    var agents=d.agents||[];
    if(sum)sum.innerHTML=(d.unhealthy>0
      ?'<span style="color:#f87171">'+d.unhealthy+' DOWN</span> / '+d.total+' total'
      :'<span style="color:#4ade80">All '+d.total+' healthy</span>');
    if(!agents.length){el.innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">No agents found in varmor namespace.</div>';return;}
    el.innerHTML='<div class="overflow-x-auto"><table class="w-full text-xs"><thead><tr style="border-bottom:1px solid #1e293b">'
      +'<th class="th" style="font-size:.7rem">Pod</th><th class="th" style="font-size:.7rem">Node</th>'
      +'<th class="th" style="font-size:.7rem">Status</th><th class="th" style="font-size:.7rem">Restarts</th>'
      +'</tr></thead><tbody>'
      +agents.map(function(a){
        var ok=a.ready&&a.phase==="Running";
        var badge=ok
          ?'<span class="badge badge-green" style="font-size:.6rem">Ready</span>'
          :'<span class="badge badge-red" style="font-size:.6rem">'+esc(a.phase)+'</span>';
        var nodeWarning=!ok?'<span title="Node unprotected!" style="color:#f87171;margin-left:.25rem">&#9888;</span>':'';
        return '<tr style="border-bottom:1px solid #0f172a">'
          +'<td class="td" style="font-family:monospace;font-size:.7rem;color:#94a3b8">'+esc(a.name)+'</td>'
          +'<td class="td" style="font-size:.7rem;color:#cbd5e1">'+esc(a.node)+nodeWarning+'</td>'
          +'<td class="td">'+badge+'</td>'
          +'<td class="td" style="font-size:.7rem;color:'+(a.restarts>0?"#fb923c":"#64748b")+'">'+a.restarts+'</td>'
          +'</tr>';
      }).join("")
      +'</tbody></table></div>';
  }catch(e){if(el)el.innerHTML='<div class="text-xs" style="color:#f87171">'+esc(e.message)+'</div>';}
}

// ── Enforcement Events ──
async function loadEnforcementEvents(){
  var el=$("dash-enforcement");if(!el)return;
  el.innerHTML='<div class="text-xs py-3 text-center" style="color:#475569">Loading…</div>';
  var f=($("enf-filter")||{}).value||"all";
  try{
    var r=await api("/api/enforcement-events?limit=50&enforcer="+encodeURIComponent(f)),d=await r.json();
    if(!r.ok){el.innerHTML='<div class="text-xs" style="color:#f87171">'+esc(d.error||"Error")+'</div>';return;}
    if(d.warn&&!d.events.length){
      el.innerHTML='<div class="text-xs py-3" style="color:#94a3b8">'+esc(d.warn)+'</div>';return;
    }
    var evs=d.events||[];
    if(!evs.length){el.innerHTML='<div class="text-xs py-3 text-center" style="color:#4ade80">No enforcement events found (all quiet).</div>';return;}
    el.innerHTML='<div style="font-size:.7rem;color:#64748b;margin-bottom:.5rem">'+evs.length+' events (most recent first)</div>'
      +'<div style="max-height:14rem;overflow-y:auto">'
      +evs.map(function(ev){
        var isSeccomp=ev.type==="seccomp";
        var isBpf=ev.type==="bpf";
        var typeColor=isSeccomp?"#f472b6":isBpf?"#34d399":"#60a5fa";
        var typeLabel=isSeccomp?"SECCOMP":isBpf?"BPF":"APPARMOR";
        var isBlocked=isSeccomp
          ?(ev.action==="SCMP_ACT_ERRNO"||ev.action==="SCMP_ACT_KILL"||ev.action==="SCMP_ACT_KILL_THREAD")
          :isBpf
            ?(ev.action==="DENIED")
            :(ev.action==="DENIED"||ev.action==="AUDIT");
        var actionColor=isBlocked?"#f87171":(ev.action==="SCMP_ACT_LOG"||ev.action==="AUDIT|ALLOWED"?"#fbbf24":"#64748b");
        var actionLabel=isBlocked?"DENIED":(ev.action==="SCMP_ACT_LOG"||ev.action==="AUDIT|ALLOWED"?"LOGGED":"ALLOWED");
        var detail=isSeccomp
          ?('<span style="color:#cbd5e1">'+esc(ev.syscall||"")+'</span>'
            +' <span style="color:'+actionColor+';font-weight:600">'+actionLabel+'</span>')
          :isBpf
            ?('<span style="color:#94a3b8">'+esc(ev.operation||ev.capability||"")+'</span>'
              +' <span style="color:'+actionColor+';font-weight:600">'+actionLabel+'</span>'
              +(ev.name||ev.ip?' <span style="color:#64748b">'+esc(ev.name||ev.ip||"")+'</span>':''))
            :('<span style="color:#94a3b8">'+esc(ev.operation||"")+'</span>'
              +' <span style="color:'+actionColor+';font-weight:600">'+actionLabel+'</span>'
              +(ev.name?' <span style="color:#64748b">'+esc(ev.name)+'</span>':''));
        var ts=ev.ts?new Date(ev.ts).toLocaleTimeString("vi-VN",{hour:"2-digit",minute:"2-digit",second:"2-digit"}):"";
        return '<div style="display:flex;align-items:center;gap:.5rem;padding:.3rem 0;border-bottom:1px solid #0f172a">'
          +'<span style="font-family:monospace;color:#475569;min-width:4rem;font-size:.65rem">'+esc(ts)+'</span>'
          +'<span style="font-weight:700;color:'+typeColor+';min-width:5.5rem;font-size:.65rem">'+typeLabel+'</span>'
          +'<span style="color:#94a3b8;min-width:5rem;font-size:.7rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(ev.comm||"")+'</span>'
          +'<span style="flex:1;font-size:.7rem">'+detail+'</span>'
          +'</div>';
      }).join("")
      +'</div>';
  }catch(e){if(el)el.innerHTML='<div class="text-xs" style="color:#f87171">'+esc(e.message)+'</div>';}
}

// ── Apply Model as Policy ──
async function applyModel(name,namespace){
  if(!canApplyModel()){alert("Insufficient permissions to apply behavior models.");return;}
  if(!confirm('Apply model "'+name+'" as DefenseInDepth policy?\nThis changes the originating BehaviorModeling policy to DefenseInDepth mode.'))return;
  try{
    var r=await api("/api/namespaces/"+encodeURIComponent(namespace)+"/models/"+encodeURIComponent(name)+"/apply",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({mode:"DefenseInDepth"})
    });
    var d=await r.json();
    if(!r.ok){alert("Error: "+(d.error||r.status));return;}
    alert('Policy "'+d.policy+'" updated: '+d.old_mode+' -> '+d.new_mode);
    loadProfileModels();
    loadPolicies();
  }catch(e){alert("Error: "+e.message);}
}

// ── Batch select / delete ──
function getCheckedPolicies(){
  return Array.from(document.querySelectorAll(".pol-chk:checked")).map(function(el){
    return{name:el.dataset.name,ns:el.dataset.ns,scope:el.dataset.scope||"namespace"};
  });
}
function updateBatchBar(){
  var items=getCheckedPolicies();
  var bar=$("batch-bar"),cnt=$("batch-count"),all=$("chk-all");
  if(!canDelete()){
    if(bar) hide("batch-bar");
    if(all){all.checked=false;all.indeterminate=false;all.disabled=true;}
    return;
  }
  if(all) all.disabled=false;
  if(items.length>0){show("batch-bar");cnt.textContent=items.length+" selected";}
  else{hide("batch-bar");}
  if(all){
    var total=document.querySelectorAll(".pol-chk").length;
    all.checked=total>0&&items.length===total;
    all.indeterminate=items.length>0&&items.length<total;
  }
}
function toggleSelectAll(){
  if(!canDelete()) return;
  var checked=$("chk-all").checked;
  document.querySelectorAll(".pol-chk").forEach(function(el){el.checked=checked;});
  updateBatchBar();
}
function clearSelection(){
  document.querySelectorAll(".pol-chk").forEach(function(el){el.checked=false;});
  if($("chk-all"))$("chk-all").checked=false;
  updateBatchBar();
}
function confirmBatchDelete(){
  if(!canDelete()){alert("Insufficient permissions to delete policies.");return;}
  var items=getCheckedPolicies();
  if(!items.length) return;
  if(!confirm("Delete "+items.length+" selected polic"+(items.length===1?"y":"ies")+"? This cannot be undone.")) return;
  doBatchDelete(items);
}
async function doBatchDelete(items){
  if(!canDelete()){alert("Insufficient permissions to delete policies.");return;}
  var errs=[];
  for(var i=0;i<items.length;i++){
    var p=items[i];
    try{
      var path=p.scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(p.name)
        :"/api/namespaces/"+p.ns+"/policies/"+encodeURIComponent(p.name);
      var res=await api(path,{method:"DELETE"});
      if(!res.ok){var d=await res.json();errs.push(p.name+": "+(d.error||res.status));}
    }catch(err){errs.push(p.name+": "+err.message);}
  }
  if(errs.length) alert("Some deletes failed:\n"+errs.join("\n"));
  setTimeout(loadAll,400);
}

// ── Export policy as YAML ──
async function exportPolicy(el){
  var name=el.dataset.name,namespace=el.dataset.ns,scope=el.dataset.scope||"namespace";
  try{
    var path=scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(name)
      :"/api/namespaces/"+namespace+"/policies/"+encodeURIComponent(name);
    var res=await api(path);
    if(!res.ok){var d=await res.json();alert("Export failed: "+(d.error||res.status));return;}
    var data=await res.json();
    var content=typeof jsyaml!=="undefined"?jsyaml.dump(data,{lineWidth:120}):JSON.stringify(data,null,2);
    var ext=typeof jsyaml!=="undefined"?".yaml":".json";
    var blob=new Blob([content],{type:"text/plain"});
    var a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download=name+ext;
    a.click();
    URL.revokeObjectURL(a.href);
  }catch(err){alert("Export error: "+err.message);}
}

// ── Audit Log ──
// ════════════════════════════════════════════
// LOGS TAB — unified Security Events + views
// ════════════════════════════════════════════

var _secEventsRaw=[];   // normalized, unfiltered security events
var _auditRaw=[];       // raw audit events
var _profilesRaw=[];    // raw armor profiles
var _secTimeRange="";   // "15m"|"1h"|"24h"|"7d"|""
var _autoRefreshActive=false;
var _autoRefreshTimer=null;
var _drawerEvent=null;  // currently shown event in drawer
