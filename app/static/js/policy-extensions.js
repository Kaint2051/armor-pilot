
// ── Attack Protection Groups (per-rule) ──
function addAttackGroup(rules, targets){
  var div=document.createElement("div");
  div.className="attack-group";
  div.style.cssText="background:#0f172a;border:1px solid #334155;border-radius:.5rem;padding:.625rem .75rem;display:grid;gap:.5rem;grid-template-columns:1fr 1fr auto";
  var rulesVal=Array.isArray(rules)?rules.join(", "):(rules||"");
  var targetsVal=Array.isArray(targets)?targets.join("\n"):(targets||"");
  div.innerHTML='<div><label style="font-size:.7rem;color:#64748b;display:block;margin-bottom:.25rem">Rules (comma-separated)</label>'
    +'<input type="text" class="form-input" value="'+esc(rulesVal)+'" placeholder="disable-shell, disable-wget" style="font-family:monospace;font-size:.78rem"/></div>'
    +'<div><label style="font-size:.7rem;color:#64748b;display:block;margin-bottom:.25rem">Restrict to executables (one per line)</label>'
    +'<textarea class="form-input" rows="2" placeholder="/usr/bin/python3&#10;/bin/bash" style="font-family:monospace;font-size:.78rem;resize:vertical">'+esc(targetsVal)+'</textarea></div>'
    +'<div style="display:flex;align-items:flex-end"><button type="button" class="btn btn-ghost btn-sm" style="color:#f87171" onclick="this.closest(\'.attack-group\').remove();_onFormChange()">&#10005;</button></div>';
  $("attack-groups").appendChild(div);
}

function collectAttackGroups(){
  var groups=[];
  document.querySelectorAll(".attack-group").forEach(function(div){
    var inputs=div.querySelectorAll("input,textarea");
    var rulesRaw=(inputs[0].value||"").split(",").map(function(r){return r.trim();}).filter(Boolean);
    var targetsRaw=(inputs[1].value||"").split("\n").map(function(t){return t.trim();}).filter(Boolean);
    if(rulesRaw.length) groups.push({rules:rulesRaw,targets:targetsRaw});
  });
  return groups;
}

// ── Container Unconfined Overrides ──
function addUnconfinedRow(containerName){
  var div=document.createElement("div");
  div.style.cssText="display:flex;gap:.5rem;align-items:center";
  div.innerHTML='<input type="text" class="form-input unconfined-container" value="'+esc(containerName||'')+'" placeholder="container-name" style="font-family:monospace;font-size:.85rem"/>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="color:#f87171;flex-shrink:0" onclick="this.parentElement.remove();_onFormChange()">&#10005;</button>';
  $("unconfined-rows").appendChild(div);
}

function collectUnconfinedContainers(){
  return Array.from(document.querySelectorAll(".unconfined-container")).map(function(i){return i.value.trim();}).filter(Boolean);
}

// ── ArmorProfile Status ──
// ── Profile Health ──
async function loadArmorProfiles(){
  setLoading("ap-status",true);hide("ap-status-empty");hide("ap-status-err");$("ap-status-body").innerHTML="";
  try{
    var r=await api("/api/namespaces/"+ns()+"/armor-profiles"),data=await r.json();
    setLoading("ap-status",false);
    if(!r.ok){showEl($("ap-status-err"),data.error||"Failed");return;}
    _profilesRaw=data.profiles||[];
    updateLogsSummary();
    renderArmorProfiles(_profilesRaw);
  }catch(err){setLoading("ap-status",false);showEl($("ap-status-err"),err.message);}
}

function renderArmorProfiles(profiles){
  var el=$("ap-status-body");
  if(!profiles.length){show("ap-status-empty");el.innerHTML="";return;}
  hide("ap-status-empty");
  el.innerHTML=profiles.map(function(p){
    var ready=p.ready;
    var bar='<div style="display:flex;align-items:center;gap:.5rem">'
      +'<div style="flex:1;height:6px;background:#0f172a;border-radius:9999px;overflow:hidden">'
      +'<div style="height:6px;background:'+(ready?"#4ade80":"#f87171")+';width:'+(p.desired>0?Math.round(p.current/p.desired*100):0)+'%"></div></div>'
      +'<span style="font-size:.7rem;color:#94a3b8;white-space:nowrap">'+p.current+"/"+p.desired+'</span></div>';
    var nodes=p.conditions.map(function(c){
      var ok=c.status==="True";
      return '<tr style="border-bottom:1px solid #0f172a">'
        +'<td class="td" style="font-size:.7rem;color:#94a3b8">'+esc(c.nodeName)+'</td>'
        +'<td class="td"><span class="badge '+(ok?"badge-green":"badge-red")+'" style="font-size:.6rem">'+(ok?"Loaded":"Error")+'</span></td>'
        +'<td class="td" style="font-size:.7rem;color:#64748b;max-width:20rem;overflow:hidden;text-overflow:ellipsis">'+esc(c.reason||c.message||"")+'</td></tr>';
    }).join("");
    return '<div class="mb-4 p-3 rounded-xl" style="background:#0f172a;border:1px solid #1e293b">'
      +'<div class="flex items-center justify-between mb-2">'
      +'<span style="font-family:monospace;color:#93c5fd;font-size:.85rem">'+esc(p.name)+'</span>'
      +'<div class="flex items-center gap-2">'
      +'<span class="badge badge-blue" style="font-size:.65rem">'+esc(p.enforcer||"")+'</span>'
      +'<span class="badge badge-gray" style="font-size:.65rem">'+esc(p.mode||"")+'</span>'
      +'<span class="badge '+(ready?"badge-green":"badge-amber")+'" style="font-size:.65rem">'+(ready?"Ready":"Not Ready")+'</span></div></div>'
      +bar
      +(nodes?'<table class="w-full text-xs mt-2"><thead><tr style="border-bottom:1px solid #1e293b"><th class="th" style="font-size:.65rem">Node</th><th class="th" style="font-size:.65rem">Status</th><th class="th" style="font-size:.65rem">Reason</th></tr></thead><tbody>'+nodes+'</tbody></table>':"")
      +'</div>';
  }).join("");
}

// Legacy stubs — kept so old inline Refresh calls don't break
function loadAaEvents(){loadSecurityEvents();}
function loadViolationEvents(){loadSecurityEvents();}

// ── YAML Import ──
function openImportModal(){
  if(!canImport()){alert("Insufficient permissions to import policies.");return;}
  $("ta-import-yaml").value="";hideEl($("import-msg"));show("modal-import");
}
function closeImportModal(){hide("modal-import");}
$("modal-import").addEventListener("click",function(e){if(e.target===$("modal-import"))closeImportModal();});

async function doImportPolicy(){
  var msgEl=$("import-msg");hideEl(msgEl);
  var yamlText=$("ta-import-yaml").value.trim();
  if(!yamlText){showMsg(msgEl,"error","Paste a YAML policy first.");return;}
  var btn=$("btn-import-confirm");btn.disabled=true;
  try{
    var res=await api("/api/policies/import",{method:"POST",body:JSON.stringify({yaml:yamlText})});
    var d=await res.json();
    if(!res.ok){showMsg(msgEl,"error",d.error||"Import failed");btn.disabled=false;return;}
    showMsg(msgEl,"success","Policy '"+d.name+"' imported successfully ("+d.scope+").");
    setTimeout(function(){closeImportModal();loadAll();},1400);
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
}

// ── Policy Backup / Restore ──
function openBackupModal(){
  if(!canExport()){alert("Insufficient permissions to export policies.");return;}
  hideEl($("backup-msg"));show("modal-backup");
}
function closeBackupModal(){hide("modal-backup");}
$("modal-backup").addEventListener("click",function(e){if(e.target===$("modal-backup"))closeBackupModal();});

async function downloadPolicyBackup(){
  var msgEl=$("backup-msg");hideEl(msgEl);
  var includeNs=$("chk-backup-ns").checked;
  var includeCluster=$("chk-backup-cluster").checked;
  if(!includeNs&&!includeCluster){showMsg(msgEl,"error","Select at least one backup scope.");return;}
  var btn=$("btn-backup-download");btn.disabled=true;
  try{
    var qs=new URLSearchParams({namespace:ns(),include_namespace:includeNs?"1":"0",include_cluster:includeCluster?"1":"0"});
    var res=await api("/api/policies/backup?"+qs.toString());
    var data=await res.json();
    if(!res.ok){showMsg(msgEl,"error",data.error||"Backup failed");return;}
    var blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
    var a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download="varmor-policy-backup-"+new Date().toISOString().replace(/[:.]/g,"-")+".json";
    a.click();
    URL.revokeObjectURL(a.href);
    showMsg(msgEl,"success","Downloaded "+(data.total||0)+" policy item(s).");
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
}

function openRestoreModal(){
  if(!canImport()){alert("Insufficient permissions to restore policies.");return;}
  $("ta-restore-json").value="";
  $("inp-restore-file").value="";
  $("restore-summary").textContent="No backup loaded.";
  $("restore-preview-body").innerHTML='<tr><td colspan="6" class="td text-center" style="color:#64748b">Run Preview first.</td></tr>';
  hideEl($("restore-msg"));
  if($("btn-restore-direct")){$("btn-restore-direct").classList.toggle("hidden",!isAdmin());$("btn-restore-direct").disabled=false;}
  if($("btn-restore-submit")){$("btn-restore-submit").classList.toggle("hidden",!canSubmit());$("btn-restore-submit").disabled=false;}
  show("modal-restore");
}
function closeRestoreModal(){hide("modal-restore");}
$("modal-restore").addEventListener("click",function(e){if(e.target===$("modal-restore"))closeRestoreModal();});

function loadRestoreFile(input){
  var file=input.files&&input.files[0];
  if(!file) return;
  var reader=new FileReader();
  reader.onload=function(){ $("ta-restore-json").value=String(reader.result||""); };
  reader.readAsText(file);
}

function readRestoreBackup(){
  var raw=($("ta-restore-json").value||"").trim();
  if(!raw) throw new Error("Paste or choose a backup JSON file first.");
  try{return JSON.parse(raw);}catch(e){throw new Error("Backup JSON parse error: "+e.message);}
}

function renderRestorePreview(items){
  var body=$("restore-preview-body");
  if(!items.length){
    body.innerHTML='<tr><td colspan="6" class="td text-center" style="color:#64748b">No policy items found.</td></tr>';
    return;
  }
  body.innerHTML=items.map(function(it){
    var conflict=it.error?'<span class="badge badge-red">invalid</span>':(it.exists?'<span class="badge badge-amber">exists</span>':'<span class="badge badge-green">new</span>');
    var actionColor=it.action==="overwrite"?"badge-amber":it.action==="create"?"badge-green":it.action==="skip"?"badge-gray":it.action==="submitted"?"badge-blue":"badge-red";
    var nsLabel=it.scope==="cluster"?"cluster":(it.namespace||"default");
    return '<tr style="border-bottom:1px solid #1e293b">'
      +'<td class="td"><div style="font-family:monospace;color:#93c5fd">'+esc(it.name||"")+'</div><div style="font-size:.68rem;color:#64748b">'+esc(it.kind||"")+'</div></td>'
      +'<td class="td">'+esc(nsLabel)+'</td>'
      +'<td class="td">'+esc(it.mode||"")+'</td>'
      +'<td class="td">'+esc(it.enforcer||"")+'</td>'
      +'<td class="td">'+conflict+(it.error?'<div style="font-size:.68rem;color:#fca5a5;margin-top:.25rem">'+esc(it.error)+'</div>':"")+'</td>'
      +'<td class="td"><span class="badge '+actionColor+'">'+esc(it.action||it.status||"")+'</span></td>'
      +'</tr>';
  }).join("");
}

async function previewPolicyRestore(){
  var msgEl=$("restore-msg");hideEl(msgEl);
  try{
    var backup=readRestoreBackup();
    var conflict=$("sel-restore-conflict").value;
    var res=await api("/api/policies/restore/preview",{method:"POST",body:JSON.stringify({backup:backup,conflict_action:conflict})});
    var data=await res.json();
    if(!res.ok){showMsg(msgEl,"error",data.error||"Preview failed");return null;}
    renderRestorePreview(data.items||[]);
    $("restore-summary").textContent=(data.valid||0)+" valid / "+(data.errors||0)+" error(s), total "+(data.total||0)+" item(s).";
    return data;
  }catch(err){showMsg(msgEl,"error",err.message);return null;}
}

async function restorePoliciesDirect(){
  if(!isAdmin()||!canImport()){alert("Insufficient permissions to restore directly.");return;}
  if(!confirm("Restore policies directly to the cluster?")) return;
  var msgEl=$("restore-msg");hideEl(msgEl);
  var btn=$("btn-restore-direct");btn.disabled=true;
  try{
    var backup=readRestoreBackup();
    var conflict=$("sel-restore-conflict").value;
    var res=await api("/api/policies/restore",{method:"POST",body:JSON.stringify({backup:backup,conflict_action:conflict})});
    var data=await res.json();
    if(!res.ok&&!(data.results)){showMsg(msgEl,"error",data.error||"Restore failed");return;}
    showMsg(msgEl,data.failures?"error":"success","Applied "+(data.applied||0)+" policy item(s), failures "+(data.failures||0)+".");
    renderRestorePreview((data.results||[]).map(function(r){return {name:r.name,namespace:r.namespace,scope:r.scope||"",kind:r.kind||"",mode:r.mode||"",enforcer:r.enforcer||"",exists:false,action:r.status,error:r.error||"",valid:r.status!=="error"};}));
    loadPolicies();
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
}

async function submitPolicyRestore(){
  if(!canSubmit()||!canImport()){alert("Insufficient permissions to submit restore for review.");return;}
  if(!confirm("Submit these backup policies to the review queue?")) return;
  var msgEl=$("restore-msg");hideEl(msgEl);
  var btn=$("btn-restore-submit");btn.disabled=true;
  try{
    var backup=readRestoreBackup();
    var res=await api("/api/policies/restore/submit",{method:"POST",body:JSON.stringify({backup:backup})});
    var data=await res.json();
    if(!res.ok&&!(data.results)){showMsg(msgEl,"error",data.error||"Submit failed");return;}
    showMsg(msgEl,data.failures?"error":"success","Submitted "+(data.submitted||0)+" policy item(s), failures "+(data.failures||0)+".");
    loadPolicyQueue();
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
}

// ── Secret Picker ──
function openSecretPickerModal(){
  show("modal-secret-picker");
  loadSecretsForPicker();
}
function closeSecretPickerModal(){hide("modal-secret-picker");}
$("modal-secret-picker").addEventListener("click",function(e){if(e.target===$("modal-secret-picker"))closeSecretPickerModal();});

async function loadSecretsForPicker(){
  setLoading("secret-picker",true);hide("secret-picker-err");$("secret-picker-list").innerHTML="";
  try{
    var r=await api("/api/namespaces/"+ns()+"/secrets"),d=await r.json();
    setLoading("secret-picker",false);
    if(!r.ok){showEl($("secret-picker-err"),d.error||"Failed");return;}
    var secrets=d.secrets||[];
    if(!secrets.length){$("secret-picker-list").innerHTML='<div class="text-xs py-3" style="color:#475569">No Opaque secrets found in namespace.</div>';return;}
    $("secret-picker-list").innerHTML=secrets.map(function(s){
      var keys=s.keys.map(function(k){
        return '<button type="button" onclick="insertSecretRef(\''+esc(s.name)+'\',\''+esc(k)+'\')" class="btn btn-ghost btn-sm" style="margin:.15rem;font-family:monospace;font-size:.75rem">'+esc(k)+'</button>';
      }).join("");
      return '<div class="p-2 rounded" style="background:#0f172a;border:1px solid #1e293b;margin-bottom:.5rem">'
        +'<div style="font-family:monospace;font-size:.8rem;color:#93c5fd;margin-bottom:.25rem">'+esc(s.name)+'</div>'
        +'<div>'+keys+'</div></div>';
    }).join("");
  }catch(err){setLoading("secret-picker",false);showEl($("secret-picker-err"),err.message);}
}

function openCreateSecretModal(){hide("modal-secret-picker");show("modal-create-secret");}
function closeCreateSecretModal(){hide("modal-create-secret");show("modal-secret-picker");}
$("modal-create-secret").addEventListener("click",function(e){if(e.target===$("modal-create-secret"))closeCreateSecretModal();});

async function doCreateSecret(){
  var msgEl=$("create-secret-msg");hideEl(msgEl);
  var name=$("inp-secret-name").value.trim();
  if(!name){showMsg(msgEl,"error","Secret name is required.");return;}
  var dataRaw=$("ta-secret-data").value.trim();
  if(!dataRaw){showMsg(msgEl,"error","At least one KEY=value pair is required.");return;}
  var data={};
  dataRaw.split("\n").forEach(function(line){
    var idx=line.indexOf("=");
    if(idx>0){var k=line.substring(0,idx).trim();var v=line.substring(idx+1);if(k) data[k]=v;}
  });
  if(!Object.keys(data).length){showMsg(msgEl,"error","No valid KEY=value pairs found.");return;}
  try{
    var r=await api("/api/namespaces/"+ns()+"/secrets",{method:"POST",body:JSON.stringify({name:name,data:data})});
    var d=await r.json();
    if(!r.ok){showMsg(msgEl,"error",d.error||"Failed");return;}
    showMsg(msgEl,"success","Secret '"+d.name+"' created.");
    $("inp-secret-name").value="";$("ta-secret-data").value="";
    setTimeout(function(){closeCreateSecretModal();loadSecretsForPicker();},900);
  }catch(err){showMsg(msgEl,"error",err.message);}
}

// ── Policy Advisor ──
async function openAdvisorModal(modelName,namespace){
  $("advisor-model-name").textContent=namespace+" / "+modelName;
  show("advisor-loading");hide("advisor-err");hide("advisor-body");$("advisor-body").innerHTML="";
  show("modal-advisor");
  try{
    var r=await api("/api/namespaces/"+namespace+"/models/"+encodeURIComponent(modelName)+"/advise");
    var d=await r.json();
    hide("advisor-loading");
    if(!r.ok){showEl($("advisor-err"),d.error||"Failed");return;}
    renderAdvisorResult(d);
    show("advisor-body");
  }catch(err){hide("advisor-loading");showEl($("advisor-err"),err.message);}
}
function closeAdvisorModal(){hide("modal-advisor");}
$("modal-advisor").addEventListener("click",function(e){if(e.target===$("modal-advisor"))closeAdvisorModal();});

function renderAdvisorResult(d){
  var el=$("advisor-body");
  var suggs=d.suggestions||[];
  if(!suggs.length){
    el.innerHTML='<div class="p-4 text-sm" style="color:#64748b">No rule suggestions found. The behavior model may not contain enough data, or the workload behavior is already minimal.</div>';
    return;
  }
  var catColors={hardening:"badge-purple",attack:"badge-red",vuln:"badge-green"};
  var byCategory={};
  suggs.forEach(function(s){(byCategory[s.category]=byCategory[s.category]||[]).push(s);});
  el.innerHTML='<div class="p-3">'
    +'<p class="text-sm mb-4" style="color:#94a3b8">Found <b style="color:#f1f5f9">'+suggs.length+'</b> suggested rules based on observed behavior. Click a rule to copy its ID.</p>'
    +Object.entries(byCategory).map(function(kv){
      var cat=kv[0],items=kv[1];
      var catLabel=cat.charAt(0).toUpperCase()+cat.slice(1);
      return '<div class="mb-4">'
        +'<h4 class="text-xs font-semibold uppercase tracking-wider mb-2" style="color:#64748b">'+esc(catLabel)+' Rules ('+items.length+')</h4>'
        +items.map(function(s){
          return '<div class="mb-2 p-2 rounded" style="background:#0f172a;border:1px solid #1e293b;display:flex;align-items:flex-start;gap:.75rem">'
            +'<button onclick="navigator.clipboard&&navigator.clipboard.writeText(\''+esc(s.rule)+'\');this.textContent=\'✓ Copied!\';var self=this;setTimeout(function(){self.textContent=\''+esc(s.rule)+'\';},1500)" class="btn btn-ghost btn-sm" style="font-family:monospace;font-size:.72rem;flex-shrink:0;min-width:0">'+esc(s.rule)+'</button>'
            +'<div style="flex:1;min-width:0"><p class="text-xs" style="color:#94a3b8">'+esc(s.reason)+'</p></div>'
            +'<span class="badge '+(catColors[s.category]||"badge-gray")+'" style="font-size:.6rem;flex-shrink:0">'+esc(cat)+'</span>'
            +'</div>';
        }).join("")
        +'</div>';
    }).join("")
    +'</div>';
}

// ── Behavior Model Structured View ──
var _modelViewMode="structured";
function toggleModelView(){
  if(_modelViewMode==="structured"){
    _modelViewMode="raw";
    $("btn-model-view-toggle").textContent="&#128203; Structured View";
    hide("model-detail-structured");show("model-detail-body");
  }else{
    _modelViewMode="structured";
    $("btn-model-view-toggle").textContent="&#128196; Raw YAML";
    show("model-detail-structured");hide("model-detail-body");
  }
}

function renderModelStructured(data){
  var el=$("model-detail-structured");
  var d=data.data||{};
  var dynResult=d.dynamicResult||{};
  var aa=dynResult.appArmor||{};
  var bpf=dynResult.bpf||{};
  var sc=dynResult.seccomp||{};

  function section(title,color,items,cols,rowFn){
    if(!items||!items.length) return "";
    return '<div class="mb-4"><div class="text-xs font-semibold uppercase tracking-wider mb-2" style="color:'+color+'">'+esc(title)+' ('+items.length+')</div>'
      +'<div class="overflow-x-auto"><table class="w-full" style="font-size:.72rem">'
      +'<thead><tr style="border-bottom:1px solid #1e293b">'+cols.map(function(c){return '<th class="th" style="font-size:.65rem">'+esc(c)+'</th>';}).join("")+'</tr></thead>'
      +'<tbody>'+items.map(rowFn).join("")+'</tbody></table></div></div>';
  }

  var html='<div class="p-3 space-y-3">';
  // AppArmor files
  html+=section("Files Accessed (AppArmor)","#60a5fa",aa.files||[],
    ["Path","Permissions","Owner"],function(f){return '<tr style="border-bottom:1px solid #0f172a">'
      +'<td class="td" style="font-family:monospace;color:#93c5fd">'+esc(f.path||f)+'</td>'
      +'<td class="td" style="color:#94a3b8">'+esc(f.permissions||"")+'</td>'
      +'<td class="td" style="color:#64748b">'+esc(f.owner||"")+'</td></tr>';});
  // AppArmor executions
  html+=section("Processes Executed (AppArmor)","#34d399",aa.executions||[],
    ["Path","Capabilities"],function(e){var p=typeof e==="string"?e:(e.path||"");return '<tr style="border-bottom:1px solid #0f172a">'
      +'<td class="td" style="font-family:monospace;color:#4ade80">'+esc(p)+'</td>'
      +'<td class="td" style="color:#64748b">'+esc(e.capabilities||"")+'</td></tr>';});
  // AppArmor capabilities
  html+=section("Capabilities Used (AppArmor)","#a78bfa",aa.capabilities||[],
    ["Capability"],function(c){return '<tr style="border-bottom:1px solid #0f172a">'
      +'<td class="td" style="font-family:monospace;color:#c4b5fd">'+esc(c.capability||c)+'</td></tr>';});
  // AppArmor network
  html+=section("Network Connections (AppArmor)","#fb923c",aa.networks||[],
    ["Remote","Protocol","Flags"],function(n){return '<tr style="border-bottom:1px solid #0f172a">'
      +'<td class="td" style="font-family:monospace;color:#fdba74">'+esc(n.remoteAddr||n.addr||"")+'</td>'
      +'<td class="td" style="color:#94a3b8">'+esc(n.protocol||"")+'</td>'
      +'<td class="td" style="color:#64748b">'+esc(n.flags||"")+'</td></tr>';});
  // BPF files
  html+=section("Files (BPF)","#60a5fa",bpf.files||[],
    ["Pattern","Permissions","Qualifier"],function(f){return '<tr style="border-bottom:1px solid #0f172a">'
      +'<td class="td" style="font-family:monospace;color:#93c5fd">'+esc(f.pattern||f)+'</td>'
      +'<td class="td" style="color:#94a3b8">'+esc((f.permissions||[]).join(", "))+'</td>'
      +'<td class="td" style="color:#64748b">'+esc((f.qualifiers||[]).join(", "))+'</td></tr>';});
  // Seccomp syscalls
  var syscalls=sc.syscalls||[];
  if(syscalls.length){
    html+='<div class="mb-4"><div class="text-xs font-semibold uppercase tracking-wider mb-2" style="color:#f472b6">Syscalls ('+syscalls.length+')</div>'
      +'<div style="display:flex;flex-wrap:wrap;gap:.25rem">'
      +syscalls.map(function(s){return '<code style="background:#0f172a;border:1px solid #1e293b;border-radius:.25rem;padding:.1rem .35rem;font-size:.68rem;color:#f9a8d4">'+esc(typeof s==="string"?s:(s.name||s))+'</code>';}).join("")
      +'</div></div>';
  }
  if(html==='<div class="p-3 space-y-3">') html+='<div class="py-6 text-sm text-center" style="color:#475569">No behavior data recorded yet.</div>';
  html+='</div>';
  el.innerHTML=html;
}

// ── Override openModelModal to use structured view ──
async function openModelModal(el){
  var name=el.dataset.name,namespace=el.dataset.ns;
  $("model-detail-name").textContent=namespace+" / "+name;
  show("model-detail-loading");hide("model-detail-err");hide("model-detail-body");hide("model-detail-structured");
  $("model-detail-body").textContent="";$("model-detail-structured").innerHTML="";
  _modelViewMode="structured";
  $("btn-model-view-toggle").textContent="&#128196; Raw YAML";
  show("modal-model");
  try{
    var res=await api("/api/namespaces/"+namespace+"/profile-models/"+encodeURIComponent(name));
    var data=await res.json();
    hide("model-detail-loading");
    if(!res.ok){showEl($("model-detail-err"),data.error||"Failed.");return;}
    $("model-detail-body").textContent=JSON.stringify(data,null,2);
    renderModelStructured(data);
    show("model-detail-structured");
  }catch(err){hide("model-detail-loading");showEl($("model-detail-err"),err.message);}
}

// ── Validate Policy ──
async function doValidatePolicy(){
  var ind=$("validate-indicator");
  var hint=$("validate-hint");
  ind.textContent="⟳ Validating…";ind.style.color="#60a5fa";
  try{
    var payload=buildPolicyPayload();
    if(!payload){ind.textContent="✗ Fill required fields (name, target, enforcer)";ind.style.color="#f87171";return;}
    var res=await api("/api/policies/validate",{method:"POST",body:JSON.stringify(payload)});
    var d=await res.json();
    if(d.ok){
      _validatedOk=true;
      ind.textContent="✓ Valid";ind.style.color="#4ade80";
      var btnSubmit=$("btn-submit-review"),btnApply=$("btn-apply-direct");
      if(btnSubmit&&canSubmit()) btnSubmit.disabled=false;
      if(btnApply&&isAdmin()) btnApply.disabled=false;
      if(hint) hint.style.display="none";
    }else{
      _validatedOk=false;
      ind.textContent="✗ "+esc(d.error||"Validation failed");ind.style.color="#f87171";
      var btnSubmit=$("btn-submit-review"),btnApply=$("btn-apply-direct");
      if(btnSubmit) btnSubmit.disabled=true;
      if(btnApply) btnApply.disabled=true;
    }
  }catch(e){ind.textContent="✗ "+esc(e.message);ind.style.color="#f87171";}
}

// Build payload from current form state (shared by validate/submit/apply)
function buildPolicyPayload(){
  var name=($("inp-pname")||{value:""}).value.trim();
  if(!name) return null;
  var scope=document.querySelector('input[name="scope"]:checked');
  if(!scope) return null;
  var kind=$("sel-kind").value;
  var mode=$("sel-mode").value;
  var namespace=ns();
  var tgtMode=document.querySelector('input[name="tgt-mode"]:checked');
  var targetDeployment="",targetSelector=null;
  if(tgtMode&&tgtMode.value==="selector"){
    var lines=($("ta-selector").value||"").split("\n").filter(Boolean);
    var ml={};
    lines.forEach(function(l){var p=l.split("=");if(p.length===2)ml[p[0].trim()]=p[1].trim();});
    targetSelector={};
    if(Object.keys(ml).length) targetSelector.matchLabels=ml;
    var exprRaw=($("ta-selector-expr").value||"").trim();
    if(exprRaw){try{targetSelector.matchExpressions=JSON.parse(exprRaw);}catch(e){throw new Error("Selector matchExpressions: invalid JSON — "+e.message);}}
    if(!targetSelector.matchLabels&&!targetSelector.matchExpressions) return null;
  }else{
    targetDeployment=($("sel-target")||{value:""}).value;
    if(!targetDeployment) return null;
  }
  var enforcers=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  // EnhanceProtect requires at least one enforcer; other modes still need one for the CRD
  if(!enforcers.length) return null;
  var rules=Array.from(document.querySelectorAll('input[name="rule"]:checked')).map(function(c){return c.value;});
  var caps=($("ta-dynamic-caps").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var banned=($("ta-banned").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var aaRaw=collectRawRuleInput("ta-apparmor-raw","AppArmor Raw Rules",$("create-msg"))||[];
  var atGroups=collectAttackGroups();
  var bpfFiles=collectBpfRules("bpf-files"),bpfProcs=collectBpfRules("bpf-procs"),bpfMounts=collectMountRules(),bpfPtrace=collectPtraceRule();
  var bpfNet=null;var bpfNetStr=($("ta-bpf-network").value||"").trim();
  if(bpfNetStr){try{bpfNet=JSON.parse(bpfNetStr);}catch(e){throw new Error("BPF network rules: invalid JSON — "+e.message);}}
  var scSysc=($("ta-seccomp").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var scAction=$("sel-seccomp-action").value;
  var scRaw=[];var scRawStr=($("ta-seccomp-raw").value||"").trim();
  if(scRawStr){try{scRaw=JSON.parse(scRawStr);}catch(e){throw new Error("Seccomp raw rules: invalid JSON — "+e.message);}}
  var durationMins=parseInt(($("inp-duration")||{value:"60"}).value)||60;
  var updateExisting=!!($("chk-update-existing")||{checked:false}).checked;
  var auditViol=!!($("chk-audit-viol")||{checked:false}).checked;
  var allowViol=!!($("chk-allow-viol")||{checked:false}).checked;
  var privileged=!!($("chk-privileged")||{checked:false}).checked;
  var containers=($("inp-containers").value||"").split(",").map(function(c){return c.trim();}).filter(Boolean);
  // DID fields
  var didAaType=(document.querySelector('input[name="did-aa-type"]:checked')||{value:""}).value;
  var didScType=(document.querySelector('input[name="did-sc-type"]:checked')||{value:""}).value;
  var didAaCustom=($("ta-did-aa-custom").value||"").trim();
  var didAaRaw=($("ta-did-aa-raw").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var didScCustom=($("ta-did-sc-custom").value||"").trim();
  var didScSysc=($("ta-did-sc-syscalls").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var didScRaw=[];var dsrStr=($("ta-did-sc-raw").value||"").trim();if(dsrStr){try{didScRaw=JSON.parse(dsrStr);}catch(e){throw new Error("DID Seccomp raw rules: invalid JSON — "+e.message);}}
  var didScAction=($("sel-did-sc-action")||{value:"SCMP_ACT_ERRNO"}).value;
  var didAllowViol=!!($("did-allow-viol")||{checked:false}).checked;
  var didNpEgress=null;var dneStr=($("ta-did-np-egress").value||"").trim();if(dneStr){try{didNpEgress=JSON.parse(dneStr);}catch(e){throw new Error("DID NetworkProxy egress: invalid JSON — "+e.message);}}
  var npMitmDomains=($("ta-np-mitm-domains").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  // NP builders: let errors propagate so callers (validate/submit) show them to user
  var npMitmMut=null;try{npMitmMut=collectNpHeaders();}catch(e){throw new Error("Header mutations: "+e.message);}
  var npEgress=null;try{npEgress=collectNpEgress();}catch(e){throw new Error("NetworkProxy egress: "+e.message);}
  var npProxyUid=$("inp-np-proxy-uid")&&$("inp-np-proxy-uid").value?parseInt($("inp-np-proxy-uid").value):null;
  var npProxyPort=$("inp-np-proxy-port")&&$("inp-np-proxy-port").value?parseInt($("inp-np-proxy-port").value):null;
  var npProxyAdminPort=$("inp-np-proxy-admin-port")&&$("inp-np-proxy-admin-port").value?parseInt($("inp-np-proxy-admin-port").value):null;
  var npResources=collectNpResources();
  return{
    name:name,namespace:namespace,scope:scope.value,target_kind:kind,
    target_deployment:targetDeployment,target_selector:targetSelector,
    target_containers:containers,mode:mode,enforcers:enforcers,
    rules:rules,capability_rules:caps,banned_files:banned,
    apparmor_raw_rules:aaRaw,attack_protection_groups:atGroups,privileged:privileged,
    unconfined_containers:collectUnconfinedContainers(),
    bpf_file_rules:bpfFiles,bpf_process_rules:bpfProcs,bpf_mounts:bpfMounts,
    bpf_ptrace:bpfPtrace,bpf_network:bpfNet,
    seccomp_syscalls:scSysc,seccomp_action:scAction,seccomp_raw_rules:scRaw,
    modeling_duration:durationMins*60,
    update_existing_workloads:updateExisting,audit_violations:auditViol,allow_violations:allowViol,
    did_apparmor_type:didAaType,did_apparmor_custom:didAaCustom,did_apparmor_raw_rules:didAaRaw,
    did_seccomp_type:didScType,did_seccomp_custom:didScCustom,
    did_seccomp_syscalls:didScSysc,did_seccomp_action:didScAction,did_seccomp_raw_rules:didScRaw,
    did_allow_violations:didAllowViol,did_np_egress:didNpEgress,
    np_mitm_domains:npMitmDomains,np_mitm_mutations:npMitmMut,np_egress:npEgress,
    np_proxy_uid:npProxyUid,np_proxy_port:npProxyPort,np_proxy_admin_port:npProxyAdminPort,
    np_resources:npResources
  };
}

// ── Submit for Review ──
async function doSubmitForReview(){
  if(!canSubmit()){alert("Only operator or admin can submit policies for review.");return;}
  if(!_validatedOk){alert("Please validate the policy first.");return;}
  var msgEl=$("create-msg");hideEl(msgEl);
  var btn=$("btn-submit-review");btn.disabled=true;
  try{
    var payload=buildPolicyPayload();
    if(!payload){showMsg(msgEl,"error","Fill all required fields.");btn.disabled=false;return;}
    var res=await api("/api/policies/submit",{method:"POST",body:JSON.stringify(payload)});
    var d=await res.json();
    if(!res.ok){showMsg(msgEl,"error",d.error||"Submit failed");btn.disabled=false;return;}
    showMsg(msgEl,"success","Policy '"+esc(payload.name)+"' submitted for review (ID: "+esc(d.id||"?")+"). An admin must approve before it applies to the cluster.");
    _validatedOk=false;
    setTimeout(function(){cancelEdit();switchPolicyView("queue");loadPolicyQueue();},1500);
  }catch(e){showMsg(msgEl,"error",e.message);}
  finally{if(canSubmit()&&_validatedOk) btn.disabled=false;}
}

// ── Review Queue ──
async function loadPolicyQueue(){
  setLoading("queue",true);hide("queue-empty");hide("queue-err");$("queue-body").innerHTML="";
  var statusFilter=($("sel-queue-filter")||{value:""}).value;
  var params=statusFilter?"status="+encodeURIComponent(statusFilter):"";
  try{
    var r=await api("/api/policies/queue"+(params?"?"+params:"")),d=await r.json();
    setLoading("queue",false);
    if(!r.ok){showEl($("queue-err"),d.error||"Failed to load queue");return;}
    var items=d.queue||[];
    var pending=typeof d.total_pending==="number"?d.total_pending:items.filter(function(i){return i.status==="pending";}).length;
    var badge=$("queue-pending-badge");
    if(badge){
      badge.textContent=pending+" pending";
      toggleVis("queue-pending-badge",pending>0);
    }
    renderPolicyQueue(items);
  }catch(e){setLoading("queue",false);showEl($("queue-err"),e.message);}
}

var _queueItemsMap={};

function renderPolicyQueue(items){
  var el=$("queue-body");
  if(!items.length){show("queue-empty");el.innerHTML="";return;}
  hide("queue-empty");
  var canApprove=hasPerm("review:approve");
  var canReject=hasPerm("review:reject");
  var canCancelAny=hasPerm("review:cancel");
  var statusColors={pending:"badge-amber",approved:"badge-green",rejected:"badge-red",cancelled:"badge-gray"};
  _queueItemsMap={};
  el.innerHTML="";
  items.forEach(function(item){
    _queueItemsMap[item.id]=item;
    var sb='<span class="badge '+(statusColors[item.status]||"badge-gray")+'">'+esc(item.status)+'</span>';
    var submittedAt=item.submitted_at?new Date(item.submitted_at).toLocaleString("vi-VN"):"—";
    var reviewedBy=item.reviewed_by?esc(item.reviewed_by):'<span style="color:#475569">—</span>';
    var note=item.review_note?('<span title="'+esc(item.review_note)+'" style="cursor:help;color:#64748b">'+esc(item.review_note.slice(0,30))+(item.review_note.length>30?"…":"")+'</span>'):'<span style="color:#475569">—</span>';
    var actions='<button onclick="openQueueDetail(\''+esc(item.id)+'\')" class="btn btn-ghost btn-sm" style="margin-right:2px">Detail</button>';
    if(item.status==="pending"){
      if(canApprove){
        actions+='<button onclick="approveQueued(\''+esc(item.id)+'\')" class="btn btn-green btn-sm" style="margin-right:2px">&#10003;</button>';
      }
      if(canReject){
        actions+='<button onclick="openRejectModal(\''+esc(item.id)+'\',\''+esc(item.name)+'\')" class="btn btn-danger btn-sm" style="margin-right:2px">&#10005;</button>';
      }
      if(canCancelAny||item.submitted_by===CURRENT_USER){
        actions+='<button onclick="cancelQueued(\''+esc(item.id)+'\')" class="btn btn-ghost btn-sm">Cancel</button>';
      }
    }
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b;transition:background 100ms";
    tr.onmouseover=function(){tr.style.background="#243552";};
    tr.onmouseout=function(){tr.style.background="";};
    tr.innerHTML='<td class="td" style="font-family:monospace;color:#93c5fd;font-size:.8rem">'+esc(item.name)
      +'<div style="font-size:.68rem;color:#475569">'+esc(item.namespace)+'</div></td>'
      +'<td class="td"><span class="badge '+(item.scope==="cluster"?"badge-purple":"badge-gray")+'">'+(item.scope==="cluster"?"Cluster":"NS")+'</span></td>'
      +'<td class="td" style="font-size:.8rem;color:#94a3b8">'+esc(item.submitted_by)+'</td>'
      +'<td class="td" style="font-size:.75rem;color:#475569;white-space:nowrap">'+esc(submittedAt)+'</td>'
      +'<td class="td">'+sb+'</td>'
      +'<td class="td" style="font-size:.75rem">'+reviewedBy+'</td>'
      +'<td class="td" style="font-size:.75rem;max-width:10rem">'+note+'</td>'
      +'<td class="td th-r" style="white-space:nowrap">'+actions+'</td>';
    el.appendChild(tr);
  });
}

async function approveQueued(id){
  if(!hasPerm("review:approve")){alert("Permission denied: review:approve required.");return;}
  if(!confirm("Approve and apply this policy to the cluster?")) return;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(id)+"/approve",{method:"POST",body:JSON.stringify({})});
    var d=await r.json();
    if(!r.ok){alert("Approve failed: "+(d.error||r.status));return;}
    loadPolicyQueue();loadPolicies();
  }catch(e){alert("Error: "+e.message);}
}

var _rejectTargetId=null;
function openRejectModal(id,name){
  if(!hasPerm("review:reject")){alert("Permission denied: review:reject required.");return;}
  _rejectTargetId=id;
  $("reject-policy-name").textContent=name;
  $("ta-reject-note").value="";
  hideEl($("reject-msg"));
  show("modal-reject");
}
function closeRejectModal(){hide("modal-reject");_rejectTargetId=null;}
$("modal-reject").addEventListener("click",function(e){if(e.target===$("modal-reject"))closeRejectModal();});
$("btn-reject-confirm").addEventListener("click",async function(){
  if(!_rejectTargetId) return;
  var note=$("ta-reject-note").value.trim();
  if(!note){showMsg($("reject-msg"),"error","Rejection note is required.");return;}
  this.disabled=true;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(_rejectTargetId)+"/reject",{
      method:"POST",body:JSON.stringify({note:note})
    });
    var d=await r.json();
    if(!r.ok){showMsg($("reject-msg"),"error",d.error||"Reject failed");this.disabled=false;return;}
    closeRejectModal();loadPolicyQueue();
  }catch(e){showMsg($("reject-msg"),"error",e.message);this.disabled=false;}
  this.disabled=false;
});

async function cancelQueued(id){
  if(!confirm("Cancel this pending submission?")) return;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(id),{method:"DELETE"});
    var d=await r.json();
    if(!r.ok){alert("Cancel failed: "+(d.error||r.status));return;}
    loadPolicyQueue();
  }catch(e){alert("Error: "+e.message);}
}

// ── Queue Detail Modal ──
var _qdItem=null;

function openQueueDetail(id){
  var item=_queueItemsMap[id];
  if(!item) return;
  _qdItem=item;
  var payload=null;
  try{payload=JSON.parse(item.manifest);}catch(e){}
  _renderQueueDetail(item,payload);
  show("modal-queue-detail");
}

function closeQueueDetail(){
  hide("modal-queue-detail");
  _qdItem=null;
}

function queuePayloadFromManifest(manifest,item){
  var meta=manifest.metadata||{},spec=manifest.spec||{},target=spec.target||{},policy=spec.policy||{};
  var ep=policy.enhanceProtect||{},did=policy.defenseInDepth||{},bpf=ep.bpfRawRules||{};
  var rules=[];
  (ep.hardeningRules||[]).forEach(function(r){rules.push(r);});
  (ep.vulMitigationRules||[]).forEach(function(r){rules.push(r);});
  (ep.attackProtectionRules||[]).forEach(function(g){(g.rules||[]).forEach(function(r){rules.push(r);});});
  var sc=ep.syscallRawRules||[];
  var scSimple=(sc.length===1&&sc[0]&&!sc[0].args&&!sc[0].errnoRet&&!sc[0].includes&&!sc[0].excludes)?sc[0]:null;
  return {
    name:meta.name||item.name,
    namespace:meta.namespace||item.namespace||"default",
    scope:manifest.kind==="VarmorClusterPolicy"?"cluster":"namespace",
    target_kind:target.kind||"Deployment",
    target_deployment:target.name||"",
    target_selector:target.selector||null,
    target_containers:target.containers||[],
    mode:policy.mode||"",
    enforcers:(policy.enforcer||"").split("|").filter(Boolean),
    rules:rules,
    apparmor_raw_rules:ep.appArmorRawRules||[],
    attack_protection_groups:ep.attackProtectionRules||[],
    bpf_file_rules:bpf.files||[],
    bpf_process_rules:bpf.processes||[],
    bpf_mounts:bpf.mounts||[],
    bpf_ptrace:bpf.ptrace||null,
    bpf_network:bpf.network||null,
    seccomp_syscalls:scSimple?(scSimple.names||[]):[],
    seccomp_action:scSimple?(scSimple.action||"SCMP_ACT_ERRNO"):"SCMP_ACT_ERRNO",
    seccomp_raw_rules:scSimple?[]:sc,
    np_egress:(ep.networkProxyRawRules||{}).egress||null,
    did_apparmor_type:(did.appArmor||{}).profileType||"",
    did_seccomp_type:(did.seccomp||{}).profileType||"",
    did_allow_violations:!!did.allowViolations,
    update_existing_workloads:!!spec.updateExistingWorkloads,
    audit_violations:!!ep.auditViolations,
    allow_violations:!!ep.allowViolations,
    privileged:!!ep.privileged
  };
}

function _renderQueueDetail(item,p){
  if(p&&p.apiVersion) p=queuePayloadFromManifest(p,item);
  var statusColors={pending:"badge-amber",approved:"badge-green",rejected:"badge-red",cancelled:"badge-gray"};
  var isPending=item.status==="pending";
  var canApproveItem=hasPerm("review:approve");
  var admin=canApproveItem;

  // Header
  $("qd-title").textContent=item.name;
  $("qd-subtitle").textContent=(item.scope==="cluster"?"[cluster-scoped]":("namespace: "+item.namespace));
  $("qd-status-badge").innerHTML='<span class="badge '+(statusColors[item.status]||"badge-gray")+'">'+esc(item.status)+'</span>';

  if(!p){
    $("qd-target").innerHTML='<span style="color:#f87171;font-size:.8rem">Failed to parse policy payload.</span>';
    $("qd-mode").innerHTML="";$("qd-rules").innerHTML="";$("qd-extended").innerHTML="";$("qd-options").innerHTML="";$("qd-yaml").textContent="";
  } else {
    // Target
    var tgt='<div class="qd-value">'+esc(p.target_kind||"Deployment")+'</div>';
    if(p.target_deployment) tgt+='<div style="font-family:monospace;color:#93c5fd;font-size:.82rem;margin-top:.2rem">'+esc(p.target_deployment)+'</div>';
    if(p.target_selector){var ml=p.target_selector.matchLabels||{};if(Object.keys(ml).length) tgt+='<div style="font-size:.72rem;color:#64748b;margin-top:.2rem">selector: '+esc(JSON.stringify(ml))+'</div>';}
    if(p.target_containers&&p.target_containers.length) tgt+='<div style="font-size:.72rem;color:#64748b">containers: '+esc(p.target_containers.join(", "))+'</div>';
    $("qd-target").innerHTML=tgt;

    // Mode & Enforcers
    var enfsHtml=(p.enforcers||[]).map(function(e){
      return '<span style="padding:.15rem .5rem;border-radius:.25rem;background:#0c1a3b;border:1px solid #1d4ed8;font-size:.75rem;color:#93c5fd;margin-right:.3rem">'+esc(e)+'</span>';
    }).join("");
    $("qd-mode").innerHTML='<div class="qd-value mb-2">'+esc(p.mode||"")+'</div><div>'+enfsHtml+'</div>';

    // Rules breakdown
    var rules=p.rules||[];
    var caps=p.capability_rules||[];
    var banned=p.banned_files||[];
    var rulesHtml="";
    if(!rules.length&&!caps.length&&!banned.length){
      rulesHtml='<span style="color:#475569;font-size:.78rem">(none selected)</span>';
    } else {
      var hardening=rules.filter(function(r){return _YAML_HARDENING.has(r)||/^disable-cap-/.test(r);});
      var attack=rules.filter(function(r){return !_YAML_HARDENING.has(r)&&!/^disable-cap-/.test(r)&&!_YAML_VULN.has(r);});
      var vuln=rules.filter(function(r){return _YAML_VULN.has(r);});
      function chips(arr,color){
        return arr.map(function(r){return '<span class="qd-rule-chip" style="background:#0f172a;border:1px solid '+color+';color:'+color+'">'+esc(r)+'</span>';}).join("");
      }
      if(hardening.length) rulesHtml+='<div class="mb-2"><span class="qd-label" style="color:#c4b5fd">Hardening ('+hardening.length+')</span><div>'+chips(hardening,"#c4b5fd")+'</div></div>';
      if(attack.length) rulesHtml+='<div class="mb-2"><span class="qd-label" style="color:#f87171">Attack Protection ('+attack.length+')</span><div>'+chips(attack,"#f87171")+'</div></div>';
      if(vuln.length) rulesHtml+='<div class="mb-2"><span class="qd-label" style="color:#fbbf24">Vuln Mitigation ('+vuln.length+')</span><div>'+chips(vuln,"#fbbf24")+'</div></div>';
      if(caps.length) rulesHtml+='<div class="mb-2"><span class="qd-label" style="color:#94a3b8">Custom Capabilities</span><div>'+chips(caps,"#94a3b8")+'</div></div>';
      if(banned.length) rulesHtml+='<div><span class="qd-label">Banned Files</span><div style="font-size:.72rem;color:#64748b;font-family:monospace">'+esc(banned.join(", "))+'</div></div>';
    }
    $("qd-rules").innerHTML=rulesHtml;

    // Extended config summary
    var ext=[];
    if((p.bpf_file_rules||[]).length) ext.push("BPF: "+(p.bpf_file_rules||[]).length+" file rule(s)");
    if((p.bpf_process_rules||[]).length) ext.push("BPF: "+(p.bpf_process_rules||[]).length+" process rule(s)");
    if((p.bpf_mounts||[]).length) ext.push("BPF: "+(p.bpf_mounts||[]).length+" mount rule(s)");
    if(p.bpf_ptrace) ext.push("BPF ptrace rule");
    if(p.bpf_network) ext.push("BPF network rule");
    if((p.seccomp_syscalls||[]).length) ext.push("Seccomp: "+(p.seccomp_syscalls||[]).length+" syscall(s) ["+esc(p.seccomp_action||"SCMP_ACT_ERRNO")+"]");
    if((p.seccomp_raw_rules||[]).length) ext.push("Seccomp: "+(p.seccomp_raw_rules||[]).length+" raw rule(s)");
    if(p.np_egress) ext.push("NetworkProxy: egress configured");
    if((p.np_mitm_domains||[]).length) ext.push("NetworkProxy: "+(p.np_mitm_domains||[]).length+" MITM domain(s)");
    if(p.did_apparmor_type) ext.push("DID AppArmor: "+esc(p.did_apparmor_type));
    if(p.did_seccomp_type) ext.push("DID Seccomp: "+esc(p.did_seccomp_type));
    if(p.modeling_duration) ext.push("Modeling duration: "+Math.round(p.modeling_duration/60)+" min");
    if((p.apparmor_raw_rules||[]).length) ext.push("AppArmor raw: "+(p.apparmor_raw_rules||[]).length+" rule(s)");
    if((p.attack_protection_groups||[]).length) ext.push("Attack groups: "+(p.attack_protection_groups||[]).length+" group(s)");
    $("qd-extended").innerHTML=ext.length?ext.map(function(s){return '<div style="margin-bottom:.2rem">&#8226; '+s+'</div>';}).join(""):'<span style="color:#475569">—</span>';

    // Options
    var opts=[];
    if(p.update_existing_workloads) opts.push("updateExistingWorkloads");
    if(p.audit_violations) opts.push("auditViolations");
    if(p.allow_violations) opts.push("allowViolations");
    if(p.privileged) opts.push("privileged baseline");
    $("qd-options").innerHTML=opts.length?opts.map(function(o){return '<span style="padding:.1rem .45rem;border-radius:.25rem;background:#0f172a;border:1px solid #334155;color:#94a3b8;font-size:.75rem;margin-right:.3rem">'+esc(o)+'</span>';}).join(""):'<span style="color:#475569;font-size:.78rem">—</span>';

    // YAML preview
    $("qd-yaml").textContent=_buildQueueItemYaml(p,item.scope);
  }

  // Timeline
  var tl=[];
  tl.push({color:"#4ade80",label:"Submitted",detail:esc(item.submitted_by)+" &mdash; "+(item.submitted_at?esc(new Date(item.submitted_at).toLocaleString("vi-VN")):"—")});
  if(item.reviewed_by){
    var rlabel=item.status==="approved"?"Approved":item.status==="rejected"?"Rejected":"Reviewed";
    var rcolor=item.status==="approved"?"#4ade80":item.status==="rejected"?"#f87171":"#fbbf24";
    tl.push({color:rcolor,label:rlabel,detail:esc(item.reviewed_by)+(item.reviewed_at?" &mdash; "+esc(new Date(item.reviewed_at).toLocaleString("vi-VN")):"")});
    if(item.review_note) tl.push({color:"#64748b",label:"Note",detail:'<em style="color:#94a3b8">'+esc(item.review_note)+'</em>'});
  }
  $("qd-timeline").innerHTML=tl.map(function(t){
    return '<div class="qd-timeline-row">'
      +'<div class="qd-timeline-dot" style="background:'+t.color+'"></div>'
      +'<div><span style="font-weight:600;color:#94a3b8;font-size:.78rem">'+t.label+'</span> <span style="color:#475569;font-size:.78rem">'+t.detail+'</span></div></div>';
  }).join("");

  // Footer buttons
  $("qd-btn-approve").classList.toggle("hidden",!admin||!isPending);
  $("qd-btn-reject-toggle").classList.toggle("hidden",!hasPerm("review:reject")||!isPending);
  $("qd-btn-reject-confirm").classList.add("hidden");
  $("qd-reject-note-sec").classList.add("hidden");
  $("qd-spacer").classList.remove("hidden");
  $("qd-btn-cancel-sub").classList.toggle("hidden",!isPending||(!hasPerm("review:cancel")&&item.submitted_by!==CURRENT_USER));
  $("qd-btn-reject-toggle").textContent="✗ Reject";
  hideEl($("qd-msg"));
  var rn=$("qd-reject-note");if(rn) rn.value="";
}

function _buildQueueItemYaml(p,scope){
  var crdKind=scope==="cluster"?"VarmorClusterPolicy":"VarmorPolicy";
  var lines=["apiVersion: crd.varmor.org/v1beta1","kind: "+crdKind,"metadata:","  name: "+(p.name||"unnamed")];
  if(scope!=="cluster") lines.push("  namespace: "+(p.namespace||"default"));
  lines.push("spec:","  target:","    kind: "+(p.target_kind||"Deployment"));
  if(p.target_deployment) lines.push("    name: "+p.target_deployment);
  if(p.target_selector){
    var ml=p.target_selector.matchLabels||{};
    if(Object.keys(ml).length){lines.push("    selector:","      matchLabels:");Object.entries(ml).forEach(function(e){lines.push("        "+e[0]+": "+e[1]);});}
  }
  if(p.target_containers&&p.target_containers.length) lines.push("    containers: ["+p.target_containers.join(", ")+"]");
  lines.push("  policy:","    enforcer: "+((p.enforcers||[]).join("|")||"—"),"    mode: "+(p.mode||"EnhanceProtect"));
  if(p.mode==="EnhanceProtect"){
    var rules=p.rules||[];
    var hard=rules.filter(function(r){return _YAML_HARDENING.has(r)||/^disable-cap-/.test(r);});
    var atk=rules.filter(function(r){return !_YAML_HARDENING.has(r)&&!/^disable-cap-/.test(r)&&!_YAML_VULN.has(r);});
    var vuln=rules.filter(function(r){return _YAML_VULN.has(r);});
    var _qHasBpf=(p.bpf_file_rules||[]).length||(p.bpf_process_rules||[]).length||(p.bpf_mounts||[]).length;
    var _qHasNp=p.np_egress&&typeof p.np_egress==="object";
    var _qHasSc=(p.seccomp_syscalls||[]).length;
    if(hard.length||atk.length||vuln.length||(p.apparmor_raw_rules||[]).length||_qHasBpf||_qHasNp||_qHasSc){
      lines.push("    enhanceProtect:");
      if(hard.length){lines.push("      hardeningRules:");hard.forEach(function(r){lines.push("        - "+r);});}
      // Attack rules: prefer groups-with-targets over simple checkbox rules
      var atkGrps=p.attack_protection_groups||[];
      if(atkGrps.length){
        lines.push("      attackProtectionRules:");
        atkGrps.forEach(function(g){
          lines.push("        - rules: ["+(g.rules||[]).join(", ")+"]");
          if((g.targets||[]).length){
            lines.push("          targets:");
            (g.targets||[]).forEach(function(t){lines.push("            - "+t);});
          }
        });
      } else if(atk.length){
        lines.push("      attackProtectionRules:");
        lines.push("        - rules: ["+atk.join(", ")+"]");
      }
      if(vuln.length){lines.push("      vulMitigationRules:");vuln.forEach(function(r){lines.push("        - "+r);});}
      if((p.apparmor_raw_rules||[]).length) lines.push("      # appArmorRawRules: "+(p.apparmor_raw_rules||[]).length+" rule(s)");
      if(_qHasSc){
        lines.push("      syscallRawRules:");
        lines.push("        - action: "+(p.seccomp_action||"SCMP_ACT_ERRNO"));
        lines.push("          names: ["+p.seccomp_syscalls.slice(0,8).join(", ")+(p.seccomp_syscalls.length>8?"…":"")+"]");
      }
      if(_qHasBpf){
        lines.push("      bpfRawRules:");
        if((p.bpf_file_rules||[]).length){
          lines.push("        files:");
          (p.bpf_file_rules||[]).forEach(function(r){lines.push("          - pattern: "+r.pattern+"  # perms:["+((r.permissions||[]).join(","))+"] qual:"+((r.qualifiers||["deny"]).join(",")));});
        }
        if((p.bpf_process_rules||[]).length){
          lines.push("        processes:");
          (p.bpf_process_rules||[]).forEach(function(r){lines.push("          - pattern: "+r.pattern+"  # perms:["+((r.permissions||[]).join(","))+"]");});
        }
        if((p.bpf_mounts||[]).length) lines.push("        # mounts: "+(p.bpf_mounts||[]).length+" entries");
      }
      if(_qHasNp){
        lines.push("      networkProxyRawRules:");
        lines.push("        egress:");
        lines.push("          defaultAction: "+(p.np_egress.defaultAction||"deny"));
        if((p.np_egress.rules||[]).length) lines.push("          # rules: "+(p.np_egress.rules||[]).length+" L4 rule(s)");
        if((p.np_egress.httpRules||[]).length) lines.push("          # httpRules: "+(p.np_egress.httpRules||[]).length+" HTTP rule(s)");
      }
    }
    if(!_qHasNp&&p.np_egress) lines.push("    # networkProxy: egress configured");
  }
  if(p.mode==="BehaviorModeling"&&p.modeling_duration) lines.push("    behaviorModeling:","      duration: "+p.modeling_duration+"s");
  if(p.mode==="DefenseInDepth"){
    lines.push("    defenseInDepth:");
    if(p.did_apparmor_type) lines.push("      appArmor:","        profileType: "+p.did_apparmor_type);
    if(p.did_seccomp_type) lines.push("      seccomp:","        profileType: "+p.did_seccomp_type);
    if(!p.did_apparmor_type&&!p.did_seccomp_type) lines.push("      # (no profile configured)");
  }
  if(p.audit_violations||p.allow_violations||p.privileged){
    lines.push("  # options:");
    if(p.audit_violations) lines.push("  #   auditViolations: true");
    if(p.allow_violations) lines.push("  #   allowViolations: true");
    if(p.privileged) lines.push("  #   privileged: true");
  }
  return lines.join("\n");
}

function toggleQdRejectNote(){
  var sec=$("qd-reject-note-sec"),sp=$("qd-spacer"),confirm=$("qd-btn-reject-confirm"),toggle=$("qd-btn-reject-toggle");
  var showing=!sec.classList.contains("hidden");
  sec.classList.toggle("hidden",showing);
  sp.classList.toggle("hidden",!showing);
  confirm.classList.toggle("hidden",showing);
  toggle.textContent=showing?"✗ Reject":"↩ Cancel";
  if(!showing) sec.querySelector("textarea").focus();
}

async function approveFromDetail(){
  if(!_qdItem||!hasPerm("review:approve")) return;
  if(!confirm("Approve and apply this policy to the cluster?")) return;
  $("qd-btn-approve").disabled=true;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(_qdItem.id)+"/approve",{method:"POST",body:"{}"});
    var d=await r.json();
    if(!r.ok){showMsg($("qd-msg"),"error",d.error||"Approve failed");$("qd-btn-approve").disabled=false;return;}
    showMsg($("qd-msg"),"success","Approved and applied to cluster.");
    $("qd-btn-approve").classList.add("hidden");$("qd-btn-reject-toggle").classList.add("hidden");
    setTimeout(function(){closeQueueDetail();loadPolicyQueue();loadPolicies();},1400);
  }catch(e){showMsg($("qd-msg"),"error",e.message);$("qd-btn-approve").disabled=false;}
}

async function confirmQdReject(){
  if(!_qdItem||!hasPerm("review:reject")) return;
  var note=($("qd-reject-note").value||"").trim();
  if(!note){showMsg($("qd-msg"),"error","Rejection note is required.");return;}
  $("qd-btn-reject-confirm").disabled=true;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(_qdItem.id)+"/reject",{method:"POST",body:JSON.stringify({note:note})});
    var d=await r.json();
    if(!r.ok){showMsg($("qd-msg"),"error",d.error||"Reject failed");$("qd-btn-reject-confirm").disabled=false;return;}
    showMsg($("qd-msg"),"success","Policy rejected.");
    ["qd-btn-approve","qd-btn-reject-toggle","qd-btn-reject-confirm","qd-reject-note-sec"].forEach(function(id){$(id).classList.add("hidden");});
    $("qd-spacer").classList.remove("hidden");
    setTimeout(function(){closeQueueDetail();loadPolicyQueue();},1200);
  }catch(e){showMsg($("qd-msg"),"error",e.message);$("qd-btn-reject-confirm").disabled=false;}
}

async function cancelQueuedFromDetail(){
  if(!_qdItem) return;
  if(!confirm("Cancel this pending submission?")) return;
  $("qd-btn-cancel-sub").disabled=true;
  try{
    var r=await api("/api/policies/queue/"+encodeURIComponent(_qdItem.id),{method:"DELETE"});
    var d=await r.json();
    if(!r.ok){showMsg($("qd-msg"),"error",d.error||"Cancel failed");$("qd-btn-cancel-sub").disabled=false;return;}
    showMsg($("qd-msg"),"success","Submission cancelled.");
    $("qd-btn-cancel-sub").classList.add("hidden");
    setTimeout(function(){closeQueueDetail();loadPolicyQueue();},1200);
  }catch(e){showMsg($("qd-msg"),"error",e.message);$("qd-btn-cancel-sub").disabled=false;}
}

// ── NetworkProxy Structured Builders ──

// Header Mutations builder
function addNpHeaderRow(domain,headerName,valueType,val1,val2){
  var div=document.createElement("div");
  div.className="np-header-row";
  div.style.cssText="display:grid;grid-template-columns:1fr 1fr 5rem 1fr auto;gap:.375rem;align-items:center";
  var type=valueType||"literal";
  div.innerHTML='<input type="text" class="form-input np-h-domain" value="'+esc(domain||'')+'" placeholder="example.com" style="font-family:monospace;font-size:.78rem"/>'
    +'<input type="text" class="form-input np-h-name" value="'+esc(headerName||'')+'" placeholder="Authorization" style="font-family:monospace;font-size:.78rem"/>'
    +'<select class="form-input np-h-type" style="font-size:.75rem;padding:.25rem .4rem" onchange="onNpHeaderTypeChange(this)">'
    +  '<option value="literal"'+(type==="literal"?" selected":"")+'>Value</option>'
    +  '<option value="secret"'+(type==="secret"?" selected":"")+'>Secret</option>'
    +'</select>'
    +'<div class="np-h-value-wrap" style="min-width:0">'
    +  '<input type="text" class="form-input np-h-val" value="'+esc(type==="literal"?val1||"":"")+'" placeholder="Bearer token…" style="font-family:monospace;font-size:.78rem;'+(type==="secret"?"display:none":"")+'">'
    +  '<div class="np-h-secret-wrap" style="display:'+(type==="secret"?"grid":"none")+';grid-template-columns:1fr 1fr;gap:.25rem">'
    +    '<input type="text" class="form-input np-h-secret-name" value="'+esc(type==="secret"?val1||"":"")+'" placeholder="secret-name" style="font-family:monospace;font-size:.75rem">'
    +    '<input type="text" class="form-input np-h-secret-key" value="'+esc(type==="secret"?val2||"":"")+'" placeholder="key" style="font-family:monospace;font-size:.75rem">'
    +  '</div>'
    +'</div>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="padding:.2rem .5rem;color:#f87171" onclick="this.closest(\'.np-header-row\').remove();_onFormChange()">&#10005;</button>';
  $("np-header-rows").appendChild(div);
}

function onNpHeaderTypeChange(sel){
  var row=sel.closest(".np-header-row");
  var type=sel.value;
  row.querySelector(".np-h-val").style.display=type==="literal"?"":"none";
  row.querySelector(".np-h-secret-wrap").style.display=type==="secret"?"grid":"none";
}

function collectNpHeaders(){
  var byDomain={};
  var mitmDomains=($("ta-np-mitm-domains").value||"").split("\n").map(function(d){return d.trim();}).filter(Boolean);
  document.querySelectorAll(".np-header-row").forEach(function(row,idx){
    var domain=row.querySelector(".np-h-domain").value.trim();
    var name=row.querySelector(".np-h-name").value.trim();
    var type=row.querySelector(".np-h-type").value;
    if(!domain||!name) return; // skip incomplete rows silently
    // Warn (non-blocking) if domain not in MITM list
    if(mitmDomains.length&&mitmDomains.indexOf(domain)<0){
      console.warn("Header mutation domain '"+domain+"' is not listed in MITM Domains.");
    }
    var header={name:name};
    if(type==="secret"){
      var sn=row.querySelector(".np-h-secret-name").value.trim();
      var sk=row.querySelector(".np-h-secret-key").value.trim();
      if(!sn) throw new Error("header '"+name+"' on domain '"+domain+"': Secret type requires a secret name");
      if(!sk) throw new Error("header '"+name+"' on domain '"+domain+"': secretRef requires both name and key");
      header.secretRef={name:sn,key:sk};
    }else{
      var val=row.querySelector(".np-h-val").value.trim();
      if(!val) return; // skip header with no value
      header.value=val;
    }
    if(!byDomain[domain]) byDomain[domain]=[];
    byDomain[domain].push(header);
  });
  var result=Object.keys(byDomain).map(function(d){return{domain:d,headers:byDomain[d]};});
  return result.length?result:null;
}

// L4 Egress Rules builder
function addNpL4Row(qualifier,addrType,addr,ports,description){
  var div=document.createElement("div");
  div.className="np-l4-row";
  div.style.cssText="display:grid;grid-template-columns:5.5rem 4.5rem 1fr 7rem 1fr auto;gap:.375rem;align-items:center";
  var q=qualifier||"allow";var at=addrType||"cidr";
  div.innerHTML='<select class="form-input np-l4-q" style="font-size:.75rem;padding:.25rem .4rem">'
    +'<option value="allow"'+(q==="allow"?" selected":"")+'>allow</option>'
    +'<option value="deny"'+(q==="deny"?" selected":"")+'>deny</option>'
    +'<option value="audit"'+(q==="audit"?" selected":"")+'>audit</option>'
    +'</select>'
    +'<select class="form-input np-l4-at" style="font-size:.75rem;padding:.25rem .4rem">'
    +'<option value="cidr"'+(at==="cidr"?" selected":"")+'>CIDR</option>'
    +'<option value="ip"'+(at==="ip"?" selected":"")+'>IP</option>'
    +'</select>'
    +'<input type="text" class="form-input np-l4-addr" value="'+esc(addr||'')+'" placeholder="10.0.0.0/8 or 1.2.3.4" style="font-family:monospace;font-size:.78rem"/>'
    +'<input type="text" class="form-input np-l4-ports" value="'+esc(ports||'')+'" placeholder="80,443" style="font-size:.78rem"/>'
    +'<input type="text" class="form-input np-l4-desc" value="'+esc(description||'')+'" placeholder="description" style="font-size:.78rem"/>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="padding:.2rem .5rem;color:#f87171" onclick="this.closest(\'.np-l4-row\').remove();_onFormChange()">&#10005;</button>';
  $("np-l4-rows").appendChild(div);
}

function _parsePorts(raw,errors){
  if(!raw||!raw.trim()) return [];
  var result=[];
  var items=raw.split(",");
  for(var i=0;i<items.length;i++){
    var p=items[i].trim();if(!p) continue;
    var parts=p.split("-");
    // Reject "80-90-100" — only single port or port-range (exactly 2 parts)
    if(parts.length>2){
      if(errors) errors.push("invalid port '"+p+"': use 'port' or 'port-endPort' format");
      return [];
    }
    // Strict: each part must be digits only — rejects "80abc", "8090xxx"
    if(!/^\d+$/.test(parts[0])){
      if(errors) errors.push("invalid port '"+p+"': not a valid integer");
      return [];
    }
    var port=parseInt(parts[0],10);
    if(port<1||port>65535){
      if(errors) errors.push("invalid port '"+p+"' (must be 1-65535)");
      return [];
    }
    var entry={port:port};
    if(parts.length>1){
      if(!/^\d+$/.test(parts[1])){
        if(errors) errors.push("invalid port range '"+p+"': endPort is not a valid integer");
        return [];
      }
      var endPort=parseInt(parts[1],10);
      if(endPort<1||endPort>65535){
        if(errors) errors.push("invalid port range '"+p+"': endPort must be 1-65535");
        return [];
      }
      if(endPort<port){
        if(errors) errors.push("invalid port range '"+p+"': endPort ("+endPort+") must be >= port ("+port+")");
        return [];
      }
      entry.endPort=endPort;
    }
    result.push(entry);
  }
  return result;
}

function collectNpL4Rules(){
  var rules=[],errs=[];
  document.querySelectorAll(".np-l4-row").forEach(function(row,idx){
    var q=row.querySelector(".np-l4-q").value;
    var at=row.querySelector(".np-l4-at").value;
    var addr=row.querySelector(".np-l4-addr").value.trim();
    var portErrors=[];
    var ports=_parsePorts(row.querySelector(".np-l4-ports").value,portErrors);
    if(portErrors.length){portErrors.forEach(function(e){errs.push("L4 rule #"+(idx+1)+": "+e);});return;}
    // Skip only if BOTH addr and ports are empty (port-only rules are valid per CRD)
    if(!addr&&!ports.length) return;
    var rule={qualifiers:[q]};
    if(addr){if(at==="ip") rule.ip=addr; else rule.cidr=addr;}
    if(ports.length) rule.ports=ports;
    var desc=row.querySelector(".np-l4-desc").value.trim();
    if(desc) rule.description=desc;
    rules.push(rule);
  });
  if(errs.length) throw new Error(errs.join("; "));
  return rules;
}

// L7 HTTP Rules builder
var _NP_HTTP_METHODS=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"];

function addNpHttpRow(qualifier,description,hosts,paths,methods,ports){
  var div=document.createElement("div");
  div.className="np-http-row";
  div.style.cssText="background:#0a1020;border:1px solid #1e2d45;border-radius:.5rem;padding:.625rem .75rem";
  var q=qualifier||"allow";
  var hostsVal=Array.isArray(hosts)?hosts.join(", "):(typeof hosts==="string"?hosts:"");
  var portsVal=Array.isArray(ports)?ports.map(function(p){return p.port||p;}).join(","):(ports||"");
  var desc=description||"";
  var pathsStr="";
  if(Array.isArray(paths)&&paths.length){
    pathsStr=paths.map(function(p){
      if(p.exact) return "exact:"+p.exact;
      if(p.prefix) return "prefix:"+p.prefix;
      return "";
    }).filter(Boolean).join("\n");
  }else if(typeof paths==="string"&&paths){
    pathsStr=paths;
  }
  var methodChecks=_NP_HTTP_METHODS.map(function(m){
    var chk=Array.isArray(methods)&&methods.indexOf(m)>=0?"checked":"";
    return '<label class="perm-check"><input type="checkbox" class="np-http-method" value="'+m+'" '+chk+'>'+m+'</label>';
  }).join("");
  div.innerHTML='<div style="display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.5rem">'
    +'<div style="display:flex;align-items:center;gap:.5rem;flex:1">'
    +'<select class="form-input np-http-q" style="font-size:.75rem;padding:.25rem .4rem;width:6rem">'
    +'<option value="allow"'+(q==="allow"?" selected":"")+'>allow</option>'
    +'<option value="deny"'+(q==="deny"?" selected":"")+'>deny</option>'
    +'<option value="audit"'+(q==="audit"?" selected":"")+'>audit</option>'
    +'</select>'
    +'<input type="text" class="form-input np-http-desc" value="'+esc(desc)+'" placeholder="description (optional)" style="flex:1;font-size:.78rem"/>'
    +'</div>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="padding:.2rem .5rem;color:#f87171;flex-shrink:0" onclick="this.closest(\'.np-http-row\').remove();_onFormChange()">&#10005;</button></div>'
    +'<div class="grid grid-cols-2 gap-2">'
    +'<div><label style="font-size:.68rem;color:#64748b;display:block;margin-bottom:.2rem">Hosts <span style="color:#475569">(wildcards: *.example.com)</span></label>'
    +'<input type="text" class="form-input np-http-hosts" value="'+esc(hostsVal)+'" placeholder="api.example.com, *.internal" style="font-family:monospace;font-size:.78rem"/></div>'
    +'<div><label style="font-size:.68rem;color:#64748b;display:block;margin-bottom:.2rem">Ports <span style="color:#475569">(optional)</span></label>'
    +'<input type="text" class="form-input np-http-ports" value="'+esc(portsVal)+'" placeholder="80,443" style="font-size:.78rem"/></div></div>'
    +'<div class="mt-2"><label style="font-size:.68rem;color:#64748b;display:block;margin-bottom:.2rem">Paths <span style="color:#475569">(one per line — prefix:/v1 or exact:/api/v1 or just /v1. MITM required for HTTPS)</span></label>'
    +'<textarea class="form-input np-http-paths" rows="2" placeholder="prefix:/v1/chat&#10;exact:/api/models" style="font-family:monospace;font-size:.75rem;resize:vertical">'+esc(pathsStr)+'</textarea></div>'
    +'<div class="mt-2"><label style="font-size:.68rem;color:#64748b;display:block;margin-bottom:.2rem">Methods <span style="color:#475569">(unchecked = all)</span></label>'
    +'<div style="display:flex;flex-wrap:wrap;gap:.5rem">'+methodChecks+'</div></div>';
  $("np-http-rows").appendChild(div);
}

function collectNpHttpRules(){
  var rules=[],errs=[];
  document.querySelectorAll(".np-http-row").forEach(function(row,idx){
    var q=row.querySelector(".np-http-q").value;
    var desc=row.querySelector(".np-http-desc").value.trim();
    var hostsRaw=row.querySelector(".np-http-hosts").value.trim();
    var portsRaw=row.querySelector(".np-http-ports").value.trim();
    var pathsRaw=(row.querySelector(".np-http-paths").value||"").trim();
    var methods=Array.from(row.querySelectorAll(".np-http-method:checked")).map(function(c){return c.value;});
    var hosts=hostsRaw?hostsRaw.split(",").map(function(h){return h.trim();}).filter(Boolean):[];
    if(!hosts.length&&!pathsRaw&&!methods.length) return; // empty rule, skip
    var portErrors=[];
    var ports=_parsePorts(portsRaw,portErrors);
    if(portErrors.length){portErrors.forEach(function(e){errs.push("HTTP rule #"+(idx+1)+": "+e);});return;}
    // Parse paths: one per line, prefix:/x or exact:/x or /x (defaults to prefix)
    var paths=[];
    if(pathsRaw){
      pathsRaw.split("\n").forEach(function(line){
        line=line.trim();if(!line) return;
        var po={};
        if(line.indexOf("exact:")==0) po.exact=line.slice(6).trim();
        else if(line.indexOf("prefix:")==0) po.prefix=line.slice(7).trim();
        else po.prefix=line;
        if(po.exact||po.prefix) paths.push(po);
      });
    }
    var match={};
    if(hosts.length) match.hosts=hosts;
    if(ports.length) match.ports=ports;
    if(paths.length) match.paths=paths;
    if(methods.length) match.methods=methods;
    var rule={qualifiers:[q],match:match};
    if(desc) rule.description=desc;
    rules.push(rule);
  });
  if(errs.length) throw new Error(errs.join("; "));
  return rules;
}

function collectNpEgress(){
  var da=$("sel-np-default-action")?$("sel-np-default-action").value:"";
  var l4=collectNpL4Rules();   // may throw
  var l7=collectNpHttpRules(); // may throw
  if(!da&&!l4.length&&!l7.length) return null;
  // CRD requires defaultAction when egress object is present
  if(!da&&(l4.length||l7.length)){
    throw new Error("defaultAction is required when L4 or L7 rules are configured — choose 'deny' (whitelist) or 'allow' (blacklist)");
  }
  var egress={defaultAction:da};
  if(l4.length) egress.rules=l4;
  if(l7.length) egress.httpRules=l7;
  return egress;
}

// Secret picker for header builder
var _secretPickerTarget=null;

function openSecretPickerForHeader(){
  _secretPickerTarget=null;
  show("modal-secret-picker");
  loadSecretsForPicker();
}

function insertSecretRef(secretName,key){
  if(_secretPickerTarget){
    _secretPickerTarget.querySelector(".np-h-type").value="secret";
    onNpHeaderTypeChange(_secretPickerTarget.querySelector(".np-h-type"));
    _secretPickerTarget.querySelector(".np-h-secret-name").value=secretName;
    _secretPickerTarget.querySelector(".np-h-secret-key").value=key;
    _secretPickerTarget=null;
  }else{
    addNpHeaderRow("","","secret",secretName,key);
  }
  closeSecretPickerModal();
}

// ── Restore attack groups when editing ──
// (Hook into parseSpecIntoForm which is defined earlier)
var _savedParseSpec=parseSpecIntoForm;
parseSpecIntoForm=function(crd,scope,name){
  _savedParseSpec(crd,scope,name);
  var ep=((crd.spec||{}).policy||{}).enhanceProtect||{};
  if($("attack-groups")) $("attack-groups").innerHTML="";
  (ep.attackProtectionRules||[]).forEach(function(g){
    if(g.targets&&g.targets.length) addAttackGroup(g.rules||[],g.targets||[]);
  });
};
