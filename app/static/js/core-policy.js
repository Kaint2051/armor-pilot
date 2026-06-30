"use strict";
var AUTH_HEADER=null,CURRENT_USER=null,CURRENT_ROLE="viewer";
var pendingDel={name:null,ns:null,scope:null};
var pendingProtect={name:null,ns:null};
var allPolicies=[];
var polFiltered=[];
var polPage=1;
var POL_PAGE_SIZE=10;
var editMode=null; // {name, ns, scope} when editing
var CURRENT_TAB="policy";
var CURRENT_LICENSE=null;
function switchTab(tab){
  ["dashboard","policy","logs","users","guide","settings"].forEach(function(t){
    var p=$("tab-"+t);
    if(p) p.classList.toggle("hidden",t!==tab);
    var b=$("tab-btn-"+t);
    if(b) b.classList.toggle("tab-active",t===tab);
  });
  CURRENT_TAB=tab;
  if(tab==="settings"){loadSettings();}
  if(tab==="dashboard"){loadDashboard();}
  if(tab==="logs"){
    // hide sub-nav buttons the current user has no permission to access
    var _auditNav=$("lcnav-audit");
    if(_auditNav) _auditNav.style.display=hasPerm("logs:audit")?"":"none";
    var _profilesNav=$("lcnav-profiles");
    if(_profilesNav) _profilesNav.style.display=hasPerm("logs:view")?"":"none";
    switchLogsView("security");
    // load all 3 views in parallel so summary counters are populated
    if(hasPerm("logs:violations")||hasPerm("logs:apparmor")) loadSecurityEvents();
    if(hasPerm("logs:audit")) loadAuditLogs();
    if(hasPerm("logs:view")) loadArmorProfiles();
  }
  if(tab==="users"){
    if(CURRENT_USER){
      $("user-display-name").textContent=CURRENT_USER;
      $("user-avatar").textContent=(CURRENT_USER[0]||"U").toUpperCase();
      var rb=$("user-role-badge");
      var _rc2={admin:"badge-blue",operator:"badge-amber",viewer:"badge-gray"};
      if(rb){rb.textContent=CURRENT_ROLE;rb.className="badge "+(_rc2[CURRENT_ROLE]||"badge-gray");}
    }
    _updateUsersTabForPermissions();
    if(hasPerm("users:view")){
      switchAcView("users");
      loadUsers();
    }else if(hasPerm("license:view")){
      switchAcView("license");
    }
  }
}

window.addEventListener("DOMContentLoaded",function(){
  updateRuleCounts();
  // Bind form-change validation reset so editing after ✓ Validate clears the valid state
  var _fc=$("form-create");
  if(_fc){_fc.addEventListener("input",_onFormChange);_fc.addEventListener("change",_onFormChange);}
  try{var s=JSON.parse(sessionStorage.getItem("va_auth")||"null");
    if(s&&s.header&&s.user){AUTH_HEADER=s.header;CURRENT_USER=s.user;enterDashboard();return;}}catch(x){}
  enterLogin();
});

function enterLogin(){show("pg-login");hide("pg-dash");}
function enterDashboard(){
  hide("pg-login");show("pg-dash");
  $("lbl-user").textContent="\u{1F464} "+CURRENT_USER;
  if($("user-display-name")){$("user-display-name").textContent=CURRENT_USER;$("user-avatar").textContent=(CURRENT_USER[0]||"U").toUpperCase();}
  api("/api/me").then(function(r){return r.json();}).then(function(d){
    CURRENT_ROLE=d.role||"viewer";
    CURRENT_PERMISSIONS=d.permissions||[];
    var rb=$("user-role-badge");
    var roleColors={admin:"badge-blue",operator:"badge-amber",viewer:"badge-gray"};
    if(rb){rb.textContent=CURRENT_ROLE;rb.className="badge "+(roleColors[CURRENT_ROLE]||"badge-gray");}
  }).catch(function(){CURRENT_ROLE="viewer";CURRENT_PERMISSIONS=[];}).then(function(){
    applyRoleUi();
    if(hasPerm("license:view")) loadLicenseStatus();
    loadAll();
  });
}
function logout(){
  if(AUTH_HEADER){fetch("/api/logout",{method:"POST",headers:{Authorization:AUTH_HEADER}}).catch(function(){});}
  sessionStorage.removeItem("va_auth");AUTH_HEADER=null;CURRENT_USER=null;CURRENT_ROLE="viewer";enterLogin();
}

var CURRENT_PERMISSIONS=[];
function hasPerm(p){return CURRENT_PERMISSIONS.indexOf(p)>=0;}
function isAdmin(){return hasPerm("policies:apply_direct");}
function canSubmit(){return hasPerm("policies:submit");}
function isViewer(){return !hasPerm("policies:create");}
function canEdit(){return hasPerm("policies:edit");}
function canDelete(){return hasPerm("policies:delete");}
function canImport(){return hasPerm("policies:import");}
function canExport(){return hasPerm("policies:export");}
function canApplyModel(){return hasPerm("models:apply");}

var _validatedOk=false; // true after successful validate

function applyRoleUi(){
  var admin=isAdmin(),submit=canSubmit();
  // Settings tab: only admins can access system settings
  var settingsBtn=$("tab-btn-settings");
  if(settingsBtn) settingsBtn.classList.toggle("hidden",!admin);
  var form=$("form-create");
  if(form){
    form.querySelectorAll("input,select,textarea").forEach(function(el){el.disabled=!submit;});
  }
  toggleVis("policy-admin-notice",!submit);
  // Wizard navigation buttons always accessible; action buttons role-gated
  var btnApply=$("btn-apply-direct");
  if(btnApply){btnApply.classList.toggle("hidden",!admin||_currentWizStep!==4);btnApply.disabled=!admin||!_validatedOk;}
  var btnSubmit=$("btn-submit-review");
  if(btnSubmit){btnSubmit.classList.toggle("hidden",!submit||_currentWizStep!==4);btnSubmit.disabled=!submit||!_validatedOk;}
  var btnVal=$("btn-validate");
  if(btnVal){btnVal.classList.toggle("hidden",_currentWizStep!==4);btnVal.disabled=!submit;}
  // pv-create nav: only show create if submit-capable
  var pnCreate=$("pnav-create");
  if(pnCreate) pnCreate.classList.toggle("hidden",!submit);
  var btnNewPol=$("btn-new-policy");
  if(btnNewPol) btnNewPol.classList.toggle("hidden",!hasPerm("policies:create"));
  var btnBackup=$("btn-backup-policy");
  if(btnBackup) btnBackup.classList.toggle("hidden",!canExport());
  var btnRestore=$("btn-restore-policy");
  if(btnRestore) btnRestore.classList.toggle("hidden",!canImport());
  var btnImport=$("btn-import-policy");
  if(btnImport) btnImport.classList.toggle("hidden",!canImport());
  toggleVis("btn-add-user", admin);
  var all=$("chk-all");
  if(all){all.disabled=!admin;all.checked=false;all.indeterminate=false;}
  if(!admin) clearSelection();
}

function _onFormChange(){
  // Any change resets validation state
  if(_validatedOk){
    _validatedOk=false;
    var btnApply=$("btn-apply-direct"),btnSubmit=$("btn-submit-review");
    if(btnApply) btnApply.disabled=true;
    if(btnSubmit) btnSubmit.disabled=true;
    var ind=$("validate-indicator");
    if(ind){ind.textContent="";ind.className="";}
  }
}

$("login-form").addEventListener("submit",async function(e){
  e.preventDefault();
  var u=$("inp-user").value.trim(),p=$("inp-pass").value,errEl=$("login-err");
  hideEl(errEl);
  if(!u||!p){showEl(errEl,"Please enter username and password.");return;}
  var hdr="Basic "+btoa(u+":"+p);
  try{
    var r=await fetch("/api/login",{method:"POST",headers:{Authorization:hdr}});
    if(r.status===401){showEl(errEl,"Invalid username or password.");return;}
    AUTH_HEADER=hdr;CURRENT_USER=u;
    sessionStorage.setItem("va_auth",JSON.stringify({header:hdr,user:u}));
    enterDashboard();
  }catch(err){showEl(errEl,"Connection error: "+err.message);}
});

async function api(path,opts){
  opts=opts||{};
  var r=await fetch(path,Object.assign({},opts,{headers:Object.assign({Authorization:AUTH_HEADER,"Content-Type":"application/json"},opts.headers||{})}));
  if(r.status===401){logout();throw new Error("Session expired.");}
  return r;
}

function ns(){return $("inp-ns").value.trim()||"default";}
function loadAll(){
  loadDeployments();
  loadPolicies();
  if(hasPerm("policies:view")) loadPolicyTemplates();
  if(hasPerm("logs:violations")||hasPerm("logs:apparmor")) loadSecurityEvents();
  if(hasPerm("logs:audit"))  loadAuditLogs();
  if(hasPerm("models:view")) loadProfileModels();
  loadPolicyQueue();
}

// ── Scope / mode / target toggles ──
function onScopeChange(){}
function onModeChange(){
  var m=$("sel-mode").value;
  var isEnhance=m==="EnhanceProtect";
  toggleVis("sec-enhance",isEnhance);
  var isSimple=(m==="AlwaysAllow"||m==="RuntimeDefault");
  toggleVis("sec-simple",isSimple||m==="BehaviorModeling"||m==="DefenseInDepth");
  var notes={
    AlwaysAllow:"AlwaysAllow disables all security restrictions. Use only for testing.",
    RuntimeDefault:"RuntimeDefault applies the container runtime's default AppArmor/Seccomp profile.",
    BehaviorModeling:"BehaviorModeling records container syscall/file/network behavior. Configure duration in the General tab.",
    DefenseInDepth:"DefenseInDepth applies a deny-by-default allowlist profile. Configure profiles in the DefenseInDepth tab."
  };
  var sn=$("simple-note");if(sn) sn.textContent=notes[m]||"";
  updateModeHint();
  updateRuleTabAvailability();
}
function onTargetModeChange(){
  var byLabel=document.querySelector('input[name="tgt-mode"]:checked').value==="selector";
  toggleVis("sec-tgt-name",!byLabel);
  toggleVis("sec-tgt-selector",byLabel);
}
function onKindChange(){
  loadWorkloadsForKind($("sel-kind").value);
}
var VALID_ENFORCER_COMBOS_JS=[
  ["AppArmor"],["BPF"],["Seccomp"],["NetworkProxy"],
  ["AppArmor","BPF"],["AppArmor","Seccomp"],["BPF","Seccomp"],["BPF","NetworkProxy"],
  ["AppArmor","BPF","Seccomp"],["BPF","NetworkProxy","Seccomp"]
].map(function(a){return a.slice().sort().join("|");});

function onEnforcerChange(){
  var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  updateRuleTabAvailability();
  updateComboChipHighlight();
  // Combo validation
  var warn=$("enf-combo-warn");
  if(warn){
    var combo=enfs.slice().sort().join("|");
    var isValid=!enfs.length||VALID_ENFORCER_COMBOS_JS.indexOf(combo)>=0;
    warn.style.display=isValid?"none":"block";
    if(!isValid) warn.textContent="Warning: '"+enfs.join("+")+"' is not a supported enforcer combination. Valid: "+VALID_ENFORCER_COMBOS_JS.map(function(s){return s.replace(/\|/g,"+");}).join(", ");
  }
}

// ── Policy sub-view & wizard navigation ──
var _currentPolicyView="list";
var _currentWizStep=1;
var _currentRuleTab="apparmor";

function switchPolicyView(view){
  _currentPolicyView=view;
  ["list","create","queue"].forEach(function(v){
    toggleVis("pv-"+v,v===view);
    var b=$("pnav-"+v);
    if(b){b.classList.toggle("pnav-active",v===view);}
  });
  if(view==="create"&&!editMode) resetWizard();
  if(view==="create"&&!_policyTemplatesLoaded) loadPolicyTemplates();
  if(view==="queue") loadPolicyQueue();
}

function wizGoToStep(n){
  _currentWizStep=n;
  [1,2,3,4].forEach(function(i){
    var step=$("wiz-step-"+i);
    if(step) step.classList.toggle("hidden",i!==n);
    var ind=$("wiz-ind-"+i);
    if(ind){
      ind.classList.toggle("wiz-ind-active",i===n);
      ind.classList.toggle("wiz-ind-done",i<n);
      if(i<n){ind.classList.remove("wiz-ind-active");}
      if(i===n){ind.classList.remove("wiz-ind-done");}
    }
  });
  var back=$("wiz-btn-back"),next=$("wiz-btn-next");
  var val=$("btn-validate"),sub=$("btn-submit-review"),app=$("btn-apply-direct"),valInd=$("validate-indicator");
  if(back) back.classList.toggle("hidden",n===1);
  if(next) next.classList.toggle("hidden",n===4);
  if(val) val.classList.toggle("hidden",n!==4);
  if(valInd) valInd.classList.toggle("hidden",n!==4);
  if(sub) sub.classList.toggle("hidden",!canSubmit()||n!==4);
  if(app) app.classList.toggle("hidden",!isAdmin()||n!==4);
  if(n===3){updateRuleTabAvailability();updateRuleSummary();}
  if(n===4){renderWizSummary();}
}

function wizBack(){ if(_currentWizStep>1) wizGoToStep(_currentWizStep-1); }
function wizNext(){
  if(_currentWizStep===1){
    var name=$("inp-pname").value.trim();
    var tgtMode=document.querySelector('input[name="tgt-mode"]:checked').value;
    var tgtName=$("sel-target").value,tgtSel=$("ta-selector").value.trim();
    if(!name){alert("Policy Name is required.");return;}
    if(tgtMode==="name"&&!tgtName){alert("Please select a target workload.");return;}
    if(tgtMode==="selector"&&!tgtSel){alert("Please enter a label selector.");return;}
  }
  if(_currentWizStep===2){
    var mode=$("sel-mode").value;
    if(mode==="EnhanceProtect"){
      var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked'));
      if(!enfs.length){alert("EnhanceProtect requires at least one enforcer. Select AppArmor, BPF, Seccomp, or NetworkProxy.");return;}
    }
  }
  if(_currentWizStep<4) wizGoToStep(_currentWizStep+1);
}

function switchRuleTab(tab){
  _currentRuleTab=tab;
  ["apparmor","attack","bpf","seccomp","networkproxy","did","general"].forEach(function(t){
    var panel=$("rtab-"+t);
    if(panel) panel.classList.toggle("hidden",t!==tab);
    var btn=$("rtab-btn-"+t);
    if(btn) btn.classList.toggle("rtab-active",t===tab);
  });
}

function updateRuleTabAvailability(){
  var mode=$("sel-mode")?$("sel-mode").value:"EnhanceProtect";
  var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  var isEnhance=mode==="EnhanceProtect";
  var isDid=mode==="DefenseInDepth";
  var isModeling=mode==="BehaviorModeling";
  var tabMap={
    apparmor:isEnhance&&(enfs.includes("AppArmor")||enfs.includes("BPF")),
    attack:isEnhance,
    bpf:isEnhance&&enfs.includes("BPF"),
    seccomp:isEnhance&&enfs.includes("Seccomp"),
    networkproxy:isEnhance&&enfs.includes("NetworkProxy"),
    did:isDid,
    general:isModeling||isEnhance||isDid
  };
  var firstEnabled=null;
  ["apparmor","attack","bpf","seccomp","networkproxy","did","general"].forEach(function(t){
    var btn=$("rtab-btn-"+t);
    if(!btn) return;
    var enabled=!!tabMap[t];
    btn.disabled=!enabled;
    if(enabled&&!firstEnabled) firstEnabled=t;
  });
  if(!tabMap[_currentRuleTab]&&firstEnabled) switchRuleTab(firstEnabled);
}

function renderWizSummary(){
  var el=$("wiz-summary");if(!el) return;
  var mode=$("sel-mode")?$("sel-mode").value:"";
  var scopeEl=document.querySelector('input[name="scope"]:checked');
  var scopeVal=scopeEl?scopeEl.value:"namespace";
  var name=$("inp-pname")?$("inp-pname").value.trim():"";
  var kind=$("sel-kind")?$("sel-kind").value:"";
  var tgtMode=document.querySelector('input[name="tgt-mode"]:checked');
  var tgtVal=tgtMode&&tgtMode.value==="selector"?("selector: "+($("ta-selector").value.trim().split("\n")[0]||"…")):($("sel-target").value||"(not set)");
  var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  var checkedRules=Array.from(document.querySelectorAll('input[name="rule"]:checked'));
  var autoR=$("chk-auto-restart")&&$("chk-auto-restart").checked&&scopeVal==="namespace"&&!editMode&&kind==="Deployment";
  var applyType=isAdmin()?"Apply Directly (admin)":canSubmit()?"Submit for Review (operator)":"Read-only (viewer)";
  var rows=[
    ["Policy Name",name||"(unnamed)"],
    ["Scope",scopeVal+" / "+kind],
    ["Target",tgtVal],
    ["Mode",mode],
    ["Enforcers",enfs.length?enfs.join(" + "):"(none — will fail for EnhanceProtect)"],
    ["Rules selected",checkedRules.length+" built-in rule(s)"],
    ["Workload restart",autoR?"Yes — rolling restart after apply":"No"],
    ["Action",applyType]
  ];
  el.innerHTML=rows.map(function(r){
    var warn=(r[1]+"").indexOf("fail")>=0||(r[1]+"").indexOf("viewer")>=0;
    return '<div style="display:flex;gap:1rem;padding:.35rem 0;border-bottom:1px solid #1e293b">'
      +'<span style="min-width:9rem;flex-shrink:0;color:#64748b;font-size:.78rem">'+r[0]+'</span>'
      +'<span style="color:'+(warn?"#f87171":"#f1f5f9")+';font-size:.78rem;font-weight:500">'+esc(r[1])+'</span></div>';
  }).join("");
  // restart note
  var rn=$("wiz-restart-note");
  if(rn){
    if(autoR){rn.classList.remove("hidden");rn.innerHTML="&#10003; Auto-restart is enabled — deployment will get <code>sandbox.varmor.org/enable=true</code> label and rolling restart.";}
    else{rn.classList.add("hidden");}
  }
  // apply note
  var an=$("wiz-apply-note");
  if(an){
    if(isAdmin()) an.innerHTML="&#9654; <b>Apply Directly</b> will push the policy CRD immediately to the cluster.";
    else if(canSubmit()) an.innerHTML="&#9654; <b>Submit for Review</b> queues the policy for admin approval. Nothing changes in the cluster until approved.";
    else an.innerHTML="Viewer role — cannot create or submit policies.";
  }
  // YAML preview
  var yp=$("yaml-preview");
  if(yp) yp.textContent=buildYamlPreview();
}

// ── Policy templates ──
var POLICY_TEMPLATES={};
var POLICY_TEMPLATE_PACKS=[];
var POLICY_TEMPLATE_PACK_NAMES={};
var _policyTemplatesLoaded=false;
var _templatePickerExpanded=false;
var SELECTED_POLICY_TEMPLATE_ID="";

function _riskBadgeClass(risk){
  return risk==="high"?"badge-red":risk==="medium"?"badge-amber":"badge-green";
}

function updateTemplatePickerSummary(){
  var box=$("tmpl-selected-summary");if(!box) return;
  var t=SELECTED_POLICY_TEMPLATE_ID?POLICY_TEMPLATES[SELECTED_POLICY_TEMPLATE_ID]:null;
  if(t){
    box.textContent="Selected: "+(t.name||t.id);
    box.classList.remove("tmpl-selected-empty");
  }else{
    box.textContent="No template selected";
    box.classList.add("tmpl-selected-empty");
  }
}

function setTemplatePickerExpanded(expanded){
  _templatePickerExpanded=!!expanded;
  var body=$("tmpl-picker-body");
  if(body) body.classList.toggle("hidden",!_templatePickerExpanded);
  var btn=$("tmpl-toggle-btn");
  if(btn) btn.setAttribute("aria-expanded",_templatePickerExpanded?"true":"false");
  var icon=$("tmpl-toggle-icon");
  if(icon) icon.innerHTML=_templatePickerExpanded?"&#9652;":"&#9662;";
  var label=$("tmpl-toggle-label");
  if(label) label.textContent=_templatePickerExpanded?"Hide Templates":"Browse Templates";
  if(_templatePickerExpanded&&!_policyTemplatesLoaded) loadPolicyTemplates();
}

function toggleTemplatePicker(){
  setTemplatePickerExpanded(!_templatePickerExpanded);
}

async function loadPolicyTemplates(force){
  if(_policyTemplatesLoaded&&!force){renderPolicyTemplateGallery();return;}
  var grid=$("tmpl-grid");
  if(grid) grid.innerHTML='<div style="font-size:.78rem;color:#64748b">Loading templates...</div>';
  try{
    var res=await api("/api/policy-templates");
    var data=await res.json();
    if(!res.ok) throw new Error(data.error||"Failed to load policy templates");
    POLICY_TEMPLATE_PACKS=data.packs||[];
    POLICY_TEMPLATES={};
    POLICY_TEMPLATE_PACK_NAMES={};
    POLICY_TEMPLATE_PACKS.forEach(function(p){POLICY_TEMPLATE_PACK_NAMES[p.id]=p.name;});
    (data.templates||[]).forEach(function(t){POLICY_TEMPLATES[t.id]=t;});
    _policyTemplatesLoaded=true;
    populateTemplateFilters();
    renderPolicyTemplateGallery();
  }catch(err){
    if(grid) grid.innerHTML='<div style="font-size:.78rem;color:#fca5a5">Template load failed: '+esc(err.message)+'</div>';
  }
}

function populateTemplateFilters(){
  var sel=$("tmpl-pack-filter");
  if(!sel) return;
  var cur=sel.value;
  sel.innerHTML='<option value="">All packs</option>';
  POLICY_TEMPLATE_PACKS.slice().sort(function(a,b){return(a.order||0)-(b.order||0);}).forEach(function(p){
    var o=document.createElement("option");
    o.value=p.id;o.textContent=p.name;
    sel.appendChild(o);
  });
  sel.value=cur;
}

function _templateSearchText(t){
  return [
    t.id,t.name,t.summary,t.pack,t.risk,t.mode,
    (t.enforcers||[]).join(" "),
    (t.rules||[]).join(" "),
    (t.banned_files||[]).join(" "),
    (t.capability_rules||[]).join(" "),
    (t.prerequisites||[]).join(" "),
    JSON.stringify(t.recommended_security_context||{})
  ].join(" ").toLowerCase();
}

function renderPolicyTemplateGallery(){
  var grid=$("tmpl-grid");if(!grid) return;
  var pack=($("tmpl-pack-filter")||{value:""}).value;
  var risk=($("tmpl-risk-filter")||{value:""}).value;
  var q=(($("tmpl-search")||{value:""}).value||"").trim().toLowerCase();
  var items=Object.values(POLICY_TEMPLATES).filter(function(t){
    if(pack&&t.pack!==pack) return false;
    if(risk&&t.risk!==risk) return false;
    if(q&&_templateSearchText(t).indexOf(q)<0) return false;
    return true;
  }).sort(function(a,b){
    var pa=(POLICY_TEMPLATE_PACKS.find(function(p){return p.id===a.pack;})||{}).order||0;
    var pb=(POLICY_TEMPLATE_PACKS.find(function(p){return p.id===b.pack;})||{}).order||0;
    return pa===pb?a.name.localeCompare(b.name):pa-pb;
  });
  var count=$("tmpl-count");
  if(count) count.textContent=items.length+" template"+(items.length===1?"":"s");
  updateTemplatePickerSummary();
  if(!items.length){
    grid.innerHTML='<div style="font-size:.78rem;color:#64748b">No templates match the current filters.</div>';
    return;
  }
  grid.innerHTML=items.map(function(t){
    var packName=POLICY_TEMPLATE_PACK_NAMES[t.pack]||t.pack||"Custom";
    return '<button type="button" class="tmpl-btn'+(t.id===SELECTED_POLICY_TEMPLATE_ID?' tmpl-active':'')+'" data-template-id="'+esc(t.id)+'" onclick="applyTemplate(\''+esc(t.id)+'\')">'
      +'<span class="tmpl-pack-label">'+esc(packName)+'</span>'
      +'<span class="tmpl-title">'+esc(t.name)+'</span>'
      +'<span class="tmpl-desc">'+esc(t.summary||"")+'</span>'
      +'<span class="tmpl-meta">'
      +'<span class="badge '+_riskBadgeClass(t.risk)+'">'+esc(t.risk||"low")+'</span>'
      +'<span class="badge badge-blue">'+esc(t.mode||"")+'</span>'
      +'<span class="badge badge-gray">'+esc((t.enforcers||[]).join("+")||"no enforcer")+'</span>'
      +'</span>'
      +'</button>';
  }).join("");
}

function _clearTemplateManagedFields(){
  document.querySelectorAll('input[name="rule"]').forEach(function(cb){cb.checked=false;});
  document.querySelectorAll('input[name="enforcer"]').forEach(function(cb){cb.checked=false;});
  ["bpf-files","bpf-procs","bpf-mounts","attack-groups","np-header-rows","np-l4-rows","np-http-rows"].forEach(function(id){
    var el=$(id);if(el) el.innerHTML="";
  });
  ["ta-dynamic-caps","ta-banned","ta-apparmor-raw","ta-bpf-network","ta-seccomp","ta-seccomp-raw",
   "ta-did-aa-custom","ta-did-aa-raw","ta-did-sc-syscalls","ta-did-sc-custom","ta-did-sc-raw",
   "ta-did-np-egress","ta-np-mitm-domains"].forEach(function(id){var el=$(id);if(el) el.value="";});
  ["chk-audit-viol","chk-allow-viol","chk-privileged","chk-ptrace-enable","chk-ptrace-strict","did-allow-viol"].forEach(function(id){var el=$(id);if(el) el.checked=false;});
  ["ptrace-perm-all","ptrace-perm-trace","ptrace-perm-traceby","ptrace-perm-read","ptrace-perm-readby"].forEach(function(id){var el=$(id);if(el) el.checked=false;});
  hide("sec-ptrace-rule");hide("did-aa-custom-sec");hide("did-sc-custom-sec");
  if($("sel-np-default-action")) $("sel-np-default-action").value="";
  if($("sel-seccomp-action")) $("sel-seccomp-action").value="SCMP_ACT_ERRNO";
  if($("sel-did-sc-action")) $("sel-did-sc-action").value="SCMP_ACT_ERRNO";
  if($("inp-duration")) $("inp-duration").value=60;
  ["inp-np-proxy-uid","inp-np-proxy-port","inp-np-proxy-admin-port","inp-np-req-cpu","inp-np-req-mem","inp-np-limit-cpu","inp-np-limit-mem"].forEach(function(id){var el=$(id);if(el) el.value="";});
}

function _setTemplateLines(id,values){
  var el=$(id);if(!el) return;
  el.value=(values||[]).join("\n");
}

function _applyTemplateNetworkProxy(t){
  var np=t.np_egress||null;
  if(np){
    if($("sel-np-default-action")) $("sel-np-default-action").value=np.defaultAction||"";
    (np.rules||[]).forEach(function(r){
      var at=r.ip?"ip":"cidr";
      var addr=r.ip||r.cidr||"";
      var ports=(r.ports||[]).map(function(p){return p.endPort?(p.port+"-"+p.endPort):p.port;}).join(",");
      addNpL4Row((r.qualifiers||[])[0]||"allow",at,addr,ports,r.description||"");
    });
    (np.httpRules||[]).forEach(function(r){
      var m=r.match||{};
      addNpHttpRow((r.qualifiers||[])[0]||"allow",r.description||"",m.hosts||[],m.paths||[],m.methods||[],m.ports||[]);
    });
  }
  _setTemplateLines("ta-np-mitm-domains",t.np_mitm_domains||[]);
  (t.np_mitm_mutations||[]).forEach(function(dm){
    (dm.headers||[]).forEach(function(h){
      if(h.secretRef) addNpHeaderRow(dm.domain||"",h.name||"","secret",h.secretRef.name||"",h.secretRef.key||"");
      else addNpHeaderRow(dm.domain||"",h.name||"","literal",h.value||"","");
    });
  });
}

function _renderTemplateDetail(t){
  var box=$("tmpl-selected-detail");if(!box) return;
  var packName=POLICY_TEMPLATE_PACK_NAMES[t.pack]||t.pack||"Custom";
  var tests=(t.test_steps||[]).map(function(s){return '<li>'+esc(s)+'</li>';}).join("");
  var prereq=(t.prerequisites||[]).map(function(s){return '<li>'+esc(s)+'</li>';}).join("");
  var sc=t.recommended_security_context?JSON.stringify(t.recommended_security_context,null,2):"";
  box.innerHTML='<div class="flex items-center justify-between gap-2 mb-2">'
    +'<div><b style="color:#e2e8f0">'+esc(t.name)+'</b><div style="color:#64748b;font-size:.7rem">'+esc(packName)+' / '+esc(t.mode||"")+' / '+esc((t.enforcers||[]).join("+"))+'</div></div>'
    +'<span class="badge '+_riskBadgeClass(t.risk)+'">'+esc(t.risk||"low")+'</span></div>'
    +'<div>'+esc(t.summary||"")+'</div>'
    +(prereq?'<div style="margin-top:.5rem;color:#64748b">Prerequisites:<ul style="list-style:disc;margin:.25rem 0 0 1rem">'+prereq+'</ul></div>':"")
    +(sc?'<div style="margin-top:.5rem;color:#64748b">Recommended securityContext:<pre style="white-space:pre-wrap;font-family:monospace;font-size:.68rem;background:#060c18;border:1px solid #1e293b;border-radius:.375rem;padding:.5rem;margin-top:.25rem;color:#94a3b8">'+esc(sc)+'</pre></div>':"")
    +(tests?'<div style="margin-top:.5rem;color:#64748b">Test playbook:<ul style="list-style:disc;margin:.25rem 0 0 1rem">'+tests+'</ul></div>':"");
  box.classList.remove("hidden");
}

function applyTemplate(name){
  var t=POLICY_TEMPLATES[name];if(!t) return;
  var pname=$("inp-pname");
  if(!pname||!pname.value.trim()){
    var hint=$("tmpl-name-hint");
    if(hint){hint.textContent="Please enter a policy name first.";hint.classList.remove("hidden");}
    if(pname){pname.focus();pname.classList.add("input-error");}
    return;
  }
  var hint=$("tmpl-name-hint");
  if(hint){hint.textContent="";hint.classList.add("hidden");}
  if(pname) pname.classList.remove("input-error");
  SELECTED_POLICY_TEMPLATE_ID=name;
  _clearTemplateManagedFields();
  document.querySelectorAll(".tmpl-btn").forEach(function(b){
    b.classList.toggle("tmpl-active",b.dataset.templateId===name);
  });
  var sm=$("sel-mode");if(sm){sm.value=t.mode||"EnhanceProtect";onModeChange();}
  document.querySelectorAll('input[name="enforcer"]').forEach(function(cb){cb.checked=(t.enforcers||[]).indexOf(cb.value)>=0;});
  onEnforcerChange();
  document.querySelectorAll('input[name="rule"]').forEach(function(cb){cb.checked=(t.rules||[]).indexOf(cb.value)>=0;});
  _setTemplateLines("ta-dynamic-caps",t.capability_rules||[]);
  _setTemplateLines("ta-banned",t.banned_files||[]);
  if(t.apparmor_raw_rules) $("ta-apparmor-raw").value=(t.apparmor_raw_rules||[]).map(function(r){return typeof r==="string"?r:JSON.stringify(r);}).join("\n");
  (t.bpf_file_rules||[]).forEach(function(r){addBpfRow("bpf-files",r.pattern,r.permissions,r.qualifiers);});
  (t.bpf_process_rules||[]).forEach(function(r){addBpfRow("bpf-procs",r.pattern,r.permissions,r.qualifiers);});
  (t.bpf_mounts||[]).forEach(function(r){addMountRow(r.sourcePattern,r.fstype,r.flags||[],(r.qualifiers||[])[0]||"deny");});
  if(t.bpf_network) $("ta-bpf-network").value=JSON.stringify(t.bpf_network,null,2);
  _setTemplateLines("ta-seccomp",t.seccomp_syscalls||[]);
  if(t.seccomp_action&&$("sel-seccomp-action")) $("sel-seccomp-action").value=t.seccomp_action;
  if(t.seccomp_raw_rules) $("ta-seccomp-raw").value=JSON.stringify(t.seccomp_raw_rules,null,2);
  if(t.did_apparmor_type){var aa=document.querySelector('input[name="did-aa-type"][value="'+t.did_apparmor_type+'"]');if(aa){aa.checked=true;onDidAaTypeChange();}}
  if(t.did_seccomp_type){var sc=document.querySelector('input[name="did-sc-type"][value="'+t.did_seccomp_type+'"]');if(sc){sc.checked=true;onDidScTypeChange();}}
  if(t.did_allow_violations&&$("did-allow-viol")) $("did-allow-viol").checked=true;
  if(t.modeling_duration&&$("inp-duration")) $("inp-duration").value=t.modeling_duration;
  if($("chk-audit-viol")) $("chk-audit-viol").checked=!!t.audit_violations;
  if($("chk-allow-viol")) $("chk-allow-viol").checked=!!t.allow_violations;
  if($("chk-privileged")) $("chk-privileged").checked=!!t.privileged;
  _applyTemplateNetworkProxy(t);
  _renderTemplateDetail(t);
  updateTemplatePickerSummary();
  setTemplatePickerExpanded(false);
  updateRuleCounts&&updateRuleCounts();
  _onFormChange();
  wizGoToStep(2);
}

// ── Enforcer combo chips ──
function applyEnforcerCombo(combo){
  var sel=combo.split("|");
  document.querySelectorAll('input[name="enforcer"]').forEach(function(cb){cb.checked=sel.includes(cb.value);});
  onEnforcerChange();
}

function updateComboChipHighlight(){
  var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;}).sort();
  var cur=enfs.join("|");
  document.querySelectorAll(".combo-chip").forEach(function(chip){
    var m=chip.getAttribute("onclick").match(/applyEnforcerCombo\('([^']+)'\)/);
    if(!m) return;
    var chk=m[1].split("|").sort().join("|");
    chip.classList.toggle("combo-chip-active",chk===cur);
  });
}

// ── Mode hint box ──
var MODE_HINTS={
  EnhanceProtect:"<b>EnhanceProtect</b> &mdash; Most commonly used. Adds blocking rules on top of the runtime default. Choose enforcers below, then configure rules in Step 3.",
  AlwaysAllow:"<b>AlwaysAllow</b> &mdash; Disables all security restrictions. For testing/debugging only. No enforcer or rule configuration needed.",
  RuntimeDefault:"<b>RuntimeDefault</b> &mdash; Applies the container runtime's built-in AppArmor/Seccomp profile. Minimal configuration needed.",
  BehaviorModeling:"<b>BehaviorModeling</b> &mdash; Records what the container actually does (syscalls, file access, network). Use before DefenseInDepth. Configure duration in the General tab.",
  DefenseInDepth:"<b>DefenseInDepth</b> &mdash; Strict deny-by-default allowlist. Can break workloads. Recommended only after BehaviorModeling produces a profile."
};
function updateModeHint(){
  var m=$("sel-mode")?$("sel-mode").value:"";
  var box=$("mode-hint-box");
  if(box) box.innerHTML=MODE_HINTS[m]||"";
}

// ── Rule summary bar (Step 3) ──
function updateRuleSummary(){
  var bar=$("rule-summary-bar");if(!bar) return;
  var checked=Array.from(document.querySelectorAll('input[name="rule"]:checked'));
  if(!checked.length){bar.classList.add("hidden");return;}
  bar.classList.remove("hidden");
  $("rsb-total").textContent=checked.length;
  var groups={};
  checked.forEach(function(cb){
    var body=cb.closest(".rule-group-body");
    var hdr=body?body.previousElementSibling:null;
    var nameEl=hdr?hdr.querySelector("span.flex"):null;
    var gname=nameEl?nameEl.childNodes[0].textContent.trim():"Other";
    groups[gname]=(groups[gname]||0)+1;
  });
  $("rsb-groups").innerHTML=Object.entries(groups).map(function(e){
    return '<span class="rsb-badge">'+esc(e[0])+" &times;"+e[1]+"</span>";
  }).join(" ");
  var HIGH_RISK=["disable-cap-all","disallow-mount","disallow-create-user-ns","disallow-load-all-bpf-prog"];
  var risky=checked.filter(function(cb){return HIGH_RISK.includes(cb.value);});
  var warnEl=$("rsb-warn");
  if(warnEl){
    warnEl.classList.toggle("hidden",!risky.length);
    if(risky.length) $("rsb-warn-text").textContent=risky.length+" high-impact rule(s) selected — test thoroughly";
  }
}

// ── YAML preview builder ──
// Rule category sets — must match HARDENING_RULES/ATTACK_RULES/VULN_RULES in api.py
var _YAML_HARDENING=new Set(["disallow-write-core-pattern","disallow-mount-securityfs","disallow-mount-procfs",
  "disallow-write-release-agent","disallow-mount-cgroupfs","disallow-debug-disk-device",
  "disallow-mount-disk-device","disallow-mount","disallow-umount","disallow-insmod",
  "disallow-load-bpf-prog","disallow-access-procfs-root","disallow-access-kallsyms",
  "disable-cap-all","disable-cap-all-except-net-bind-service","disable-cap-privileged",
  "disallow-abuse-user-ns","disallow-create-user-ns","disallow-load-all-bpf-prog",
  "disallow-load-bpf-via-setsockopt","disallow-userfaultfd-creation"]);
var _YAML_VULN=new Set(["cgroups-lxcfs-escape-mitigation","runc-override-mitigation",
  "dirty-pipe-mitigation","ingress-nightmare-mitigation","copy-fail-mitigation"]);
function _yamlRuleCategory(r){
  if(_YAML_HARDENING.has(r)||/^disable-cap-/.test(r)) return "hardening";
  if(_YAML_VULN.has(r)) return "vuln";
  return "attack";
}

function buildYamlPreview(){
  var name=($("inp-pname")||{value:""}).value.trim()||"unnamed";
  var scopeEl=document.querySelector('input[name="scope"]:checked');
  var scope=scopeEl?scopeEl.value:"namespace";
  var kind=$("sel-kind")?$("sel-kind").value:"Deployment";
  var mode=$("sel-mode")?$("sel-mode").value:"EnhanceProtect";
  var enfs=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  var tgtMode=document.querySelector('input[name="tgt-mode"]:checked');
  var tgtName=$("sel-target")?$("sel-target").value:"";
  var tgtSel=($("ta-selector")||{value:""}).value.trim();
  var containers=($("inp-containers")||{value:""}).value.split(",").map(function(c){return c.trim();}).filter(Boolean);
  var rules=Array.from(document.querySelectorAll('input[name="rule"]:checked')).map(function(c){return c.value;});
  var crdKind=scope==="cluster"?"VarmorClusterPolicy":"VarmorPolicy";
  var lines=["apiVersion: crd.varmor.org/v1beta1","kind: "+crdKind,"metadata:","  name: "+name];
  if(scope==="namespace") lines.push("  namespace: "+(ns()||"default"));
  lines.push("spec:","  target:","    kind: "+kind);
  if(tgtMode&&tgtMode.value==="selector"){
    if(tgtSel){
      lines.push("    selector:","      matchLabels:");
      tgtSel.split("\n").filter(Boolean).forEach(function(l){
        var p=l.split("=");if(p.length===2) lines.push("        "+p[0].trim()+": "+p[1].trim());
      });
    }
  } else if(tgtName){
    lines.push("    name: "+tgtName);
  }
  if(containers.length) lines.push("    containers: ["+containers.join(", ")+"]");
  lines.push("  policy:","    enforcer: "+(enfs.length?enfs.join("|"):"(none — required)"),"    mode: "+mode);
  if(mode==="EnhanceProtect"){
    var hardening=rules.filter(function(r){return _yamlRuleCategory(r)==="hardening";});
    var attack=rules.filter(function(r){return _yamlRuleCategory(r)==="attack";});
    var vuln=rules.filter(function(r){return _yamlRuleCategory(r)==="vuln";});
    var scSysc=($("ta-seccomp")||{value:""}).value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
    var scAct=($("sel-seccomp-action")||{value:"SCMP_ACT_ERRNO"}).value;
    var _bpfF=$("bpf-files")?collectBpfRules("bpf-files"):[];
    var _bpfP=$("bpf-procs")?collectBpfRules("bpf-procs"):[];
    var _bpfM=$("bpf-mounts")?$("bpf-mounts").querySelectorAll(".mount-row").length:0;
    var _atkGrps=collectAttackGroups();
    var _npL4=[]; var _npH=$("np-http-rows")?$("np-http-rows").children.length:0;
    try{_npL4=collectNpL4Rules();}catch(e){}
    if(hardening.length||attack.length||vuln.length||scSysc.length
       ||_bpfF.length||_bpfP.length||_bpfM||_atkGrps.length||_npL4.length||_npH){
      lines.push("    enhanceProtect:");
      if(hardening.length){lines.push("      hardeningRules:");hardening.forEach(function(r){lines.push("        - "+r);});}
      if(_atkGrps.length){
        lines.push("      attackProtectionRules:");
        _atkGrps.forEach(function(g){
          lines.push("        - rules: ["+g.rules.join(", ")+"]");
          if(g.targets.length){lines.push("          targets:");g.targets.forEach(function(t){lines.push("            - "+t);});}
        });
        if(attack.length) lines.push("        # (checkbox attack rules also present: "+attack.join(", ")+")");
      } else if(attack.length){
        lines.push("      attackProtectionRules:");
        lines.push("        - rules: ["+attack.join(", ")+"]");
      }
      if(vuln.length){lines.push("      vulMitigationRules:");vuln.forEach(function(r){lines.push("        - "+r);});}
      if(scSysc.length){lines.push("      syscallRawRules:","        - action: "+scAct,"          names: ["+scSysc.slice(0,6).join(", ")+(scSysc.length>6?"…":"")+"]");}
      if(_bpfF.length||_bpfP.length||_bpfM){
        lines.push("      bpfRawRules:");
        if(_bpfF.length){lines.push("        files:");_bpfF.forEach(function(r){lines.push("          - pattern: "+r.pattern+"  # perms:["+r.permissions.join(",")+"] qual:"+r.qualifiers.join(","));});}
        if(_bpfP.length){lines.push("        processes:");_bpfP.forEach(function(r){lines.push("          - pattern: "+r.pattern+"  # perms:["+r.permissions.join(",")+"]");});}
        if(_bpfM) lines.push("        # mounts: "+_bpfM+" entries");
      }
      if(_npL4.length||_npH){
        lines.push("      networkProxyRawRules:");
        lines.push("        egress:");
        var _npDef=($("sel-np-default-action")||{value:"deny"}).value||"deny";
        lines.push("          defaultAction: "+_npDef);
        _npL4.forEach(function(r){var p=[];if(r.cidr) p.push("cidr: "+r.cidr);else if(r.ip) p.push("ip: "+r.ip);if((r.ports||[]).length) p.push("ports:["+r.ports.map(function(x){return x.endPort?x.port+"-"+x.endPort:x.port;}).join(",")+"]");p.push("qualifiers:["+r.qualifiers.join(",")+"]");lines.push("          - "+p.join("  "));});
        if(_npH) lines.push("          # httpRules: "+_npH+" entry(ies)");
      }
    }
  }
  if(mode==="BehaviorModeling"){
    var dur=parseInt(($("inp-duration")||{value:"60"}).value)||60;
    lines.push("    behaviorModeling:","      duration: "+(dur*60)+"s");
  }
  if(mode==="DefenseInDepth"){
    lines.push("    defenseInDepth:");
    var didAa=document.querySelector('input[name="did-aa-type"]:checked');
    var didSc=document.querySelector('input[name="did-sc-type"]:checked');
    if(didAa) lines.push("      appArmor:","        profileType: "+didAa.value);
    if(didSc) lines.push("      seccomp:","        profileType: "+didSc.value);
    if(!didAa&&!didSc) lines.push("      # Configure allowlist profiles in the DefenseInDepth tab");
  }
  var auditViol=$("chk-audit-viol")&&$("chk-audit-viol").checked;
  var allowViol=$("chk-allow-viol")&&$("chk-allow-viol").checked;
  var privil=$("chk-privileged")&&$("chk-privileged").checked;
  if(auditViol||allowViol||privil){
    lines.push("  # options:");
    if(auditViol) lines.push("  #   auditViolations: true");
    if(allowViol) lines.push("  #   allowViolations: true");
    if(privil) lines.push("  #   privileged: true");
  }
  return lines.join("\n");
}

// ── Reset wizard to blank state ──
function resetWizard(){
  var form=$("form-create");
  if(form) form.reset();
  document.querySelectorAll('input[name="rule"]').forEach(function(cb){cb.checked=false;});
  // Clear all dynamic rows so old state doesn't bleed into new policy
  ["bpf-files","bpf-procs","bpf-mounts","attack-groups","unconfined-rows",
   "np-header-rows","np-l4-rows","np-http-rows"].forEach(function(id){
    var el=$(id);if(el) el.innerHTML="";
  });
  // Uncheck ptrace perms (form.reset unchecks chk-ptrace-enable but doesn't fire the change handler)
  ["ptrace-perm-all","ptrace-perm-trace","ptrace-perm-traceby","ptrace-perm-read","ptrace-perm-readby"].forEach(function(id){
    var el=$(id);if(el) el.checked=false;
  });
  // Hide conditional panels that aren't driven by form.reset
  hide("sec-ptrace-rule");
  hide("did-aa-custom-sec");
  hide("did-sc-custom-sec");
  // Reset validate state: clear indicator, re-show hint, disable action buttons
  _validatedOk=false;
  var ind=$("validate-indicator");
  if(ind){ind.textContent="";ind.className="text-sm font-semibold hidden";}
  var hint=$("validate-hint");
  if(hint){hint.style.display="";}
  var btnApply=$("btn-apply-direct");
  if(btnApply){btnApply.disabled=true;}
  var btnSubmit=$("btn-submit-review");
  if(btnSubmit){btnSubmit.disabled=true;}
  document.querySelectorAll(".tmpl-btn").forEach(function(b){b.classList.remove("tmpl-active");});
  SELECTED_POLICY_TEMPLATE_ID="";
  updateTemplatePickerSummary();
  setTemplatePickerExpanded(false);
  var _td=$("tmpl-selected-detail");if(_td){_td.innerHTML="";_td.classList.add("hidden");}
  var _ph=$("tmpl-name-hint");if(_ph){_ph.textContent="";_ph.classList.add("hidden");}
  var _pn=$("inp-pname");if(_pn) _pn.classList.remove("input-error");
  var tp=$("tmpl-picker");if(tp) tp.classList.remove("hidden");
  var eb=$("edit-banner");if(eb) eb.classList.add("hidden");
  var cancelBtn=$("btn-cancel-edit");if(cancelBtn) cancelBtn.classList.add("hidden");
  if($("pnav-create-label")) $("pnav-create-label").textContent="Create Policy";
  editMode=null;
  onModeChange();
  onEnforcerChange();
  updateRuleCounts&&updateRuleCounts();
  wizGoToStep(1);
}

async function loadWorkloadsForKind(kind){
  $("sel-target").innerHTML="<option value=\"\">&#8212; loading&#8230; &#8212;</option>";
  try{
    var r=await api("/api/namespaces/"+ns()+"/workloads?kind="+encodeURIComponent(kind));
    var data=await r.json();
    $("sel-target").innerHTML="<option value=\"\">&#8212; select "+kind+" &#8212;</option>";
    (data.workloads||[]).forEach(function(w){
      var o=document.createElement("option");o.value=w.name;o.textContent=w.name;
      $("sel-target").appendChild(o);
    });
  }catch(e){$("sel-target").innerHTML="<option value=\"\">&#8212; error &#8212;</option>";}
}

// ── BPF raw rules dynamic rows ──
function addBpfRow(containerId,pattern,permissions,qualifiers){
  var div=document.createElement("div");
  div.className="bpf-row";
  var perms=permissions||[];
  var quals=qualifiers||["deny"];
  function chk(v){return(perms.length===0&&v==="read")||perms.includes(v)?'checked':'';}
  var qualSel='<select class="form-input" style="font-size:.75rem;padding:.25rem .4rem">'
    +'<option value="deny"'+(quals.includes("deny")?" selected":"")+'>deny</option>'
    +'<option value="audit"'+(quals.includes("audit")?" selected":"")+'>audit</option>'
    +'</select>';
  div.innerHTML='<input type="text" class="form-input" value="'+esc(pattern||'')+'" placeholder="/etc/** or /bin/sh" style="font-family:monospace;font-size:.8rem"/>'
    +qualSel
    +'<div style="display:flex;gap:.375rem;flex-shrink:0">'
    +'<label class="perm-check"><input type="checkbox" value="read" '+chk("read")+'>r</label>'
    +'<label class="perm-check"><input type="checkbox" value="write" '+chk("write")+'>w</label>'
    +'<label class="perm-check"><input type="checkbox" value="append" '+chk("append")+'>a</label>'
    +'<label class="perm-check"><input type="checkbox" value="exec" '+chk("exec")+'>e</label>'
    +'<label class="perm-check"><input type="checkbox" value="all" '+chk("all")+'>*</label>'
    +'</div>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="padding:.2rem .5rem;color:#f87171" onclick="this.parentElement.remove();_onFormChange()">&#10005;</button>';
  $(containerId).appendChild(div);
}

function collectBpfRules(containerId){
  var rows=$(containerId).querySelectorAll(".bpf-row");
  var result=[];
  rows.forEach(function(row){
    var pattern=row.querySelector("input[type=text]").value.trim();
    if(!pattern) return;
    var perms=Array.from(row.querySelectorAll("input[type=checkbox]:checked")).map(function(c){return c.value;});
    if(!perms.length) perms=["read"];
    var qualSel=row.querySelector("select");
    var quals=qualSel?[qualSel.value]:["deny"];
    result.push({pattern:pattern,permissions:perms,qualifiers:quals});
  });
  return result;
}

// ── BPF mount / ptrace / network helpers ──
function parseJsonArrayInput(raw,label,msgEl){
  var text=(raw||"").trim();
  if(!text) return [];
  var parsed;
  try{parsed=JSON.parse(text);}catch(e){showMsg(msgEl,"error",label+": invalid JSON - "+e.message);return null;}
  if(!Array.isArray(parsed)){showMsg(msgEl,"error",label+": expected a JSON array.");return null;}
  return parsed;
}

function collectRawRuleInput(id,label,msgEl){
  var text=($(id).value||"").trim();
  if(!text) return [];
  if(text[0]==="[") return parseJsonArrayInput(text,label,msgEl);
  return text.split("\n").map(function(l){return l.trim();}).filter(Boolean).map(function(rule){return {rules:rule};});
}

function collectNpResources(){
  var resources={requests:{},limits:{}};
  var reqCpu=$("inp-np-req-cpu").value.trim();
  var reqMem=$("inp-np-req-mem").value.trim();
  var limitCpu=$("inp-np-limit-cpu").value.trim();
  var limitMem=$("inp-np-limit-mem").value.trim();
  if(reqCpu) resources.requests.cpu=reqCpu;
  if(reqMem) resources.requests.memory=reqMem;
  if(limitCpu) resources.limits.cpu=limitCpu;
  if(limitMem) resources.limits.memory=limitMem;
  if(!Object.keys(resources.requests).length) delete resources.requests;
  if(!Object.keys(resources.limits).length) delete resources.limits;
  return Object.keys(resources).length?resources:null;
}

function addMountRow(sp,ft,flags,qual){
  var div=document.createElement("div");
  div.className="mount-row";
  var flagStr=Array.isArray(flags)?flags.join(","):(flags||"");
  div.innerHTML='<input type="text" class="form-input" value="'+esc(sp||'')+'" placeholder="/** (source)" style="font-family:monospace;font-size:.78rem"/>'
    +'<input type="text" class="form-input" value="'+esc(ft||'')+'" placeholder="tmpfs" style="font-size:.78rem"/>'
    +'<input type="text" class="form-input" value="'+esc(flagStr)+'" placeholder="ro,bind" style="font-size:.78rem"/>'
    +'<select class="form-input" style="font-size:.75rem;padding:.25rem .4rem">'
    +'<option value="deny"'+(!qual||qual==="deny"?" selected":"")+'>deny</option>'
    +'<option value="audit"'+(qual==="audit"?" selected":"")+'>audit</option>'
    +'</select>'
    +'<button type="button" class="btn btn-ghost btn-sm" style="padding:.2rem .5rem;color:#f87171" onclick="this.parentElement.remove();_onFormChange()">&#10005;</button>';
  $("bpf-mounts").appendChild(div);
}

function collectMountRules(){
  var rows=$("bpf-mounts").querySelectorAll(".mount-row");
  var result=[];
  rows.forEach(function(row){
    var inputs=row.querySelectorAll("input[type=text]");
    var sp=inputs[0].value.trim();if(!sp) return;
    var ft=inputs[1].value.trim();
    var flags=inputs[2].value.trim().split(",").map(function(f){return f.trim();}).filter(Boolean);
    var qual=row.querySelector("select").value;
    result.push({sourcePattern:sp,fstype:ft,flags:flags,qualifiers:[qual]});
  });
  return result;
}

function collectPtraceRule(){
  if(!$("chk-ptrace-enable").checked) return null;
  var quals=[$("sel-ptrace-qual").value];
  var perms=["all","trace","traceby","read","readby"].filter(function(v){
    var el=$("ptrace-perm-"+v);return el&&el.checked;
  });
  if(!perms.length) perms=["all"];
  var rule={qualifiers:quals,permissions:perms};
  if($("chk-ptrace-strict").checked) rule.strictMode=true;
  return rule;
}

function fillNetworkTemplate(){
  $("ta-bpf-network").value=JSON.stringify({
    egress:{
      toDestinations:[
        {qualifiers:["deny"],cidr:"169.254.169.254/32",
         ports:[{protocol:"TCP",port:80},{protocol:"TCP",port:443}]}
      ]
    }
  },null,2);
}

function onPtraceEnableChange(){
  toggleVis("sec-ptrace-rule",$("chk-ptrace-enable").checked);
}

function onDidAaTypeChange(){
  var v=document.querySelector('input[name="did-aa-type"]:checked');
  toggleVis("did-aa-custom-sec",v&&v.value==="Custom");
}

function onDidScTypeChange(){
  var v=document.querySelector('input[name="did-sc-type"]:checked');
  toggleVis("did-sc-custom-sec",v&&v.value==="Custom");
}

// ── Edit mode ──
async function loadPolicyForEdit(el){
  if(!canEdit()){alert("Insufficient permissions to edit policies.");return;}
  var name=el.dataset.name,namespace=el.dataset.ns,scope=el.dataset.scope||"namespace";
  var path=scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(name)
    :"/api/namespaces/"+namespace+"/policies/"+encodeURIComponent(name);
  try{
    var res=await api(path);var crd=await res.json();
    if(!res.ok){alert("Cannot load policy: "+(crd.error||"unknown"));return;}
    editMode={name:name,ns:namespace,scope:scope};
    parseSpecIntoForm(crd,scope,name);
    show("edit-banner");show("btn-cancel-edit");
    var _tp=$("tmpl-picker");if(_tp) _tp.classList.add("hidden");
    $("edit-banner-name").textContent=(scope==="cluster"?"[cluster] ":namespace+"/")+name;
    $("btn-create-label").textContent="Update Policy";
    if($("pnav-create-label")) $("pnav-create-label").textContent="Edit Policy";
    $("inp-pname").readOnly=true;
    $("inp-pname").value=name;
    document.querySelectorAll('input[name="scope"]').forEach(function(r){r.disabled=true;r.checked=(r.value===scope);});
    switchPolicyView("create");
    wizGoToStep(1);
  }catch(err){alert("Error loading policy: "+err.message);}
}

function parseSpecIntoForm(crd,scope,name){
  var spec=crd.spec||{};
  var pol=spec.policy||{};
  var target=spec.target||{};
  var ep=pol.enhanceProtect||{};

  // Reset to clean slate first
  $("form-create").reset();
  $("bpf-files").innerHTML="";$("bpf-procs").innerHTML="";
  $("bpf-mounts").innerHTML="";
  $("chk-ptrace-enable").checked=false;hide("sec-ptrace-rule");
  $("ta-bpf-network").value="";
  $("ta-selector-expr").value="";
  $("ta-dynamic-caps").value="";
  $("ta-apparmor-raw").value="";
  $("ta-seccomp-raw").value="";
  $("ta-did-sc-raw").value="";
  $("chk-privileged").checked=false;
  document.querySelectorAll('input[name="rule"]').forEach(function(c){c.checked=false;});
  document.querySelectorAll('input[name="enforcer"]').forEach(function(c){c.checked=false;});

  // Mode
  $("sel-mode").value=pol.mode||"EnhanceProtect";
  onModeChange();

  // Enforcers
  var enfStr=pol.enforcer||"AppArmor";
  enfStr.split("|").forEach(function(e){
    var el=document.querySelector('input[name="enforcer"][value="'+e.trim()+'"]');
    if(el) el.checked=true;
  });
  onEnforcerChange();

  // Target kind
  $("sel-kind").value=target.kind||"Deployment";

  // Target by name vs selector
  if(target.selector&&(target.selector.matchLabels||target.selector.matchExpressions)){
    document.querySelector('input[name="tgt-mode"][value="selector"]').checked=true;
    onTargetModeChange();
    var lines=Object.entries(target.selector.matchLabels||{}).map(function(kv){return kv[0]+"="+kv[1];});
    $("ta-selector").value=lines.join("\n");
    if(target.selector.matchExpressions)
      try{$("ta-selector-expr").value=JSON.stringify(target.selector.matchExpressions,null,2);}catch(e){}
  } else {
    document.querySelector('input[name="tgt-mode"][value="name"]').checked=true;
    onTargetModeChange();
    // Populate workload dropdown with at least the current target name
    var opt=document.createElement("option");opt.value=target.name||"";opt.textContent=target.name||"";opt.selected=true;
    $("sel-target").innerHTML="";$("sel-target").appendChild(opt);
    loadWorkloadsForKind($("sel-kind").value).then(function(){
      if(target.name) $("sel-target").value=target.name;
    });
  }

  // Containers
  if(target.containers&&target.containers.length) $("inp-containers").value=target.containers.join(", ");

  // updateExistingWorkloads
  $("chk-update-existing").checked=!!spec.updateExistingWorkloads;

  // EnhanceProtect rules
  var allRules=[];
  (ep.hardeningRules||[]).forEach(function(r){allRules.push(r);});
  (ep.vulMitigationRules||[]).forEach(function(r){allRules.push(r);});
  (ep.attackProtectionRules||[]).forEach(function(g){(g.rules||[]).forEach(function(r){allRules.push(r);});});
  var dynamicCaps=[];
  allRules.forEach(function(r){
    var el=document.querySelector('input[name="rule"][value="'+r+'"]');
    if(el) el.checked=true;
    else if(/^disable-cap-/.test(r)) dynamicCaps.push(r.replace(/^disable-cap-/,"").toUpperCase().replace(/-/g,"_"));
  });
  $("ta-dynamic-caps").value=dynamicCaps.join("\n");
  updateRuleCounts();

  // Banned files (appArmorRawRules)
  var bannedLines=[],aaRawEntries=[];
  (ep.appArmorRawRules||[]).forEach(function(r){
    var rule=(r.rules||"").trim();
    var m=rule.match(/^deny\s+(.+?)\s+rwmlk,\s*$/);
    if(m&&!(r.targets&&r.targets.length)) bannedLines.push(m[1]);
    else if(rule) aaRawEntries.push(r);
  });
  $("ta-banned").value=bannedLines.join("\n");
  $("ta-apparmor-raw").value=aaRawEntries.map(function(r){
    if(r.targets&&r.targets.length) return JSON.stringify(r);
    return r.rules||"";
  }).join("\n");

  // Audit/allow violations
  $("chk-audit-viol").checked=!!ep.auditViolations;
  $("chk-allow-viol").checked=!!ep.allowViolations;
  $("chk-privileged").checked=!!ep.privileged;

  // Attack protection targets
  var atk=(ep.attackProtectionRules||[])[0];
  // Restore per-rule attack groups (handled in parseSpecIntoForm monkey-patch below)

  // BPF raw rules (files, processes, ptrace, mounts, network)
  var bpfObj=ep.bpfRawRules;
  if(bpfObj){
    (bpfObj.files||[]).forEach(function(fr){addBpfRow("bpf-files",fr.pattern,fr.permissions,fr.qualifiers);});
    (bpfObj.processes||[]).forEach(function(pr){addBpfRow("bpf-procs",pr.pattern,pr.permissions,pr.qualifiers);});
    if(bpfObj.ptrace){
      $("chk-ptrace-enable").checked=true;show("sec-ptrace-rule");
      var pt=bpfObj.ptrace;
      if(pt.qualifiers&&pt.qualifiers[0]) $("sel-ptrace-qual").value=pt.qualifiers[0];
      (pt.permissions||[]).forEach(function(v){var el=$("ptrace-perm-"+v);if(el)el.checked=true;});
      if(pt.strictMode) $("chk-ptrace-strict").checked=true;
    }
    (bpfObj.mounts||[]).forEach(function(mr){
      var flagStr=Array.isArray(mr.flags)?mr.flags.join(","):(mr.flags||"");
      var qual=(mr.qualifiers||["deny"])[0];
      addMountRow(mr.sourcePattern,mr.fstype,flagStr,qual);
    });
    if(bpfObj.network){
      try{$("ta-bpf-network").value=JSON.stringify(bpfObj.network,null,2);}catch(e){}
    }
  }

  // Seccomp raw rules
  var seccompRules=ep.syscallRawRules||[];
  var sr=seccompRules[0];
  if(seccompRules.length===1&&sr&&!sr.args&&!sr.errnoRet&&!sr.includes&&!sr.excludes){
    $("ta-seccomp").value=(sr.names||[]).join("\n");
    if(sr.action) $("sel-seccomp-action").value=sr.action;
  }else if(seccompRules.length){
    try{$("ta-seccomp-raw").value=JSON.stringify(seccompRules,null,2);}catch(e){}
  }

  // BehaviorModeling duration (CRD stores seconds, form shows minutes)
  var dur=(pol.modelingOptions||{}).duration||3600;
  $("inp-duration").value=Math.round(dur/60);

  // DefenseInDepth
  var did=pol.defenseInDepth||{};
  if(pol.mode==="DefenseInDepth"){
    var didAa=did.appArmor||{};
    if(didAa.profileType){
      var aaRadio=document.querySelector('input[name="did-aa-type"][value="'+didAa.profileType+'"]');
      if(aaRadio){aaRadio.checked=true;onDidAaTypeChange();}
    }
    if(didAa.customProfile) $("ta-did-aa-custom").value=didAa.customProfile;
    if(didAa.appArmorRawRules&&didAa.appArmorRawRules.length)
      $("ta-did-aa-raw").value=(didAa.appArmorRawRules||[]).map(function(r){return r.rules||"";}).join("\n");
    var didSc=did.seccomp||{};
    if(didSc.profileType){
      var scRadio=document.querySelector('input[name="did-sc-type"][value="'+didSc.profileType+'"]');
      if(scRadio){scRadio.checked=true;onDidScTypeChange();}
    }
    if(didSc.customProfile) $("ta-did-sc-custom").value=didSc.customProfile;
    var didScRules=didSc.syscallRawRules||[];
    var didScSr=didScRules[0];
    if(didScRules.length===1&&didScSr&&!didScSr.args&&!didScSr.errnoRet&&!didScSr.includes&&!didScSr.excludes){
      $("ta-did-sc-syscalls").value=(didScSr.names||[]).join("\n");
      if(didScSr.action) $("sel-did-sc-action").value=didScSr.action;
    }else if(didScRules.length){
      try{$("ta-did-sc-raw").value=JSON.stringify(didScRules,null,2);}catch(e){}
    }
    if(did.networkProxy&&did.networkProxy.egress)
      try{$("ta-did-np-egress").value=JSON.stringify(did.networkProxy.egress,null,2);}catch(e){}
    if(did.allowViolations) $("did-allow-viol").checked=true;
  }

  // NetworkProxy structured builders
  $("np-header-rows").innerHTML="";$("np-l4-rows").innerHTML="";$("np-http-rows").innerHTML="";
  if($("sel-np-default-action")) $("sel-np-default-action").value="";
  var npRaw=ep.networkProxyRawRules||{};
  var egress=npRaw.egress||{};
  if(egress.defaultAction&&$("sel-np-default-action")) $("sel-np-default-action").value=egress.defaultAction;
  (egress.rules||[]).forEach(function(r){
    var at=r.ip?"ip":"cidr";
    var addr=r.ip||r.cidr||"";
    var portsStr=(r.ports||[]).map(function(p){return p.endPort?(p.port+"-"+p.endPort):p.port;}).join(",");
    addNpL4Row((r.qualifiers||[])[0]||"allow",at,addr,portsStr,r.description||"");
  });
  (egress.httpRules||[]).forEach(function(r){
    var m=r.match||{};
    var hostsStr=(m.hosts||[]).join(", ");
    var portsStr=(m.ports||[]).map(function(p){return p.endPort?(p.port+"-"+p.endPort):p.port;}).join(",");
    addNpHttpRow((r.qualifiers||[])[0]||"allow",r.description||"",hostsStr,m.paths||[],m.methods||[],portsStr);
  });
  var npCfg=pol.networkProxyConfig||{};
  var mitm=npCfg.mitm||{};
  if(mitm.domains&&mitm.domains.length) $("ta-np-mitm-domains").value=mitm.domains.join("\n");
  (mitm.headerMutations||[]).forEach(function(dm){
    var domain=dm.domain||"";
    (dm.headers||[]).forEach(function(h){
      if(h.secretRef){
        addNpHeaderRow(domain,h.name||"","secret",h.secretRef.name||"",h.secretRef.key||"");
      }else{
        addNpHeaderRow(domain,h.name||"","literal",h.value||"","");
      }
    });
  });
  if(npCfg.proxyUID!=null) $("inp-np-proxy-uid").value=npCfg.proxyUID;
  if(npCfg.proxyPort!=null) $("inp-np-proxy-port").value=npCfg.proxyPort;
  if(npCfg.proxyAdminPort!=null) $("inp-np-proxy-admin-port").value=npCfg.proxyAdminPort;
  var npRes=npCfg.resources||{};
  if(npRes.requests){
    if(npRes.requests.cpu) $("inp-np-req-cpu").value=npRes.requests.cpu;
    if(npRes.requests.memory) $("inp-np-req-mem").value=npRes.requests.memory;
  }
  if(npRes.limits){
    if(npRes.limits.cpu) $("inp-np-limit-cpu").value=npRes.limits.cpu;
    if(npRes.limits.memory) $("inp-np-limit-mem").value=npRes.limits.memory;
  }
}

function cancelEdit(){
  editMode=null;
  $("inp-pname").readOnly=false;
  document.querySelectorAll('input[name="scope"]').forEach(function(r){r.disabled=false;});
  hide("edit-banner");hide("btn-cancel-edit");
  $("btn-create-label").textContent="Apply Directly";
  if($("pnav-create-label")) $("pnav-create-label").textContent="Create Policy";
  $("form-create").reset();
  document.querySelector('input[name="enforcer"][value="AppArmor"]').checked=true;
  $("chk-auto-restart").checked=true;
  $("sel-mode").value="EnhanceProtect";
  onModeChange();onEnforcerChange();updateRuleCounts();
  $("bpf-files").innerHTML="";$("bpf-procs").innerHTML="";
  $("bpf-mounts").innerHTML="";
  if($("attack-groups")) $("attack-groups").innerHTML="";
  if($("unconfined-rows")) $("unconfined-rows").innerHTML="";
  $("ta-bpf-network").value="";
  $("chk-ptrace-enable").checked=false;hide("sec-ptrace-rule");
  $("ta-dynamic-caps").value="";$("ta-apparmor-raw").value="";$("ta-seccomp-raw").value="";$("chk-privileged").checked=false;
  $("ta-did-aa-raw").value="";$("ta-did-aa-custom").value="";hide("did-aa-custom-sec");
  $("ta-did-sc-syscalls").value="";$("ta-did-sc-custom").value="";$("ta-did-sc-raw").value="";hide("did-sc-custom-sec");
  $("ta-did-np-egress").value="";
  $("ta-np-mitm-domains").value="";
  $("np-header-rows").innerHTML="";$("np-l4-rows").innerHTML="";$("np-http-rows").innerHTML="";
  if($("sel-np-default-action")) $("sel-np-default-action").value="";
  $("inp-np-proxy-uid").value="";$("inp-np-proxy-port").value="";$("inp-np-proxy-admin-port").value="";
  $("inp-np-req-cpu").value="";$("inp-np-req-mem").value="";$("inp-np-limit-cpu").value="";$("inp-np-limit-mem").value="";
  $("ta-selector-expr").value="";
  document.querySelector('input[name="scope"][value="namespace"]').checked=true;
  document.querySelector('input[name="tgt-mode"][value="name"]').checked=true;
  onTargetModeChange();
  hideEl($("create-msg"));
  _validatedOk=false;
  switchPolicyView("list");
  wizGoToStep(1);
}

// ── Deployments sidebar ──
async function loadDeployments(){
  setLoading("dep",true);hide("dep-empty");hide("dep-err");
  $("dep-list").innerHTML="";
  if($("sel-kind").value==="Deployment")
    $("sel-target").innerHTML="<option value=\"\">&#8212; select workload &#8212;</option>";
  try{
    var r=await api("/api/namespaces/"+ns()+"/deployments"),data=await r.json();
    setLoading("dep",false);
    if(!r.ok){showEl($("dep-err"),data.error||"Failed");return;}
    var deps=data.deployments||[];
    if(!deps.length){show("dep-empty");return;}
    deps.forEach(function(d){
      var card=document.createElement("div");
      card.style.cssText="background:#0f172a;border:1px solid #1e293b;border-radius:.75rem;padding:.625rem .75rem";
      var p=d.varmor_enabled;
      var badge=p?'<span class="badge badge-green">&#128737; Protected</span>'
                 :'<span class="badge badge-amber">&#9888; No Shield</span>';
      var abtn=isAdmin()
        ?(p?('<button class="btn btn-ghost btn-sm" onclick="openProtectModal(this)" data-name="'+esc(d.name)+'" data-ns="'+esc(ns())+'" data-already="1">&#x21BA; Restart</button>')
            :('<button class="btn btn-green btn-sm" onclick="openProtectModal(this)" data-name="'+esc(d.name)+'" data-ns="'+esc(ns())+'" data-already="0">+ Shield</button>'))
        :"";
      card.innerHTML='<div style="display:flex;align-items:center;justify-content:space-between;gap:.5rem">'
        +'<div style="min-width:0;flex:1"><p style="font-size:.875rem;font-weight:500;color:#f1f5f9;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(d.name)+'</p>'
        +'<p style="font-size:.75rem;color:#475569">'+d.ready_replicas+"/"+d.replicas+' replicas</p></div>'
        +'<div style="display:flex;align-items:center;gap:.375rem;flex-shrink:0">'+badge+abtn+'</div></div>';
      $("dep-list").appendChild(card);
      if($("sel-kind").value==="Deployment"){
        var opt=document.createElement("option");opt.value=d.name;opt.textContent=d.name;
        $("sel-target").appendChild(opt);
      }
    });
  }catch(err){setLoading("dep",false);showEl($("dep-err"),err.message);}
}

// ── Policies table ──
async function loadPolicies(){
  setLoading("pol",true);hide("pol-empty");hide("pol-err");$("pol-body").innerHTML="";allPolicies=[];
  try{
    var [r1,r2]=await Promise.allSettled([
      api("/api/namespaces/"+ns()+"/policies"),
      api("/api/cluster-policies"),
    ]);
    setLoading("pol",false);
    var combined=[];
    if(r1.status==="fulfilled"){var d1=await r1.value.json();if(r1.value.ok) combined=combined.concat(d1.policies||[]);}
    if(r2.status==="fulfilled"){var d2=await r2.value.json();if(r2.value.ok) combined=combined.concat(d2.policies||[]);}
    allPolicies=combined;
    renderPolicies(allPolicies);
  }catch(err){setLoading("pol",false);showEl($("pol-err"),err.message);}
}

function filterPolicies(){
  polPage=1;
  var q     = ($("inp-search")||{}).value||"";
  var scope = ($("fil-scope")||{}).value||"";
  var mode  = ($("fil-mode")||{}).value||"";
  var status= ($("fil-status")||{}).value||"";

  // Highlight active filters
  ["fil-scope","fil-mode","fil-status"].forEach(function(id){
    var el=$(id); if(!el) return;
    if(el.value) { el.style.borderColor="#3b82f6"; el.style.color="#93c5fd"; }
    else         { el.style.borderColor=""; el.style.color=""; }
  });

  var ql = q.toLowerCase();
  renderPolicies(allPolicies.filter(function(p){
    // Scope
    if(scope){
      var ps = p.scope||"namespace";
      if(ps !== scope) return false;
    }
    // Mode
    if(mode && p.mode !== mode) return false;
    // Status: Ready = green, Pending = amber, else = red (Error)
    if(status){
      var st = p.status||"Pending";
      if(status === "Ready"   && st !== "Ready")   return false;
      if(status === "Pending" && st !== "Pending") return false;
      if(status === "Error"   && (st === "Ready" || st === "Pending")) return false;
    }
    // Text search
    if(!ql) return true;
    var tgt = (p.target&&p.target.name)||"";
    return p.name.toLowerCase().includes(ql)
      || tgt.toLowerCase().includes(ql)
      || (p.mode||"").toLowerCase().includes(ql)
      || (p.scope||"").toLowerCase().includes(ql)
      || (p.enforcer||"").toLowerCase().includes(ql);
  }));
}

function polGoTo(page){
  var totalPages=Math.ceil(polFiltered.length/POL_PAGE_SIZE)||1;
  polPage=Math.max(1,Math.min(page,totalPages));
  _renderPoliciesPage();
}

function _renderPoliciesPage(){
  var pols=polFiltered;
  var totalPages=Math.ceil(pols.length/POL_PAGE_SIZE)||1;
  var start=(polPage-1)*POL_PAGE_SIZE;
  var pageItems=pols.slice(start,start+POL_PAGE_SIZE);

  $("pol-body").innerHTML="";
  if($("chk-all")) $("chk-all").checked=false;
  updateBatchBar();

  if(!pols.length){show("pol-empty");hide("pol-pagination");return;}
  hide("pol-empty");

  var cEdit=canEdit(),cDel=canDelete();
  pageItems.forEach(function(p){
    var rdy=p.status==="Ready";
    var isPending=p.status==="Pending";
    var statusMsg=p.status_message||"";
    var sbClass=rdy?"badge-green":isPending?"badge-amber":"badge-red";
    var sbIcon=rdy?"&#x25CF; ":isPending?"&#x23F3; ":"&#x26A0; ";
    var sbLabel=rdy?"Ready":esc(p.status||"Pending");
    var tooltipAttr=(!rdy&&statusMsg)?' title="'+esc(statusMsg)+'" style="cursor:help"':"";
    var sb='<span class="badge '+sbClass+'"'+tooltipAttr+'>'+sbIcon+sbLabel+'</span>';
    var phaseColors={Pending:"badge-amber",Modeling:"badge-purple",Completed:"badge-blue",
      Protecting:"badge-green",Error:"badge-red",Failed:"badge-red",Unknown:"badge-gray",Unchanged:"badge-gray"};
    var ph=p.phase||"";
    var phaseBadge=ph?('<span class="badge '+(phaseColors[ph]||"badge-gray")+'" title="phase" style="margin-left:2px;font-size:.6rem">'+esc(ph)+'</span>'):"";
    sb+=phaseBadge;
    var cr=p.created_at?new Date(p.created_at).toLocaleDateString("vi-VN"):"&#8212;";
    var isCluster=p.scope==="cluster";
    var scopeBadge=isCluster?'<span class="badge badge-purple">Cluster</span>':'<span class="badge badge-gray">NS</span>';
    var tgt=p.target||{};
    var tgtName=tgt.name?esc(tgt.name):(tgt.selector?'<span style="color:#64748b;font-size:.7rem">selector</span>':"&#8212;");
    var tgtKind=tgt.kind?('<div style="font-size:.7rem;color:#475569">'+esc(tgt.kind)+'</div>'):"";
    var enfs=(p.enforcer||"").split("|").filter(Boolean);
    var enfBadges=enfs.length?enfs.map(function(e){return'<span class="badge badge-blue" style="margin-right:2px">'+esc(e)+'</span>';}).join(""):'<span class="badge badge-gray">&#8212;</span>';
    var chkAttrs='data-name="'+esc(p.name)+'" data-ns="'+esc(p.namespace||"")+'" data-scope="'+esc(p.scope||"namespace")+'"';
    var chk=cDel?'<input type="checkbox" class="pol-chk" '+chkAttrs+' onchange="updateBatchBar()" style="accent-color:#3b82f6;width:1rem;height:1rem;cursor:pointer">':"";
    var editBtn=cEdit?'<button onclick="loadPolicyForEdit(this)" '+chkAttrs+' class="btn btn-ghost btn-sm" style="margin-right:2px" title="Edit">&#9998;</button>':"";
    var viewBtn='<button onclick="openDetailModal(this)" '+chkAttrs+' class="btn btn-ghost btn-sm" style="margin-right:2px">View</button>';
    var exportBtn='<button onclick="exportPolicy(this)" '+chkAttrs+' class="btn btn-ghost btn-sm" style="margin-right:2px" title="Export YAML">&#11123;</button>';
    var delBtn=cDel?'<button onclick="openDelModal(this)" '+chkAttrs+' class="btn btn-sm" style="border:1px solid #7f1d1d;color:#f87171;background:transparent">Del</button>':"";
    var tr=document.createElement("tr");
    tr.style.cssText="border-bottom:1px solid #1e293b;transition:background 100ms";
    tr.onmouseover=function(){tr.style.background="#243552";};
    tr.onmouseout=function(){tr.style.background="";};
    tr.innerHTML='<td class="td" style="width:2rem;text-align:center">'+chk+'</td>'
      +'<td class="td" style="font-family:monospace;color:#93c5fd;font-size:.75rem">'+esc(p.name)+'</td>'
      +'<td class="td">'+scopeBadge+'</td>'
      +'<td class="td" style="font-size:.8rem"><div style="color:#cbd5e1">'+tgtName+'</div>'+tgtKind+'</td>'
      +'<td class="td">'+modeColor(p.mode)+'</td>'
      +'<td class="td">'+enfBadges+'</td>'
      +'<td class="td">'+sb+'</td>'
      +'<td class="td" style="color:#475569;font-size:.75rem">'+cr+'</td>'
      +'<td class="td th-r" style="white-space:nowrap">'+editBtn+viewBtn+exportBtn+delBtn+'</td>';
    $("pol-body").appendChild(tr);
  });

  // Pagination controls
  var pagDiv=$("pol-pagination");
  if(pagDiv){
    if(totalPages<=1){pagDiv.classList.add("hidden");return;}
    pagDiv.classList.remove("hidden");
    var info=$("pol-page-info");
    if(info) info.textContent="Trang "+polPage+"/"+totalPages+" ("+pols.length+" policy)";
    var prev=$("pol-btn-prev"); if(prev) prev.disabled=(polPage<=1);
    var next=$("pol-btn-next"); if(next) next.disabled=(polPage>=totalPages);
    var nums=$("pol-page-nums");
    if(nums){
      nums.innerHTML="";
      var show5=Math.min(totalPages,5);
      var startP=Math.max(1,Math.min(polPage-2,totalPages-show5+1));
      for(var pg=startP;pg<startP+show5;pg++){
        (function(pg){
          var btn=document.createElement("button");
          btn.textContent=pg;
          btn.className="btn btn-ghost btn-sm";
          btn.style.cssText="padding:.2rem .55rem;min-height:0;min-width:1.8rem"+(pg===polPage?";background:#1e3a5f;color:#93c5fd":"");
          btn.onclick=function(){polGoTo(pg);};
          nums.appendChild(btn);
        })(pg);
      }
    }
  }
}

function renderPolicies(pols){
  polFiltered=pols;
  _renderPoliciesPage();
}

function modeColor(m){
  var c={EnhanceProtect:'<span class="badge badge-blue">'+esc(m)+'</span>',
    AlwaysAllow:'<span class="badge badge-amber">'+esc(m)+'</span>',
    RuntimeDefault:'<span class="badge badge-gray">'+esc(m)+'</span>',
    BehaviorModeling:'<span class="badge badge-purple">'+esc(m)+'</span>',
    DefenseInDepth:'<span class="badge badge-green">'+esc(m)+'</span>'};
  return c[m]||'<span class="badge badge-gray">'+(esc(m)||"&#8212;")+'</span>';
}

// ── Helpers ──
function $(id){return document.getElementById(id);}
function show(id){$(id).classList.remove("hidden");}
function hide(id){$(id).classList.add("hidden");}
function toggleVis(id,v){v?show(id):hide(id);}
function showEl(el,msg){el.textContent=msg;el.classList.remove("hidden");}
function hideEl(el){el.classList.add("hidden");}
function setLoading(p,on){on?show(p+"-loading"):hide(p+"-loading");}
function showMsg(el,type,text){
  el.textContent=text;
  var s={success:"background:#052e16;border:1px solid #166534;color:#86efac",
    error:"background:#450a0a;border:1px solid #7f1d1d;color:#fca5a5",
    warn:"background:#451a03;border:1px solid #9a3412;color:#fdba74"};
  el.style.cssText="padding:.75rem;border-radius:.5rem;font-size:.875rem;"+(s[type]||s.error);
  el.classList.remove("hidden");
  if(type!=="error")setTimeout(function(){hideEl(el);},9000);
}
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");}
