
// ── Form submit ──
$("form-create").addEventListener("submit",async function(e){
  e.preventDefault();
  var msgEl=$("create-msg"),progEl=$("create-progress");
  hideEl(msgEl);
  if(!canSubmit()){showMsg(msgEl,"error","Insufficient permissions to create or edit policies.");return;}
  if(!_validatedOk){showMsg(msgEl,"error","Please run Validate first — policy spec must pass validation before applying.");return;}
  var name=$("inp-pname").value.trim();
  var scope=document.querySelector('input[name="scope"]:checked').value;
  var kind=$("sel-kind").value;
  var tgtMode=document.querySelector('input[name="tgt-mode"]:checked').value;
  var mode=$("sel-mode").value;
  var namespace=ns();
  var autoR=$("chk-auto-restart").checked&&scope==="namespace"&&!editMode;
  if(!name){showMsg(msgEl,"error","Policy name is required.");return;}

  var targetDeployment="",targetSelector=null;
  if(tgtMode==="selector"){
    var selectorLines=$("ta-selector").value.split("\n").filter(Boolean);
    var matchLabels={};
    selectorLines.forEach(function(l){var p=l.split("=");if(p.length===2) matchLabels[p[0].trim()]=p[1].trim();});
    targetSelector={};
    if(Object.keys(matchLabels).length) targetSelector.matchLabels=matchLabels;
    var exprRaw=($("ta-selector-expr").value||"").trim();
    if(exprRaw){
      var expr=parseJsonArrayInput(exprRaw,"Match Expressions",msgEl);
      if(expr===null) return;
      targetSelector.matchExpressions=expr;
    }
    if(!targetSelector.matchLabels&&!targetSelector.matchExpressions){showMsg(msgEl,"error","Label selector requires matchLabels or matchExpressions.");return;}
  } else {
    targetDeployment=$("sel-target").value;
    if(!targetDeployment){showMsg(msgEl,"error","Please select a target workload.");return;}
  }

  var enforcers=Array.from(document.querySelectorAll('input[name="enforcer"]:checked')).map(function(c){return c.value;});
  if(!enforcers.length){showMsg(msgEl,"error","Select at least one enforcer.");return;}
  if(mode==="BehaviorModeling"&&enforcers.includes("NetworkProxy")){showMsg(msgEl,"error","BehaviorModeling does not support NetworkProxy enforcer.");return;}
  if(mode==="DefenseInDepth"&&enforcers.includes("BPF")){showMsg(msgEl,"error","DefenseInDepth does not support BPF enforcer.");return;}
  var rules=Array.from(document.querySelectorAll('input[name="rule"]:checked')).map(function(c){return c.value;});
  var capabilityRules=$("ta-dynamic-caps").value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var banned=$("ta-banned").value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var apparmorRaw=collectRawRuleInput("ta-apparmor-raw","AppArmor Raw Rules",msgEl);
  if(apparmorRaw===null) return;
  var attackTargets=[];  // deprecated; replaced by attack_protection_groups
  var attackGroups=collectAttackGroups();
  var bpfFileRules=collectBpfRules("bpf-files");
  var bpfProcRules=collectBpfRules("bpf-procs");
  var bpfMountRules=collectMountRules();
  var bpfPtraceRule=collectPtraceRule();
  var bpfNetworkStr=($("ta-bpf-network").value||"").trim();
  var bpfNetwork=null;
  if(bpfNetworkStr){try{bpfNetwork=JSON.parse(bpfNetworkStr);}catch(e){showMsg(msgEl,"error","BPF Network Rules: invalid JSON — "+e.message);return;}}
  var seccompSyscalls=$("ta-seccomp").value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var seccompAction=$("sel-seccomp-action").value;
  var seccompRaw=parseJsonArrayInput($("ta-seccomp-raw").value,"Seccomp LinuxSyscall JSON",msgEl);
  if(seccompRaw===null) return;
  var containers=$("inp-containers").value.split(",").map(function(c){return c.trim();}).filter(Boolean);
  var durationMins=parseInt($("inp-duration").value)||60;
  var updateExisting=$("chk-update-existing").checked;
  var auditViol=$("chk-audit-viol").checked;
  var allowViol=$("chk-allow-viol").checked;
  var privileged=$("chk-privileged").checked;

  // DefenseInDepth fields
  var didAaTypeEl=document.querySelector('input[name="did-aa-type"]:checked');
  var didAaType=didAaTypeEl?didAaTypeEl.value:"";
  var didAaCustom=$("ta-did-aa-custom").value.trim();
  var didAaRaw=$("ta-did-aa-raw").value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var didScTypeEl=document.querySelector('input[name="did-sc-type"]:checked');
  var didScType=didScTypeEl?didScTypeEl.value:"";
  var didScCustom=$("ta-did-sc-custom").value.trim();
  var didScSyscalls=$("ta-did-sc-syscalls").value.split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var didScRaw=parseJsonArrayInput($("ta-did-sc-raw").value,"DID Seccomp LinuxSyscall JSON",msgEl);
  if(didScRaw===null) return;
  var didScAction=$("sel-did-sc-action").value;
  var didAllowViol=$("did-allow-viol").checked;
  var didNpEgressStr=($("ta-did-np-egress").value||"").trim();
  var didNpEgress=null;
  if(didNpEgressStr){try{didNpEgress=JSON.parse(didNpEgressStr);}catch(e){showMsg(msgEl,"error","DID NetworkProxy Egress: invalid JSON — "+e.message);return;}}

  // NetworkProxy MITM config fields
  var npMitmDomains=($("ta-np-mitm-domains").value||"").split("\n").map(function(l){return l.trim();}).filter(Boolean);
  var npMitmMut,npEgress;
  try{npMitmMut=collectNpHeaders();}catch(ex){showMsg(msgEl,"error","NetworkProxy Header Mutations: "+ex.message);return;}
  try{npEgress=collectNpEgress();}catch(ex){showMsg(msgEl,"error","NetworkProxy Egress: "+ex.message);return;}
  var npProxyUid=$("inp-np-proxy-uid").value?parseInt($("inp-np-proxy-uid").value):null;
  var npProxyPort=$("inp-np-proxy-port").value?parseInt($("inp-np-proxy-port").value):null;
  var npProxyAdminPort=$("inp-np-proxy-admin-port").value?parseInt($("inp-np-proxy-admin-port").value):null;
  var npResources=collectNpResources();

  if(mode==="EnhanceProtect"&&!rules.length&&!capabilityRules.length&&!banned.length&&!apparmorRaw.length&&!bpfFileRules.length&&!bpfProcRules.length&&!bpfMountRules.length&&!bpfPtraceRule&&!bpfNetwork&&!seccompSyscalls.length&&!seccompRaw.length&&!npEgress){
    showMsg(msgEl,"error","EnhanceProtect requires at least one rule, banned file, or raw rule.");return;
  }

  progEl.classList.remove("hidden");
  setStep("policy","spin");setStep("restart","wait");
  var btn=$("btn-apply-direct");btn.disabled=true;

  var payload={
    name:name,namespace:namespace,scope:scope,target_kind:kind,
    target_deployment:targetDeployment,target_selector:targetSelector,
    target_containers:containers,mode:mode,enforcers:enforcers,
    rules:rules,capability_rules:capabilityRules,banned_files:banned,
    apparmor_raw_rules:apparmorRaw,
    attack_protection_groups:attackGroups,
    unconfined_containers:collectUnconfinedContainers(),
    privileged:privileged,
    bpf_file_rules:bpfFileRules,bpf_process_rules:bpfProcRules,
    bpf_mounts:bpfMountRules,bpf_ptrace:bpfPtraceRule,bpf_network:bpfNetwork,
    seccomp_syscalls:seccompSyscalls,seccomp_action:seccompAction,seccomp_raw_rules:seccompRaw,
    modeling_duration:durationMins*60,
    update_existing_workloads:updateExisting,audit_violations:auditViol,allow_violations:allowViol,
    did_apparmor_type:didAaType,did_apparmor_custom:didAaCustom,did_apparmor_raw_rules:didAaRaw,
    did_seccomp_type:didScType,did_seccomp_custom:didScCustom,
    did_seccomp_syscalls:didScSyscalls,did_seccomp_action:didScAction,did_seccomp_raw_rules:didScRaw,
    did_allow_violations:didAllowViol,did_np_egress:didNpEgress,
    np_mitm_domains:npMitmDomains,np_mitm_mutations:npMitmMut,np_egress:npEgress,
    np_proxy_uid:npProxyUid,np_proxy_port:npProxyPort,np_proxy_admin_port:npProxyAdminPort,
    np_resources:npResources
  };

  try{
    var method,path;
    if(editMode){
      method="PUT";
      path=editMode.scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(editMode.name)
        :"/api/namespaces/"+editMode.ns+"/policies/"+encodeURIComponent(editMode.name);
    }else{
      method="POST";path="/api/policies";
    }
    var res=await api(path,{method:method,body:JSON.stringify(payload)});
    var data=await res.json();
    if(!res.ok){setStep("policy","fail");progEl.classList.add("hidden");showMsg(msgEl,"error",data.error||"Failed");btn.disabled=false;return;}
    setStep("policy","done");

    if(autoR&&kind==="Deployment"&&targetDeployment){
      setStep("restart","spin");await sleep(2000);
      try{
        var r2=await api("/api/namespaces/"+namespace+"/deployments/"+encodeURIComponent(targetDeployment)+"/protect",{method:"PUT",body:JSON.stringify({enable:true})});
        var d2=await r2.json();
        if(r2.ok){setStep("restart","done");await sleep(600);progEl.classList.add("hidden");showMsg(msgEl,"success","Policy created. Deployment \""+targetDeployment+"\" restarted.");}
        else{setStep("restart","fail");progEl.classList.add("hidden");showMsg(msgEl,"warn","Policy created &#8212; restart failed: "+(d2.error||"unknown"));}
      }catch(e2){setStep("restart","fail");progEl.classList.add("hidden");showMsg(msgEl,"warn","Policy created &#8212; restart error: "+e2.message);}
    }else{
      setStep("restart","skip");await sleep(300);progEl.classList.add("hidden");
      var okMsg=editMode?("Policy \""+name+"\" updated successfully."):"Policy \""+name+"\" applied successfully.";
      var hasAppArmor=enforcers.indexOf("AppArmor")>=0;
      if(hasAppArmor&&!editMode){okMsg+=" AppArmor enforcement applies to new/restarted pods — restart the target deployment to enforce immediately.";}
      showMsg(msgEl,"success",okMsg);
    }
    setTimeout(function(){cancelEdit();loadAll();},1500);
  }catch(err){setStep("policy","fail");progEl.classList.add("hidden");showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
});

function setStep(s,state){
  var row=$("step-"+s),icon=$("icon-"+s);
  var C={done:"#4ade80",fail:"#f87171",spin:"#60a5fa",wait:"#64748b",skip:"#475569"};
  var I={done:"✓",fail:"✗",spin:"⟳",wait:"○",skip:"—"};
  row.style.color=C[state]||C.wait;icon.textContent=I[state]||"○";
}
function sleep(ms){return new Promise(function(r){setTimeout(r,ms);});}

function toggleGroup(id){
  var body=$(id),arr=$("arr-"+id.replace("grp-",""));
  var h=body.classList.contains("hidden");
  if(h){body.classList.remove("hidden");arr.textContent="▼";}else{body.classList.add("hidden");arr.textContent="►";}
}

function toggleSection(contentId,arrId){
  var body=$(contentId),arr=$(arrId);
  var h=body.classList.contains("hidden");
  if(h){body.classList.remove("hidden");arr.textContent="▼";}else{body.classList.add("hidden");arr.textContent="►";}
}

function updateRuleCounts(){
  ["hardening","attack","vuln"].forEach(function(g){
    var n=document.querySelectorAll('#grp-'+g+' input[type="checkbox"]:checked').length;
    var el=$("cnt-"+g);if(el) el.textContent=n?("("+n+" selected)"):"";
  });
  updateRuleSummary();
}

// ── Delete modal ──
function openDelModal(el){
  if(!canDelete()){alert("Insufficient permissions to delete policies.");return;}
  pendingDel={name:el.dataset.name,ns:el.dataset.ns,scope:el.dataset.scope||"namespace"};
  $("del-pname").textContent=(pendingDel.scope==="cluster"?"[cluster] ":"")+pendingDel.name;
  show("modal-del");
}
function closeDelModal(){pendingDel={name:null,ns:null,scope:null};hide("modal-del");}
$("btn-del-confirm").addEventListener("click",async function(){
  if(!canDelete()){alert("Insufficient permissions to delete policies.");return;}
  var name=pendingDel.name,namespace=pendingDel.ns,scope=pendingDel.scope;
  if(!name) return;
  closeDelModal();
  try{
    var path=scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(name)
      :"/api/namespaces/"+namespace+"/policies/"+encodeURIComponent(name);
    var res=await api(path,{method:"DELETE"});
    var data=await res.json();
    if(!res.ok){alert("Delete failed: "+(data.error||"unknown"));return;}
    setTimeout(loadAll,600);
  }catch(err){alert("Error: "+err.message);}
});
$("modal-del").addEventListener("click",function(e){if(e.target===$("modal-del"))closeDelModal();});

// ── Protect modal ──
function openProtectModal(el){
  if(!isAdmin()){alert("Viewer role cannot restart workloads.");return;}
  var name=el.dataset.name,namespace=el.dataset.ns,already=el.dataset.already==="1";
  pendingProtect={name:name,ns:namespace};
  $("protect-dname").textContent=name;
  $("protect-title").textContent=already?"Restart Deployment":"Enable Protection";
  var btn=$("btn-protect-confirm");
  btn.textContent=already?"↺ Restart Pods":"Enable & Restart";
  btn.style.background=already?"#1d4ed8":"#0284c7";
  hide("protect-msg");show("modal-protect");
}
function closeProtectModal(){pendingProtect={name:null,ns:null};hide("modal-protect");}
$("btn-protect-confirm").addEventListener("click",async function(){
  if(!isAdmin()){alert("Viewer role cannot restart workloads.");return;}
  var name=pendingProtect.name,namespace=pendingProtect.ns;if(!name||!namespace) return;
  var btn=$("btn-protect-confirm");btn.disabled=true;
  var msgEl=$("protect-msg");hideEl(msgEl);
  try{
    var res=await api("/api/namespaces/"+namespace+"/deployments/"+encodeURIComponent(name)+"/protect",{method:"PUT",body:JSON.stringify({enable:true})});
    var data=await res.json();
    if(res.ok){showMsg(msgEl,"success",data.message||"Done.");setTimeout(function(){closeProtectModal();loadDeployments();},1500);}
    else{showMsg(msgEl,"error",data.error||"Failed.");}
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
});
$("modal-protect").addEventListener("click",function(e){if(e.target===$("modal-protect"))closeProtectModal();});

// ── Detail modal (Policy) ──
async function openDetailModal(el){
  var name=el.dataset.name,namespace=el.dataset.ns,scope=el.dataset.scope||"namespace";
  $("detail-name").textContent=(scope==="cluster"?"cluster / ":namespace+" / ")+name;
  show("detail-loading");hide("detail-err");hide("detail-body");$("detail-body").textContent="";
  show("modal-detail");
  try{
    var path=scope==="cluster"?"/api/cluster-policies/"+encodeURIComponent(name)
      :"/api/namespaces/"+namespace+"/policies/"+encodeURIComponent(name);
    var res=await api(path);var data=await res.json();
    hide("detail-loading");
    if(!res.ok){showEl($("detail-err"),data.error||"Failed.");return;}
    $("detail-body").textContent=JSON.stringify(data,null,2);show("detail-body");
  }catch(err){hide("detail-loading");showEl($("detail-err"),err.message);}
}
function closeDetailModal(){hide("modal-detail");}
$("modal-detail").addEventListener("click",function(e){if(e.target===$("modal-detail"))closeDetailModal();});

// ── Model detail modal (ArmorProfileModel) ──
async function openModelModal(el){
  var name=el.dataset.name,namespace=el.dataset.ns;
  $("model-detail-name").textContent=namespace+" / "+name;
  show("model-detail-loading");hide("model-detail-err");hide("model-detail-body");$("model-detail-body").textContent="";
  show("modal-model");
  try{
    var res=await api("/api/namespaces/"+namespace+"/profile-models/"+encodeURIComponent(name));
    var data=await res.json();
    hide("model-detail-loading");
    if(!res.ok){showEl($("model-detail-err"),data.error||"Failed.");return;}
    $("model-detail-body").textContent=JSON.stringify(data,null,2);show("model-detail-body");
  }catch(err){hide("model-detail-loading");showEl($("model-detail-err"),err.message);}
}
function closeModelModal(){hide("modal-model");}
$("modal-model").addEventListener("click",function(e){if(e.target===$("modal-model"))closeModelModal();});

// ── User management ──
