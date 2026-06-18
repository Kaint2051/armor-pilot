
// ── User management helpers ──
function relTime(iso){
  if(!iso) return null;
  var sec=Math.floor((Date.now()-new Date(iso).getTime())/1000);
  if(sec<60) return "just now";
  var m=Math.floor(sec/60);if(m<60) return m+"m ago";
  var h=Math.floor(m/60);if(h<24) return h+"h ago";
  var d=Math.floor(h/24);if(d<7) return d+"d ago";
  if(d<30) return Math.floor(d/7)+"w ago";
  if(d<365) return Math.floor(d/30)+"mo ago";
  return Math.floor(d/365)+"y ago";
}

var _allUsers=[];

// ── Access Control sub-views ──
var _rolesData=[];      // cache from /api/roles
var _allPermsData=[];   // cache from /api/roles all_permissions
var _editingRole=null;  // null = create, string = role name being edited

function switchAcView(view){
  ["users","roles","matrix","license"].forEach(function(v){
    var el=$("acv-"+v);if(el)el.classList[v===view?"remove":"add"]("hidden");
    var btn=$("acnav-"+v);
    if(btn){
      if(v===view){btn.style.background="#334155";btn.style.color="#f1f5f9";}
      else{btn.style.background="";btn.style.color="#94a3b8";}
    }
  });
  if(view==="roles") loadRoles();
  if(view==="matrix") loadRolesForMatrix();
  if(view==="license") loadLicenseStatus();
}

function _licenseBadgeClass(status){
  if(!status) return "badge-gray";
  if(status.violations&&status.violations.length) return "badge-red";
  if(status.valid) return (status.in_grace||(status.warnings&&status.warnings.length))?"badge-amber":"badge-green";
  if(status.required&&!status.fail_open) return "badge-red";
  return "badge-amber";
}

function _renderHeaderLicense(status){
  var badge=$("license-badge");if(!badge)return;
  if(!hasPerm("license:view")){badge.classList.add("hidden");return;}
  var text="License";
  if(status){
    if(status.status==="limit_exceeded"){
      text="License limit";
    }else if(status.valid){
      var p=status.payload||{};
      text=(p.edition||"licensed")+" / "+(status.days_remaining!=null?status.days_remaining+"d":"valid");
    }else if(status.status==="missing"){
      text=status.required?"No license":"Dev mode";
    }else{
      text=status.required?"Invalid license":"License warning";
    }
  }
  badge.textContent=text;
  badge.className="badge "+_licenseBadgeClass(status);
}

function _licenseStatusRows(status){
  var p=status.payload||{};
  var product=status.product||{};
  var usage=status.usage||{};
  var installation=status.installation||{};
  var rows=[
    ["Product edition",product.effective_edition||"community"],
    ["Status",status.status||"unknown"],
    ["Compliant",status.compliant===false?"no":"yes"],
    ["Installation ID",installation.installation_id||"unavailable"],
    ["Bound license",p.installation_id?(p.installation_id===installation.installation_id?"yes":"mismatch"):"no"],
    ["Cluster UID",usage.cluster_uid||p.cluster_uid||"n/a"],
    ["Nodes",usage.nodes==null?"n/a":String(usage.nodes)],
    ["Policies",usage.policies==null?"n/a":String(usage.policies)],
    ["Required",status.required?"yes":"no"],
    ["Fail open",status.fail_open?"yes":"no"],
    ["Customer",p.customer||"—"],
    ["Edition",p.edition||"—"],
    ["Expires",p.expires_at||"—"],
    ["Days remaining",status.days_remaining==null?"—":String(status.days_remaining)],
    ["License ID",p.license_id||"—"],
    ["Path",status.path||"—"],
    ["Reason",status.reason||"—"]
  ];
  return rows.map(function(r){
    return '<div class="p-3 rounded-lg" style="background:#0f172a;border:1px solid #334155">'
      +'<div class="text-xs uppercase font-semibold mb-1" style="color:#475569;letter-spacing:.06em">'+esc(r[0])+'</div>'
      +'<div class="font-mono text-xs break-all" style="color:#cbd5e1">'+esc(r[1])+'</div>'
      +'</div>';
  }).join("");
}

function renderLicenseStatus(status){
  CURRENT_LICENSE=status;
  _renderHeaderLicense(status);
  var card=$("license-status-card");
  if(card) card.innerHTML=_licenseStatusRows(status);
  var feats=$("license-feature-list");
  if(feats){
    var p=status.payload||{};
    var features=status.effective_features||[];
    var limits=p.limits||{};
    var usage=status.usage||{};
    var limitStatus=status.limit_status||{};
    var warnings=status.warnings||[];
    var violations=status.violations||[];
    var warnHtml=warnings.length?'<div class="mb-3 p-2 rounded" style="background:#1c1200;border:1px solid #713f12;color:#fde68a">'+warnings.map(esc).join('<br>')+'</div>':'';
    var violHtml=violations.length?'<div class="mb-3 p-2 rounded" style="background:#450a0a;border:1px solid #7f1d1d;color:#fca5a5">'+violations.map(esc).join('<br>')+'</div>':'';
    feats.innerHTML=violHtml+warnHtml
      +'<div class="font-semibold mb-2" style="color:#cbd5e1">Effective Features</div>'
      +'<div class="flex flex-wrap gap-1 mb-3">'+(features.length?features.map(function(f){return '<span class="badge badge-blue">'+esc(f)+'</span>';}).join(""):'<span style="color:#64748b">No licensed features</span>')+'</div>'
      +'<div class="font-semibold mb-2" style="color:#cbd5e1">Runtime Usage</div>'
      +'<pre style="white-space:pre-wrap;font-family:monospace;color:#94a3b8">'+esc(JSON.stringify(usage,null,2))+'</pre>'
      +'<div class="font-semibold mb-2" style="color:#cbd5e1">Limits</div>'
      +'<pre style="white-space:pre-wrap;font-family:monospace;color:#94a3b8">'+esc(JSON.stringify({configured:limits,status:limitStatus},null,2))+'</pre>';
  }
  var btn=$("btn-save-license");
  if(btn) btn.classList.toggle("hidden",!hasPerm("license:manage"));
  var rmBtn=$("btn-remove-license");
  if(rmBtn) rmBtn.classList.toggle("hidden", !hasPerm("license:manage")||!status.valid);
  var ta=$("ta-license-json");
  if(ta) ta.disabled=!hasPerm("license:manage");
  var reqBtn=$("btn-download-activation-request");
  if(reqBtn) reqBtn.disabled=!(status.installation&&status.installation.available);
  var copyBtn=$("btn-copy-installation-id");
  if(copyBtn) copyBtn.disabled=!(status.installation&&status.installation.installation_id);
}

function arToggleCustomDays(){
  var sel=$("ar-req-duration");
  var row=$("ar-custom-days-row");
  if(sel&&row) row.classList.toggle("hidden", sel.value!=="custom");
}

function downloadActivationRequest(){
  [
    "ar-contact-name","ar-contact-company","ar-tax-id","ar-contact-email",
    "ar-contact-phone","ar-country","ar-address","ar-contact-notes",
    "ar-req-custom-days","ar-existing-license-id","ar-quote-reference"
  ].forEach(function(id){
    var el=$(id); if(el) el.value="";
  });
  var rt=$("ar-request-type");     if(rt) rt.value="new";
  var ed=$("ar-req-edition");     if(ed) ed.value="professional";
  var dur=$("ar-req-duration");   if(dur) dur.value="365";
  var mn=$("ar-req-max-nodes");   if(mn) mn.value="10";
  var mp=$("ar-req-max-policies");if(mp) mp.value="500";
  var row=$("ar-custom-days-row");if(row) row.classList.add("hidden");
  var errEl=$("ar-error-msg"); if(errEl) errEl.classList.add("hidden");
  var btn=$("btn-ar-confirm"); if(btn){btn.disabled=false;btn.textContent="Tai xuong";}
  show("modal-activation-request");
  setTimeout(function(){var n=$("ar-contact-name");if(n)n.focus();},80);
}

function closeActivationRequestModal(){
  hide("modal-activation-request");
}

async function confirmDownloadActivationRequest(){
  var errEl=$("ar-error-msg");
  hideEl(errEl);

  var name   =($("ar-contact-name")||{}).value||"";
  var company=($("ar-contact-company")||{}).value||"";
  var taxId  =($("ar-tax-id")||{}).value||"";
  var email  =($("ar-contact-email")||{}).value||"";
  var phone  =($("ar-contact-phone")||{}).value||"";
  var country=($("ar-country")||{}).value||"";
  var address=($("ar-address")||{}).value||"";
  var notes  =($("ar-contact-notes")||{}).value||"";
  var requestType=($("ar-request-type")||{}).value||"new";
  var edition=($("ar-req-edition")||{}).value||"professional";
  var durSel =($("ar-req-duration")||{}).value||"365";
  var days   =durSel==="custom"?parseInt(($("ar-req-custom-days")||{}).value||"0",10):parseInt(durSel,10);
  var maxNodes   =parseInt(($("ar-req-max-nodes")||{}).value||"0",10);
  var maxPolicies=parseInt(($("ar-req-max-policies")||{}).value||"0",10);
  var existingLicenseId=($("ar-existing-license-id")||{}).value||"";
  var quoteReference=($("ar-quote-reference")||{}).value||"";

  if(!name.trim()||!company.trim()||!email.trim()){
    showEl(errEl,"Complete all required customer fields.");
    return;
  }
  var emailRe=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!emailRe.test(email.trim())){
    showEl(errEl,"Enter a valid contact email address.");
    return;
  }
  if(!days||days<1){
    showEl(errEl,"Enter a valid license term.");
    return;
  }
  if(!maxNodes||maxNodes<1||!maxPolicies||maxPolicies<1){
    showEl(errEl,"Requested nodes and policies must be greater than zero.");
    return;
  }
  if(["renewal","rehost","replacement"].indexOf(requestType)>=0&&!existingLicenseId.trim()){
    showEl(errEl,"Existing License ID is required for renewal, rehost, or replacement requests.");
    return;
  }

  var btn=$("btn-ar-confirm");
  if(btn){btn.disabled=true;btn.textContent="Creating...";}
  try{
    var customerRequest={
      request_type:requestType,
      organization_name:company.trim(),
      tax_id:taxId.trim(),
      contact_name:name.trim(),
      contact_email:email.trim(),
      contact_phone:phone.trim(),
      country:country.trim(),
      address:address.trim(),
      requested_edition:edition,
      requested_days:days,
      requested_nodes:maxNodes,
      requested_policies:maxPolicies,
      existing_license_id:existingLicenseId.trim(),
      quote_reference:quoteReference.trim(),
      notes:notes.trim()
    };
    var r=await api("/api/license/activation-request",{
      method:"POST",
      body:JSON.stringify({customer_request:customerRequest})
    }),data=await r.json();
    if(!r.ok) throw new Error(data.error||"Failed to create activation request");

    var blob=new Blob([JSON.stringify(data,null,2)+"\n"],{type:"application/json"});
    var url=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=url;
    a.download="varmor-activation-request.json";
    document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
    closeActivationRequestModal();
  }catch(e){
    showEl(errEl,e.message||"Failed to create activation request.");
  }finally{
    if(btn){btn.disabled=false;btn.textContent="Download Request";}
  }
}

async function copyInstallationId(){
  var id=((CURRENT_LICENSE||{}).installation||{}).installation_id||"";
  if(!id){alert("Installation ID is unavailable.");return;}
  try{await navigator.clipboard.writeText(id);}
  catch(e){
    var ta=document.createElement("textarea");ta.value=id;document.body.appendChild(ta);
    ta.select();document.execCommand("copy");ta.remove();
  }
}

async function loadLicenseStatus(){
  if(!hasPerm("license:view")) return;
  try{
    var r=await api("/api/license"),data=await r.json();
    if(!r.ok) throw new Error(data.error||"Failed to load license");
    renderLicenseStatus(data);
  }catch(e){
    if(CURRENT_LICENSE) _renderHeaderLicense(CURRENT_LICENSE);
    var card=$("license-status-card");
    if(card) card.innerHTML='<div class="p-3 rounded-lg text-sm" style="background:#450a0a;border:1px solid #7f1d1d;color:#fca5a5">'+esc(e.message)+'</div>';
  }
}

async function saveLicense(){
  if(!hasPerm("license:manage")){alert("Insufficient permissions to manage license.");return;}
  var msg=$("license-msg");hideEl(msg);
  var raw=($("ta-license-json")||{}).value||"";
  if(!raw.trim()){
    msg.style.background="#450a0a";msg.style.border="1px solid #7f1d1d";msg.style.color="#fca5a5";
    showEl(msg,"License key is required.");return;
  }
  var btn=$("btn-save-license");btn.disabled=true;btn.textContent="Saving...";
  try{
    var r=await api("/api/license",{method:"POST",body:JSON.stringify({license:raw})});
    var data=await r.json();
    if(!r.ok){
      msg.style.background="#450a0a";msg.style.border="1px solid #7f1d1d";msg.style.color="#fca5a5";
      showEl(msg,data.error||"Failed to save license");return;
    }
    msg.style.background="#052e16";msg.style.border="1px solid #166534";msg.style.color="#86efac";
    showEl(msg,"License saved and verified.");
    renderLicenseStatus(data);
    loadPolicyTemplates(true);
  }catch(e){msg.style.background="#450a0a";msg.style.border="1px solid #7f1d1d";msg.style.color="#fca5a5";showEl(msg,e.message);}
  finally{btn.disabled=false;btn.textContent="Save License";}
}

async function removeLicense(){
  if(!hasPerm("license:manage")){alert("Insufficient permissions.");return;}
  if(!confirm("Xac nhan xoa license hien tai?\nHe thong se chuyen sang trang thai chua co license.")) return;
  var msg=$("license-msg"); hideEl(msg);
  var btn=$("btn-remove-license"); if(btn){btn.disabled=true;btn.textContent="Removing...";}
  try{
    var r=await api("/api/license",{method:"DELETE"});
    var data=await r.json();
    if(!r.ok){
      msg.style.background="#450a0a";msg.style.border="1px solid #7f1d1d";msg.style.color="#fca5a5";
      showEl(msg,data.error||"Failed to remove license");return;
    }
    msg.style.background="#1c1917";msg.style.border="1px solid #44403c";msg.style.color="#d6d3d1";
    showEl(msg,"License da duoc xoa.");
    var ta=$("ta-license-json"); if(ta) ta.value="";
    loadLicenseStatus();
  }catch(e){
    msg.style.background="#450a0a";msg.style.border="1px solid #7f1d1d";msg.style.color="#fca5a5";
    showEl(msg,e.message);
  }finally{
    if(btn){btn.disabled=false;btn.textContent="Remove License";}
  }
}

async function loadRoles(){
  var grid=$("roles-grid");if(!grid)return;
  grid.innerHTML='<div class="text-sm" style="color:#475569">Loading…</div>';
  try{
    var r=await api("/api/roles"),data=await r.json();
    if(!r.ok){grid.innerHTML='<div class="text-sm" style="color:#f87171">'+( data.error||"Failed")+'</div>';return;}
    _rolesData=data.roles||[];
    _allPermsData=data.all_permissions||[];
    if(hasPerm("users:view")){show("btn-new-role");}else{hide("btn-new-role");}
    renderRolesGrid(_rolesData);
  }catch(e){grid.innerHTML='<div class="text-sm" style="color:#f87171">'+e.message+'</div>';}
}

function _permGroupHtml(perms,color){
  var groups={};
  perms.forEach(function(p){var pts=p.split(":");var m=pts[0],a=pts[1];if(!groups[m])groups[m]=[];groups[m].push(a);});
  var h="";
  Object.keys(groups).sort().forEach(function(mod){
    h+='<div class="mb-1.5"><div class="text-xs font-semibold uppercase mb-0.5" style="color:'+color+'55;letter-spacing:.06em">'+mod+'</div>';
    groups[mod].forEach(function(act){h+='<div class="text-xs py-px" style="color:#94a3b8"><span style="color:'+color+'">&#10003;</span> '+act+'</div>';});
    h+='</div>';
  });
  return h||'<span class="text-xs" style="color:#475569">No permissions</span>';
}

function renderRolesGrid(roles){
  var grid=$("roles-grid");if(!grid)return;
  var builtinColors={admin:"#60a5fa",operator:"#fbbf24",viewer:"#94a3b8"};
  var builtinBorders={admin:"#1e3a5f",operator:"#78350f33",viewer:"transparent"};
  var html="";
  roles.forEach(function(role){
    var color=builtinColors[role.name]||"#a78bfa";
    var border=builtinBorders[role.name]||"#312e81";
    var perms=role.permissions||[];
    var editBtn=(!role.builtin&&hasPerm("users:view"))
      ?'<button onclick="openRoleModal(\''+role.name+'\')" class="btn btn-ghost btn-sm text-xs" style="color:#a78bfa">Edit</button>'
      :'';
    var delBtn=(!role.builtin&&hasPerm("users:delete"))
      ?'<button onclick="deleteRole(\''+role.name+'\')" class="btn btn-ghost btn-sm text-xs" style="color:#f87171">Delete</button>'
      :'';
    html+='<div class="card flex flex-col" style="border-color:'+border+'">';
    html+='<div class="flex items-start justify-between gap-2 mb-1">';
    html+='<div><span class="badge text-sm px-3 py-1" style="background:'+color+'22;color:'+color+'">'+role.name+'</span>';
    if(!role.builtin)html+=' <span class="text-xs ml-1" style="color:#6366f1;background:#312e81;padding:1px 6px;border-radius:4px">custom</span>';
    html+='</div>';
    html+='<div class="flex gap-1">'+editBtn+delBtn+'</div>';
    html+='</div>';
    if(role.description)html+='<p class="text-xs mb-3" style="color:#64748b">'+role.description+'</p>';
    html+='<div class="text-xs mb-2" style="color:#475569">'+perms.length+' permission'+(perms.length!==1?'s':'')+(role.user_count!=null?' · '+role.user_count+' user'+(role.user_count!==1?'s':''):'')+' </div>';
    html+='<div class="flex-1 overflow-y-auto" style="max-height:220px">'+_permGroupHtml(perms,color)+'</div>';
    html+='</div>';
  });
  grid.innerHTML=html||'<div class="text-sm" style="color:#475569">No roles defined.</div>';
}

async function loadRolesForMatrix(){
  if(_rolesData.length===0){
    var r=await api("/api/roles"),data=await r.json();
    if(!r.ok)return;
    _rolesData=data.roles||[];_allPermsData=data.all_permissions||[];
  }
  renderPermMatrix(_rolesData,_allPermsData);
}

function renderPermMatrix(roles,allPerms){
  var body=$("perm-matrix-body");if(!body)return;
  // Rebuild thead to include custom role columns
  var thead=body.closest("table").querySelector("thead tr");
  // rebuild header: first 4 cols fixed, append custom roles
  thead.innerHTML='<th class="text-left py-2 pr-4 font-semibold" style="color:#94a3b8;min-width:200px">Permission</th>'
    +'<th class="text-center py-2 px-3 font-semibold" style="color:#94a3b8">viewer</th>'
    +'<th class="text-center py-2 px-3 font-semibold" style="color:#fbbf24">operator</th>'
    +'<th class="text-center py-2 px-3 font-semibold" style="color:#60a5fa">admin</th>';
  var customRoles=roles.filter(function(r){return !r.builtin;});
  customRoles.forEach(function(r){
    thead.innerHTML+='<th class="text-center py-2 px-3 font-semibold" style="color:#a78bfa">'+r.name+'</th>';
  });

  var rolePermMap={};
  roles.forEach(function(r){var s=new Set(r.permissions||[]);rolePermMap[r.name]=s;});

  var lastMod="",html="";
  allPerms.forEach(function(perm){
    var pts=perm.split(":");var mod=pts[0],act=pts[1];
    if(mod!==lastMod){
      var cols=4+customRoles.length;
      html+='<tr><td colspan="'+cols+'" class="pt-3 pb-1 text-xs font-bold uppercase tracking-wider" style="color:#475569">'+mod+'</td></tr>';
      lastMod=mod;
    }
    html+='<tr style="border-bottom:1px solid #0f172a">';
    html+='<td class="py-1.5 pr-4 text-xs font-mono" style="color:#cbd5e1">'+act+'</td>';
    ["viewer","operator","admin"].forEach(function(rn){
      var has=rolePermMap[rn]&&rolePermMap[rn].has(perm);
      html+='<td class="text-center py-1.5 text-sm">'+(has?'<span style="color:#22c55e">&#10003;</span>':'<span style="color:#334155">—</span>')+'</td>';
    });
    customRoles.forEach(function(r){
      var has=rolePermMap[r.name]&&rolePermMap[r.name].has(perm);
      html+='<td class="text-center py-1.5 text-sm">'+(has?'<span style="color:#22c55e">&#10003;</span>':'<span style="color:#334155">—</span>')+'</td>';
    });
    html+='</tr>';
  });
  body.innerHTML=html;
}

// ── Role create/edit modal ──
function openRoleModal(roleName){
  _editingRole=roleName;
  var isEdit=!!roleName;
  $("role-modal-title").textContent=isEdit?"Edit Role: "+roleName:"New Role";
  $("inp-role-name").value=roleName||"";
  $("inp-role-name").disabled=isEdit;
  $("inp-role-desc").value="";
  hideEl($("role-modal-msg"));
  // Build permission checkboxes grouped by module
  var existing=new Set();
  if(isEdit){
    var rd=_rolesData.find(function(r){return r.name===roleName;});
    if(rd){$("inp-role-desc").value=rd.description||"";(rd.permissions||[]).forEach(function(p){existing.add(p);});}
  }
  var src=_allPermsData.length?_allPermsData:[];
  var groups={};
  src.forEach(function(p){var m=p.split(":")[0];if(!groups[m])groups[m]=[];groups[m].push(p);});
  var html="";
  Object.keys(groups).sort().forEach(function(mod){
    html+='<div class="mb-3">';
    html+='<div class="text-xs font-bold uppercase tracking-wider mb-2" style="color:#475569;letter-spacing:.08em">'+mod+'</div>';
    html+='<div class="grid grid-cols-2 gap-1">';
    groups[mod].forEach(function(perm){
      var act=perm.split(":")[1];
      var chk=existing.has(perm)?' checked':'';
      html+='<label class="flex items-center gap-2 text-xs cursor-pointer p-1 rounded hover:bg-slate-800">';
      html+='<input type="checkbox" class="role-perm-cb" value="'+perm+'"'+chk+' style="accent-color:#6366f1">';
      html+='<span style="color:#cbd5e1">'+act+'</span></label>';
    });
    html+='</div></div>';
  });
  $("role-perm-checkboxes").innerHTML=html;
  show("modal-role");
}

function closeRoleModal(){hide("modal-role");}
$("modal-role").addEventListener("click",function(e){if(e.target===$("modal-role"))closeRoleModal();});

function _roleSelectAll(checked){
  document.querySelectorAll(".role-perm-cb").forEach(function(cb){cb.checked=checked;});
}

async function saveRole(){
  var isEdit=!!_editingRole;
  var name=isEdit?_editingRole:($("inp-role-name").value||"").trim().toLowerCase().replace(/\s+/g,"_");
  var desc=($("inp-role-desc").value||"").trim();
  var perms=Array.from(document.querySelectorAll(".role-perm-cb:checked")).map(function(cb){return cb.value;});
  var msgEl=$("role-modal-msg");
  hideEl(msgEl);
  if(!name){showEl(msgEl,"Role name is required");return;}
  var btn=$("btn-role-save");btn.disabled=true;btn.textContent="Saving…";
  try{
    var r=await api(isEdit?"/api/roles/"+encodeURIComponent(name):"/api/roles",{
      method:isEdit?"PUT":"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name:name,description:desc,permissions:perms})
    });
    var data=await r.json();
    if(!r.ok){showEl(msgEl,data.error||"Failed");return;}
    closeRoleModal();
    _rolesData=[];
    loadRoles();
  }catch(e){showEl(msgEl,e.message);}
  finally{btn.disabled=false;btn.textContent="Save Role";}
}

async function deleteRole(name){
  if(!confirm('Delete role "'+name+'"? Users with this role will be demoted to viewer.'))return;
  var r=await api("/api/roles/"+encodeURIComponent(name),{method:"DELETE"});
  var data=await r.json();
  if(!r.ok){alert(data.error||"Failed to delete role");return;}
  _rolesData=[];loadRoles();
}

function _updateUsersTabForPermissions(){
  // show/hide Add User button based on permission
  if(hasPerm("users:create")){show("btn-add-user");}else{hide("btn-add-user");}
  // show/hide access control sub-nav if the user can access at least one view
  var canUseAccess=hasPerm("users:view")||hasPerm("license:view");
  var nav=$("ac-subnav");if(nav)nav.classList[canUseAccess?"remove":"add"]("hidden");
  // hide roles/matrix nav if no users:view (viewer role won't have it)
  ["acnav-roles","acnav-matrix"].forEach(function(id){
    var el=$(id);if(el)el.style.display=hasPerm("users:view")?"":"none";
  });
  var lic=$("acnav-license");if(lic)lic.style.display=hasPerm("license:view")?"":"none";
}

async function loadUsers(){
  setLoading("users",true);hide("users-err");$("users-body").innerHTML="";
  // Pre-load roles so user table dropdown and add-user modal are populated
  if(_rolesData.length===0 && hasPerm("users:view")){
    try{var rr=await api("/api/roles"),rd=await rr.json();if(rr.ok){_rolesData=rd.roles||[];_allPermsData=rd.all_permissions||[];}}catch(e){}
  }
  try{
    var r=await api("/api/users"),data=await r.json();
    setLoading("users",false);
    if(r.status===403){show("users-admin-notice");hide("btn-add-user");return;}
    if(!r.ok){showEl($("users-err"),data.error||"Failed to load users");return;}
    hide("users-admin-notice");show("btn-add-user");
    _allUsers=data.users||[];
    _updateUserStats(_allUsers);
    renderUsers(_allUsers);
    _renderUserActivity(_allUsers);
  }catch(err){setLoading("users",false);showEl($("users-err"),err.message);}
}

function _updateUserStats(users){
  var total=users.length;
  var admins=users.filter(function(u){return u.role==="admin";}).length;
  var ops=users.filter(function(u){return u.role==="operator";}).length;
  var viewers=users.filter(function(u){return u.role==="viewer";}).length;
  var never=users.filter(function(u){return !u.last_login;}).length;
  ["total","admin","operator","viewer","never"].forEach(function(k,i){
    var el=$("usr-stat-"+k);
    if(el) el.textContent=[total,admins,ops,viewers,never][i];
  });
}

function _renderUserActivity(users){
  var el=$("usr-activity");if(!el) return;
  var sorted=users.slice().sort(function(a,b){
    if(!a.last_login&&!b.last_login) return 0;
    if(!a.last_login) return 1;
    if(!b.last_login) return -1;
    return new Date(b.last_login)-new Date(a.last_login);
  });
  var roleColors={admin:"#60a5fa",operator:"#fbbf24",viewer:"#94a3b8"};
  var roleBg={admin:"#060f2e",operator:"#1c1200",viewer:"#0c0c0c"};
  var html=sorted.map(function(u){
    var rt=u.last_login?relTime(u.last_login):"Never logged in";
    var dot=u.last_login?"#4ade80":"#475569";
    var initials=(u.username[0]||"?").toUpperCase();
    var avatarBg={admin:"#1d4ed8",operator:"#92400e",viewer:"#334155"}[u.role]||"#334155";
    return '<div style="display:flex;align-items:center;gap:.625rem;padding:.45rem 0;border-bottom:1px solid #1e293b">'
      +'<div style="width:.45rem;height:.45rem;border-radius:50%;background:'+dot+';flex-shrink:0"></div>'
      +'<div style="width:1.6rem;height:1.6rem;border-radius:50%;background:'+avatarBg+';color:#fff;font-size:.65rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">'+esc(initials)+'</div>'
      +'<span style="font-family:monospace;font-size:.78rem;color:#f1f5f9;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(u.username)+'</span>'
      +'<span class="badge" style="font-size:.65rem;padding:.1rem .4rem;border-radius:.25rem;background:'+roleBg[u.role]+';color:'+roleColors[u.role]+';border:1px solid;border-color:'+roleColors[u.role]+'40">'+esc(u.role)+'</span>'
      +'<span style="font-size:.72rem;color:#475569;white-space:nowrap;flex-shrink:0">'+esc(rt)+'</span>'
      +'</div>';
  }).join("");
  el.innerHTML=html||'<p class="text-sm text-center py-3" style="color:#475569">No users found.</p>';
}

function filterUsers(){
  var q=($("usr-search")||{}).value.toLowerCase().trim();
  var rf=($("usr-role-filter")||{}).value;
  var rows=$("users-body").querySelectorAll("tr");
  var vis=0;
  rows.forEach(function(tr){
    var uname=(tr.dataset.username||"").toLowerCase();
    var role=(tr.dataset.role||"");
    var matchQ=!q||uname.includes(q);
    var matchR=!rf||role===rf;
    tr.style.display=(matchQ&&matchR)?"":"none";
    if(matchQ&&matchR) vis++;
  });
  toggleVis("usr-no-match",vis===0&&rows.length>0);
}

function renderUsers(users){
  $("users-body").innerHTML="";
  var roleAvatarBg={admin:"#1d4ed8",operator:"#92400e",viewer:"#334155"};
  var roleColors={admin:"badge-blue",operator:"badge-amber",viewer:"badge-gray"};
  users.forEach(function(u){
    var isMe=u.username===CURRENT_USER;
    var initials=(u.username[0]||"?").toUpperCase();
    var avatarBg=roleAvatarBg[u.role]||"#334155";
    var avatar='<div style="width:2rem;height:2rem;border-radius:50%;background:'+avatarBg+';color:#fff;font-size:.75rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">'+esc(initials)+'</div>';
    var cr=u.created_at?new Date(u.created_at).toLocaleDateString("vi-VN"):"—";
    var ll=u.last_login?(relTime(u.last_login)||new Date(u.last_login).toLocaleDateString("vi-VN")):"Never";
    var llColor=u.last_login?"#94a3b8":"#f87171";
    // Role cell: dropdown if admin and not self, else badge only
    var roleCell;
    if(isAdmin()&&!isMe){
      var roleOptions=_rolesData.length
        ? _rolesData.map(function(rd){return rd.name;})
        : ["admin","operator","viewer"];
      roleCell='<select class="form-input usr-role-sel" data-user="'+esc(u.username)+'" onchange="changeUserRole(this)" style="font-size:.72rem;padding:.2rem .45rem;background:#0f172a;border-color:#334155;color:#f1f5f9;width:9rem">'
        +roleOptions.map(function(r){return '<option value="'+r+'"'+(r===u.role?" selected":"")+'>'+r+'</option>';}).join("")
        +'</select>';
    } else {
      roleCell='<span class="badge '+(roleColors[u.role]||"badge-gray")+'" style="font-size:.72rem">'+esc(u.role)+'</span>';
    }
    var resetBtn=isMe?"":'<button onclick="openResetPwdModal(this)" data-user="'+esc(u.username)+'" data-role="'+esc(u.role)+'" class="btn btn-ghost btn-sm" style="padding:.2rem .45rem;font-size:.7rem" title="Reset password">&#128272;</button>';
    var delBtn=isMe?"":'<button onclick="deleteUser(this)" data-user="'+esc(u.username)+'" class="btn btn-sm" style="padding:.2rem .45rem;font-size:.7rem;border:1px solid #7f1d1d;color:#f87171;background:transparent" title="Delete user">&#128465;</button>';
    var tr=document.createElement("tr");
    tr.dataset.username=u.username;
    tr.dataset.role=u.role;
    tr.style.cssText="border-bottom:1px solid #1e293b;transition:background 100ms";
    tr.onmouseover=function(){tr.style.background="#0f1d33"};tr.onmouseout=function(){tr.style.background=""};
    tr.innerHTML='<td class="td"><div style="display:flex;align-items:center;gap:.5rem">'+avatar
      +'<div><span style="font-family:monospace;font-size:.82rem;color:#f1f5f9">'+esc(u.username)+'</span>'
      +(isMe?'<span style="display:block;font-size:.65rem;color:#475569">(you)</span>':'')+'</div></div></td>'
      +'<td class="td">'+roleCell+'</td>'
      +'<td class="td" style="font-size:.75rem;color:'+llColor+'">'+esc(ll)+'</td>'
      +'<td class="td" style="font-size:.75rem;color:#475569">'+esc(cr)+'</td>'
      +'<td class="td th-r" style="white-space:nowrap">'+resetBtn+delBtn+'</td>';
    $("users-body").appendChild(tr);
  });
}

async function changeUserRole(sel){
  var username=sel.dataset.user,role=sel.value;
  var prev=sel.options[Array.from(sel.options).findIndex(function(o){return!o.selected&&!o.disabled;})];
  // Find previous selected value
  var prevRole=_allUsers.find(function(u){return u.username===username;});
  prevRole=prevRole?prevRole.role:"viewer";
  if(role==="admin"&&prevRole!=="admin"){
    if(!confirm("Grant admin to '"+username+"'?\n\nAdmins have full access including user management. Continue?")){
      sel.value=prevRole;return;
    }
  } else if(prevRole==="admin"&&role!=="admin"){
    if(!confirm("Revoke admin from '"+username+"' and set to '"+role+"'? Continue?")){sel.value=prevRole;return;}
  }
  sel.disabled=true;
  try{
    var r=await api("/api/users/"+encodeURIComponent(username)+"/role",{method:"PUT",body:JSON.stringify({role:role})});
    var d=await r.json();
    if(!r.ok){alert(d.error||"Failed");sel.value=prevRole;sel.disabled=false;return;}
    loadUsers();
  }catch(e){alert(e.message);sel.value=prevRole;sel.disabled=false;}
}

async function deleteUser(el){
  var username=el.dataset.user;
  if(!confirm("Delete user '"+username+"'? This cannot be undone."))return;
  try{
    var r=await api("/api/users/"+encodeURIComponent(username),{method:"DELETE"});
    var d=await r.json();
    if(!r.ok){alert(d.error||"Failed");return;}
    loadUsers();
  }catch(e){alert(e.message);}
}

function openAddUserModal(){
  $("inp-new-uname").value="";$("inp-new-upass").value="";
  hideEl($("add-user-msg"));
  // Populate role dropdown with all roles (built-in + custom)
  var sel=$("sel-new-role");
  var roleDescs={viewer:"Read-only",operator:"Submit policies for review",admin:"Full access"};
  var allRoles=_rolesData.length?_rolesData:[{name:"viewer"},{name:"operator"},{name:"admin"}];
  sel.innerHTML=allRoles.map(function(r){
    var desc=r.description||roleDescs[r.name]||"";
    return '<option value="'+r.name+'">'+r.name+(desc?' — '+desc:'')+'</option>';
  }).join("");
  sel.value="viewer";
  show("modal-add-user");
}
function closeAddUserModal(){hide("modal-add-user");}
$("modal-add-user").addEventListener("click",function(e){if(e.target===$("modal-add-user"))closeAddUserModal();});

$("form-add-user").addEventListener("submit",async function(e){
  e.preventDefault();
  var msgEl=$("add-user-msg");hideEl(msgEl);
  var uname=$("inp-new-uname").value.trim();
  var pass=$("inp-new-upass").value;
  var role=$("sel-new-role").value;
  if(!uname||!pass){showMsg(msgEl,"error","Username and password are required.");return;}
  if(pass.length<8){showMsg(msgEl,"error","Password must be at least 8 characters.");return;}
  var btn=this.querySelector('button[type=submit]');btn.disabled=true;
  try{
    var r=await api("/api/users",{method:"POST",body:JSON.stringify({username:uname,password:pass,role:role})});
    var d=await r.json();
    if(!r.ok){showMsg(msgEl,"error",d.error||"Failed");return;}
    closeAddUserModal();loadUsers();
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
});

var resetPwdTarget=null;
function openResetPwdModal(el){
  resetPwdTarget=el.dataset.user;
  $("reset-pwd-uname").textContent=resetPwdTarget;
  var role=el.dataset.role||"viewer";
  var avatarBg={admin:"#1d4ed8",operator:"#92400e",viewer:"#334155"}[role]||"#334155";
  $("reset-pwd-avatar").style.background=avatarBg;
  $("reset-pwd-avatar").textContent=(resetPwdTarget[0]||"?").toUpperCase();
  $("reset-pwd-role-badge").textContent=role;
  $("reset-pwd-role-badge").className="badge "+({admin:"badge-blue",operator:"badge-amber",viewer:"badge-gray"}[role]||"badge-gray");
  $("inp-reset-pass").value="";$("inp-reset-confirm").value="";
  hide("reset-gen-box");hideEl($("reset-pwd-msg"));show("modal-reset-pwd");
}
function closeResetPwdModal(){hide("modal-reset-pwd");resetPwdTarget=null;}
$("modal-reset-pwd").addEventListener("click",function(e){if(e.target===$("modal-reset-pwd"))closeResetPwdModal();});

function generateAndFillPwd(){
  var chars="ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%";
  var pwd=Array.from({length:16},function(){return chars[Math.floor(Math.random()*chars.length)];}).join("");
  $("inp-reset-pass").value=pwd;$("inp-reset-confirm").value=pwd;
  $("reset-gen-display").textContent=pwd;show("reset-gen-box");
}
function copyGenPwd(){
  var txt=$("reset-gen-display").textContent;
  navigator.clipboard&&navigator.clipboard.writeText(txt).then(function(){
    var b=$("reset-gen-display");var old=b.style.color;b.style.color="#4ade80";
    setTimeout(function(){b.style.color=old;},800);
  });
}

$("btn-reset-pwd-confirm").addEventListener("click",async function(){
  var msgEl=$("reset-pwd-msg");hideEl(msgEl);
  var pass=$("inp-reset-pass").value;
  var conf=$("inp-reset-confirm").value;
  if(!pass||pass.length<8){showMsg(msgEl,"error","Password must be at least 8 characters.");return;}
  if(pass!==conf){showMsg(msgEl,"error","Passwords do not match.");return;}
  this.disabled=true;
  try{
    var r=await api("/api/users/"+encodeURIComponent(resetPwdTarget)+"/password",{method:"PUT",body:JSON.stringify({new_password:pass})});
    var d=await r.json();
    if(!r.ok){showMsg(msgEl,"error",d.error||"Failed");this.disabled=false;return;}
    closeResetPwdModal();
  }catch(e){showMsg(msgEl,"error",e.message);this.disabled=false;}
  this.disabled=false;
});

$("form-chgpwd").addEventListener("submit",async function(e){
  e.preventDefault();
  var msgEl=$("chgpwd-msg");hideEl(msgEl);
  var cur=$("inp-cur-pass").value;
  var np=$("inp-new-pass").value;
  var cp=$("inp-confirm-pass").value;
  if(!cur||!np||!cp){showMsg(msgEl,"error","All fields are required.");return;}
  if(np.length<8){showMsg(msgEl,"error","New password must be at least 8 characters.");return;}
  if(np!==cp){showMsg(msgEl,"error","New passwords do not match.");return;}
  var btn=this.querySelector('button[type=submit]');btn.disabled=true;
  try{
    var r=await api("/api/users/"+encodeURIComponent(CURRENT_USER)+"/password",{method:"PUT",body:JSON.stringify({current_password:cur,new_password:np})});
    var d=await r.json();
    if(!r.ok){showMsg(msgEl,"error",d.error||"Failed to change password.");btn.disabled=false;return;}
    var newHdr="Basic "+btoa(CURRENT_USER+":"+np);
    AUTH_HEADER=newHdr;localStorage.setItem("va_auth",JSON.stringify({header:newHdr,user:CURRENT_USER}));
    $("inp-cur-pass").value="";$("inp-new-pass").value="";$("inp-confirm-pass").value="";
    showMsg(msgEl,"success","Password changed successfully.");
  }catch(err){showMsg(msgEl,"error",err.message);}
  finally{btn.disabled=false;}
});
