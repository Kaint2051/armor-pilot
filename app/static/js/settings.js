"use strict";

// ── Settings sub-nav ──
function switchSettingsSection(section) {
  ["server","storage","logging","admin"].forEach(function(s) {
    var el = $("setv-"+s);
    if (el) el.classList.toggle("hidden", s !== section);
    var btn = $("setnav-"+s);
    if (!btn) return;
    if (s === section) { btn.style.background = "#334155"; btn.style.color = "#f1f5f9"; }
    else { btn.style.background = ""; btn.style.color = "#94a3b8"; }
  });
}

// ── Load settings from API ──
function loadSettings() {
  var pathEl   = $("settings-env-file-path");
  var badgeEl  = $("settings-env-writable");
  if (pathEl) pathEl.textContent = "loading…";

  api("/api/settings").then(function(r) {
    return r.json();
  }).then(function(d) {
    if (d.error) { _settingsStatus(d.error, false); return; }

    // Env file info bar
    if (pathEl) pathEl.textContent = d.env_file || "(none configured)";
    if (badgeEl) {
      if (!d.env_file) {
        badgeEl.textContent = "not configured"; badgeEl.className = "badge badge-gray";
      } else if (!d.env_file_exists) {
        badgeEl.textContent = "will be created"; badgeEl.className = "badge badge-amber";
      } else if (d.writable) {
        badgeEl.textContent = "writable"; badgeEl.className = "badge badge-green";
      } else {
        badgeEl.textContent = "read-only"; badgeEl.className = "badge badge-red";
      }
    }

    // Populate text fields
    var plain = ["HOST","PORT","ARMORPILOT_DATA_DIR","DB_PATH","APPARMOR_LOG_PATH","ADMIN_USER"];
    var cfg = d.settings || {};
    plain.forEach(function(k) {
      var el = $("set-"+k);
      if (el) el.value = cfg[k] || "";
    });
    // Never pre-fill the password field
    var passEl = $("set-ADMIN_PASS");
    if (passEl) passEl.value = "";
  }).catch(function(err) {
    _settingsStatus("Failed to load settings: " + (err.message || String(err)), false);
    if (pathEl) pathEl.textContent = "error";
  });
}

// ── Save a subset of settings ──
function saveSettingsSection(keys) {
  var body = {};
  var aborted = false;

  keys.forEach(function(k) {
    if (aborted) return;
    var el = $("set-"+k);
    if (!el) return;
    var val = el.value.trim();

    // Blank password = keep existing
    if (k === "ADMIN_PASS" && val === "") return;

    if (k === "PORT" && val !== "") {
      var p = parseInt(val, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        _settingsStatus("PORT must be a number between 1 and 65535.", false);
        aborted = true; return;
      }
    }
    if (k === "ADMIN_PASS" && val.length < 12) {
      _settingsStatus("Admin password must be at least 12 characters.", false);
      aborted = true; return;
    }
    body[k] = val;
  });

  if (aborted) return;
  if (Object.keys(body).length === 0) {
    _settingsStatus("No changes to save.", true); return;
  }

  api("/api/settings", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  }).then(function(r) {
    return r.json();
  }).then(function(d) {
    if (d.ok) {
      _settingsStatus("Saved successfully. Restart the application for changes to take effect.", true);
      var passEl = $("set-ADMIN_PASS");
      if (passEl) passEl.value = "";
    } else {
      _settingsStatus(d.error || "Failed to save settings.", false);
    }
  }).catch(function(err) {
    _settingsStatus("Error: " + (err.message || String(err)), false);
  });
}

// ── Status banner ──
function _settingsStatus(msg, ok) {
  var el = $("settings-status");
  if (!el) return;
  el.textContent = msg;
  el.className = "mb-4 p-3 rounded-lg text-sm";
  if (ok) {
    el.style.cssText = "background:#14532d;color:#86efac;border:1px solid #166534";
  } else {
    el.style.cssText = "background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d";
  }
  el.classList.remove("hidden");
  setTimeout(function() { el.classList.add("hidden"); }, 6000);
}
