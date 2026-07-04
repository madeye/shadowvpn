// ShadowVPN desktop UI — full frontend logic.
//
// Talks to the Tauri backend exclusively through window.__TAURI__.core.invoke
// (see the IPC contract) and window.__TAURI__.dialog.open for file pickers.
// No bundler, no build step: this file is loaded directly via <script src>.

(function () {
  "use strict";

  const invoke = window.__TAURI__ && window.__TAURI__.core.invoke;
  const openDialog =
    window.__TAURI__ && window.__TAURI__.dialog && window.__TAURI__.dialog.open;

  const STATUS_POLL_MS = 2000;
  const LOG_POLL_MS = 2000;
  const LOG_LINES = 300;

  // ---------------------------------------------------------------------
  // Element references
  // ---------------------------------------------------------------------

  const statusPill = document.getElementById("status-pill");
  const statusDetail = document.getElementById("status-detail");
  const connectToggleBtn = document.getElementById("connect-toggle-btn");

  const profileListEl = document.getElementById("profile-list");
  const newProfileBtn = document.getElementById("new-profile-btn");
  const settingsBtn = document.getElementById("settings-btn");

  const tabBtns = Array.from(document.querySelectorAll(".tab-btn"));
  const viewEditor = document.getElementById("view-editor");
  const viewLog = document.getElementById("view-log");
  const viewSettings = document.getElementById("view-settings");

  const editorPlaceholder = document.getElementById("editor-placeholder");
  const profileForm = document.getElementById("profile-form");

  const fName = document.getElementById("f-name");
  const fServer = document.getElementById("f-server");
  const fPassword = document.getElementById("f-password");
  const passwordToggleBtn = document.getElementById("password-toggle-btn");
  const fCipher = document.getElementById("f-cipher");
  const fObfs = document.getElementById("f-obfs");

  const fTunName = document.getElementById("f-tun_name");
  const fTunIp = document.getElementById("f-tun_ip");
  const fTunNetmask = document.getElementById("f-tun_netmask");
  const fPeerIp = document.getElementById("f-peer_ip");
  const fMtu = document.getElementById("f-mtu");

  const fMode = document.getElementById("f-mode");
  const fDnsListen = document.getElementById("f-dns_listen");
  const fDnsLocal = document.getElementById("f-dns_local");
  const fDnsRemote = document.getElementById("f-dns_remote");
  const fGfwlist = document.getElementById("f-gfwlist");
  const fChnroute = document.getElementById("f-chnroute");
  const fGeoip = document.getElementById("f-geoip");
  const fGeoipCountry = document.getElementById("f-geoip_country");
  const fSetDns = document.getElementById("f-set_dns");

  const fDnsTimeoutMs = document.getElementById("f-dns_timeout_ms");
  const fPrewarmDisable = document.getElementById("f-prewarm_disable");
  const fPrewarm = document.getElementById("f-prewarm");
  const fCacheFile = document.getElementById("f-cache_file");

  const duplicateProfileBtn = document.getElementById("duplicate-profile-btn");
  const deleteProfileBtn = document.getElementById("delete-profile-btn");

  const logPane = document.getElementById("log-pane");
  const logSource = document.getElementById("log-source");

  const fClientBin = document.getElementById("f-client-bin");
  const settingsResolved = document.getElementById("settings-resolved");
  const saveSettingsBtn = document.getElementById("save-settings-btn");

  const toastContainer = document.getElementById("toast-container");

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  let profiles = []; // last list_profiles() result
  let selectedProfile = null; // profile name currently open in the editor, or null (new)
  // Full config object the editor was populated from. The form has no
  // controls for some valid FileConfig fields (nat, lease_ttl_secs, and any
  // future additions); serializeForm() carries those through from this base
  // so saving never silently strips them from a hand-written profile.
  let editorBase = {};

  // Keys the editor form owns (has controls for). Everything else found in a
  // loaded profile is preserved verbatim on save.
  const FORM_OWNED_KEYS = new Set([
    "server",
    "password",
    "cipher",
    "tun_name",
    "tun_ip",
    "tun_netmask",
    "peer_ip",
    "mtu",
    "obfs",
    "mode",
    "dns_listen",
    "dns_local",
    "dns_remote",
    "gfwlist",
    "chnroute",
    "geoip",
    "geoip_country",
    "set_dns",
    "dns_timeout_ms",
    "cache_file",
    "prewarm",
  ]);
  let currentStatus = {
    state: "disconnected",
    pid: null,
    profile: null,
    since: null,
    log_file: null,
  };
  let busy = false; // a connect()/disconnect() call is in flight
  let logUserScrolledUp = false;
  let activeTab = "editor";

  // ---------------------------------------------------------------------
  // Toasts
  // ---------------------------------------------------------------------

  function toast(message, kind) {
    const el = document.createElement("div");
    el.className = "toast" + (kind === "info" ? " toast-info" : "");

    const msg = document.createElement("span");
    msg.className = "toast-message";
    msg.textContent = message;
    el.appendChild(msg);

    const closeBtn = document.createElement("button");
    closeBtn.className = "toast-close";
    closeBtn.type = "button";
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", () => el.remove());
    el.appendChild(closeBtn);

    toastContainer.appendChild(el);
    setTimeout(() => el.remove(), 6000);
  }

  function errText(err) {
    if (typeof err === "string") return err;
    if (err && typeof err.message === "string") return err.message;
    try {
      return JSON.stringify(err);
    } catch (_e) {
      return String(err);
    }
  }

  async function callInvoke(cmd, args) {
    if (!invoke) {
      toast("Tauri bridge unavailable (window.__TAURI__ missing)");
      throw new Error("no invoke");
    }
    try {
      return args === undefined ? await invoke(cmd) : await invoke(cmd, args);
    } catch (err) {
      toast(errText(err));
      throw err;
    }
  }

  // ---------------------------------------------------------------------
  // Tabs / views
  // ---------------------------------------------------------------------

  function showTab(tab) {
    activeTab = tab;
    tabBtns.forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    viewEditor.hidden = tab !== "editor";
    viewLog.hidden = tab !== "log";
    viewSettings.hidden = true;
    if (tab === "log") {
      refreshLog();
    }
  }

  function showSettingsView() {
    activeTab = "settings";
    tabBtns.forEach((b) => b.classList.remove("active"));
    viewEditor.hidden = true;
    viewLog.hidden = true;
    viewSettings.hidden = false;
    loadSettings();
  }

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => showTab(btn.dataset.tab));
  });

  settingsBtn.addEventListener("click", showSettingsView);

  // ---------------------------------------------------------------------
  // Profile list (sidebar)
  // ---------------------------------------------------------------------

  async function loadProfiles() {
    try {
      profiles = await callInvoke("list_profiles");
    } catch (_err) {
      return;
    }
    renderProfileList();
  }

  function renderProfileList() {
    profileListEl.innerHTML = "";
    for (const p of profiles) {
      const li = document.createElement("li");
      li.dataset.name = p.name;
      if (p.name === selectedProfile) li.classList.add("selected");
      if (
        currentStatus.state === "connected" &&
        currentStatus.profile === p.name
      ) {
        li.classList.add("connected");
      }

      const dot = document.createElement("span");
      dot.className = "dot";
      li.appendChild(dot);

      const names = document.createElement("span");
      names.className = "names";

      const nameEl = document.createElement("span");
      nameEl.className = "profile-name";
      nameEl.textContent = p.name;
      names.appendChild(nameEl);

      const serverEl = document.createElement("span");
      serverEl.className = "profile-server";
      serverEl.textContent = p.server || "(no server set)";
      names.appendChild(serverEl);

      li.appendChild(names);

      li.addEventListener("click", () => selectProfile(p.name));
      profileListEl.appendChild(li);
    }
  }

  // ---------------------------------------------------------------------
  // Profile editor
  // ---------------------------------------------------------------------

  function clearForm() {
    profileForm.reset();
    fName.readOnly = false;
    updatePolicyFieldsState();
  }

  function populateForm(name, config) {
    clearForm();
    editorBase = config || {};
    fName.value = name || "";
    fName.readOnly = !!name;

    fServer.value = config.server || "";
    fPassword.value = config.password || "";
    fCipher.value = config.cipher || "";
    fObfs.value = config.obfs || "";

    fTunName.value = config.tun_name || "";
    fTunIp.value = config.tun_ip || "";
    fTunNetmask.value = config.tun_netmask || "";
    fPeerIp.value = config.peer_ip || "";
    fMtu.value = config.mtu != null ? String(config.mtu) : "";

    fMode.value = config.mode || "";
    fDnsListen.value = config.dns_listen || "";
    fDnsLocal.value = config.dns_local || "";
    fDnsRemote.value = config.dns_remote || "";
    fGfwlist.value = config.gfwlist || "";
    fChnroute.value = config.chnroute || "";
    fGeoip.value = config.geoip || "";
    fGeoipCountry.value = config.geoip_country || "";
    fSetDns.checked = config.set_dns !== false;

    fDnsTimeoutMs.value =
      config.dns_timeout_ms != null ? String(config.dns_timeout_ms) : "";
    if (Array.isArray(config.prewarm) && config.prewarm.length === 0) {
      fPrewarmDisable.checked = true;
      fPrewarm.value = "";
    } else {
      fPrewarmDisable.checked = false;
      fPrewarm.value = Array.isArray(config.prewarm)
        ? config.prewarm.join("\n")
        : "";
    }
    fCacheFile.value = config.cache_file || "";

    updatePolicyFieldsState();
  }

  async function selectProfile(name) {
    selectedProfile = name;
    renderProfileList();
    try {
      const config = await callInvoke("get_profile", { name });
      editorPlaceholder.hidden = true;
      profileForm.hidden = false;
      populateForm(name, config);
    } catch (_err) {
      // error already toasted
    }
    showTab("editor");
  }

  function newProfile() {
    selectedProfile = null;
    renderProfileList();
    editorPlaceholder.hidden = true;
    profileForm.hidden = false;
    populateForm("", {});
    fName.focus();
    showTab("editor");
  }

  newProfileBtn.addEventListener("click", newProfile);

  function updatePolicyFieldsState() {
    const mode = fMode.value || "full";
    document.querySelectorAll(".policy-field").forEach((label) => {
      const forMode = label.dataset.forMode;
      const enabled = forMode === mode;
      label.classList.toggle("field-disabled", !enabled);
      label.querySelectorAll("input").forEach((input) => {
        input.disabled = !enabled;
      });
      label.querySelectorAll("button[data-browse]").forEach((btn) => {
        btn.disabled = !enabled;
      });
    });
  }

  fMode.addEventListener("change", updatePolicyFieldsState);

  passwordToggleBtn.addEventListener("click", () => {
    const showing = fPassword.type === "text";
    fPassword.type = showing ? "password" : "text";
    passwordToggleBtn.textContent = showing ? "Show" : "Hide";
  });

  // ---- serialization: empty/placeholder input => omit the key ----

  function strOrUndef(input) {
    const v = input.value.trim();
    return v === "" ? undefined : v;
  }

  function intOrUndef(input) {
    const v = input.value.trim();
    if (v === "") return undefined;
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? undefined : n;
  }

  function serializeForm() {
    // Start from the fields the form does NOT own (nat, lease_ttl_secs, any
    // future FileConfig additions) so a save round-trips them untouched.
    const config = {};
    for (const key of Object.keys(editorBase)) {
      if (!FORM_OWNED_KEYS.has(key)) {
        config[key] = editorBase[key];
      }
    }
    Object.assign(config, {
      server: strOrUndef(fServer),
      password: strOrUndef(fPassword),
      cipher: strOrUndef(fCipher),
      tun_name: strOrUndef(fTunName),
      tun_ip: strOrUndef(fTunIp),
      tun_netmask: strOrUndef(fTunNetmask),
      peer_ip: strOrUndef(fPeerIp),
      mtu: intOrUndef(fMtu),
      obfs: strOrUndef(fObfs),
      mode: strOrUndef(fMode),
      dns_listen: strOrUndef(fDnsListen),
      dns_local: strOrUndef(fDnsLocal),
      dns_remote: strOrUndef(fDnsRemote),
      gfwlist: strOrUndef(fGfwlist),
      chnroute: strOrUndef(fChnroute),
      geoip: strOrUndef(fGeoip),
      geoip_country: strOrUndef(fGeoipCountry),
      set_dns: fSetDns.checked ? undefined : false,
      dns_timeout_ms: intOrUndef(fDnsTimeoutMs),
      cache_file: strOrUndef(fCacheFile),
    });

    // Tri-state prewarm: empty+unchecked => omit, checked => [], lines => array.
    if (fPrewarmDisable.checked) {
      config.prewarm = [];
    } else {
      const lines = fPrewarm.value
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      config.prewarm = lines.length > 0 ? lines : undefined;
    }

    return config;
  }

  profileForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = fName.value.trim();
    if (!name) {
      toast("Profile name is required");
      return;
    }
    const config = serializeForm();
    try {
      await callInvoke("save_profile", { name, config });
      toast(`Saved profile "${name}"`, "info");
      selectedProfile = name;
      await loadProfiles();
      await selectProfile(name);
    } catch (_err) {
      // already toasted
    }
  });

  duplicateProfileBtn.addEventListener("click", () => {
    if (profileForm.hidden) return;
    const config = serializeForm();
    selectedProfile = null;
    fName.readOnly = false;
    fName.value = "";
    populateForm("", config);
    fName.focus();
    toast("Duplicated — pick a new name and Save", "info");
  });

  deleteProfileBtn.addEventListener("click", async () => {
    if (!selectedProfile) {
      toast("No profile selected");
      return;
    }
    if (!window.confirm(`Delete profile "${selectedProfile}"? This cannot be undone.`)) {
      return;
    }
    try {
      await callInvoke("delete_profile", { name: selectedProfile });
      toast(`Deleted profile "${selectedProfile}"`, "info");
      selectedProfile = null;
      editorPlaceholder.hidden = false;
      profileForm.hidden = true;
      await loadProfiles();
    } catch (_err) {
      // already toasted
    }
  });

  // ---- file pickers ----

  document.querySelectorAll("button[data-browse]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!openDialog) {
        toast("File dialog unavailable");
        return;
      }
      try {
        const path = await openDialog({ multiple: false, filters: [] });
        if (typeof path === "string" && path.length > 0) {
          const targetInput = document.getElementById(btn.dataset.browse);
          if (targetInput) targetInput.value = path;
        }
      } catch (err) {
        toast(errText(err));
      }
    });
  });

  // ---------------------------------------------------------------------
  // Connect / disconnect / status polling
  // ---------------------------------------------------------------------

  function formatUptime(sinceSeconds) {
    if (!sinceSeconds) return "";
    const nowSec = Math.floor(Date.now() / 1000);
    let delta = nowSec - sinceSeconds;
    if (delta < 0) delta = 0;
    const h = Math.floor(delta / 3600);
    const m = Math.floor((delta % 3600) / 60);
    const s = delta % 60;
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  function renderStatus() {
    const state = currentStatus.state || "disconnected";
    statusPill.textContent =
      state === "connected"
        ? "Connected"
        : state === "connecting"
          ? "Connecting…"
          : "Disconnected";
    statusPill.className =
      "pill " +
      (state === "connected"
        ? "pill-connected"
        : state === "connecting"
          ? "pill-connecting"
          : "pill-disconnected");

    const parts = [];
    if (currentStatus.profile) parts.push(currentStatus.profile);
    if (state === "connected" && currentStatus.since) {
      parts.push(formatUptime(currentStatus.since));
    }
    statusDetail.textContent = parts.join(" · ");

    // Connect/Disconnect toggle
    connectToggleBtn.classList.toggle("disconnect", state !== "disconnected");
    connectToggleBtn.textContent =
      state === "connected"
        ? "Disconnect"
        : state === "connecting"
          ? "Cancel / Disconnect"
          : "Connect";
    connectToggleBtn.disabled =
      busy || (state === "disconnected" && !selectedProfile);

    renderProfileList();
  }

  connectToggleBtn.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    renderStatus();
    try {
      if (currentStatus.state === "disconnected") {
        if (!selectedProfile) {
          toast("Select a profile first");
          return;
        }
        const status = await callInvoke("connect", { name: selectedProfile });
        currentStatus = status;
        showTab("log");
      } else {
        const status = await callInvoke("disconnect");
        currentStatus = status;
      }
    } catch (_err) {
      // already toasted; refresh status to reflect reality
      await pollStatus();
    } finally {
      busy = false;
      renderStatus();
    }
  });

  async function pollStatus() {
    try {
      currentStatus = await callInvoke("status");
    } catch (_err) {
      return;
    }
    renderStatus();
    if (currentStatus.state !== "disconnected") {
      refreshLog();
    }
  }

  // ---------------------------------------------------------------------
  // Log pane
  // ---------------------------------------------------------------------

  logPane.addEventListener("scroll", () => {
    const atBottom =
      logPane.scrollHeight - logPane.scrollTop - logPane.clientHeight < 20;
    logUserScrolledUp = !atBottom;
  });

  async function refreshLog() {
    try {
      const lines = await callInvoke("read_log", { lines: LOG_LINES });
      logPane.textContent = lines.length > 0 ? lines.join("\n") : "(no log yet)";
      logSource.textContent = currentStatus.log_file || "";
      if (!logUserScrolledUp) {
        logPane.scrollTop = logPane.scrollHeight;
      }
    } catch (_err) {
      // already toasted
    }
  }

  // ---------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------

  async function loadSettings() {
    try {
      const info = await callInvoke("get_settings");
      fClientBin.value = info.client_bin || "";
      const resolved = info.resolved_client_bin
        ? `Resolved: ${info.resolved_client_bin} (from ${info.resolved_from || "unknown"})`
        : "No client binary could be resolved.";
      settingsResolved.textContent = resolved;
    } catch (_err) {
      // already toasted
    }
  }

  saveSettingsBtn.addEventListener("click", async () => {
    const client_bin = fClientBin.value.trim();
    try {
      await callInvoke("save_settings", {
        settings: { client_bin: client_bin === "" ? undefined : client_bin },
      });
      toast("Settings saved", "info");
      await loadSettings();
    } catch (_err) {
      // already toasted
    }
  });

  // ---------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------

  document.addEventListener("DOMContentLoaded", () => {
    updatePolicyFieldsState();
    loadProfiles();
    pollStatus();
    setInterval(pollStatus, STATUS_POLL_MS);
    setInterval(() => {
      if (currentStatus.state !== "disconnected" || activeTab === "log") {
        refreshLog();
      }
    }, LOG_POLL_MS);
  });
})();
