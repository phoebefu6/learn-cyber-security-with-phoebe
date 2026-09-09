/* sec-live.js - the attack-path bench for learn-cyber-security-with-phoebe.

   Real graph computation, not a quiz. Ironwood's data estate is a small directed
   graph: accounts, keys, buckets, a warehouse, the crown-jewel table, backups and
   an external endpoint. Every control you switch on removes or logs specific edges.
   The engine then enumerates every simple path from the two starting points
   (the internet, and an insider who already holds a functional role) to the crown
   jewels, counts how many cross no logged edge, and works out whether the backups
   survive an attacker who reaches the admin account.

   Nothing here is modelled. The graph is a written inventory; the numbers are
   path counts over it. Exposes window.SEC_ENGINE, renders into [data-sec-bench]. */
(function (root) {
  "use strict";

  var NODES = {
    internet:     { label: "Internet",            kind: "start" },
    insider:      { label: "Insider analyst",     kind: "start" },
    repo:         { label: "Git repo",            kind: "asset" },
    ci_runner:    { label: "CI runner",           kind: "asset" },
    svc_key:      { label: "ETL service key",     kind: "cred" },
    user_analyst: { label: "Analyst login",       kind: "cred" },
    admin:        { label: "Admin login",         kind: "cred" },
    bucket_export:{ label: "Export bucket",       kind: "asset" },
    warehouse:    { label: "Warehouse",           kind: "asset" },
    crown:        { label: "customers table",     kind: "crown" },
    egress:       { label: "External endpoint",   kind: "exfil" },
    backups:      { label: "Backups",             kind: "backup" }
  };

  /* Each edge: from, to, how (the attacker's move), and either
       removedBy: a control that closes the edge, or
       loggedBy:  a control that makes crossing it visible.
     firewallBlocks marks the edges a perimeter allowlist alone would close. */
  var EDGES = [
    { from: "internet", to: "repo",          how: "public repo holds a committed key",  removedBy: null },
    { from: "repo",     to: "svc_key",       how: "key read out of the repo history",   removedBy: "key_rotation" },
    { from: "internet", to: "user_analyst",  how: "phished password reused",            removedBy: "mfa" },
    { from: "internet", to: "admin",         how: "phished admin, no second factor",    removedBy: "mfa" },
    { from: "internet", to: "ci_runner",     how: "malicious package in the build",     removedBy: "pinned_deps" },
    { from: "ci_runner",to: "svc_key",       how: "runner environment holds the key",   removedBy: null },
    { from: "internet", to: "bucket_export", how: "bucket listable without auth",       removedBy: "private_bucket" },
    { from: "bucket_export", to: "crown",    how: "nightly extract of the table",       removedBy: "private_bucket" },
    { from: "svc_key",  to: "warehouse",     how: "key authenticates from anywhere",    removedBy: null, firewallBlocks: true },
    { from: "user_analyst", to: "warehouse", how: "SSO login",                          removedBy: null },
    { from: "admin",    to: "warehouse",     how: "SSO login",                          removedBy: null },
    { from: "insider",  to: "user_analyst",  how: "it is their own account",            removedBy: null },
    { from: "insider",  to: "warehouse",     how: "their own legitimate support session", removedBy: null },
    { from: "warehouse",to: "crown",         how: "SELECT within a role that must read customers", removedBy: null, loggedBy: "query_logging", viaRole: "insider" },
    { from: "warehouse",to: "crown",         how: "SELECT with a broad role",           removedBy: "least_privilege", loggedBy: "query_logging", viaRole: "user_analyst" },
    { from: "warehouse",to: "crown",         how: "SELECT as the ETL service",          removedBy: null, loggedBy: "query_logging", viaRole: "svc_key" },
    { from: "warehouse",to: "crown",         how: "SELECT as admin",                    removedBy: null, loggedBy: "query_logging", viaRole: "admin" },
    { from: "crown",    to: "egress",        how: "COPY INTO an external stage",        removedBy: null, loggedBy: "egress_alerting" },
    { from: "user_analyst", to: "admin",     how: "admin role granted for a Friday unblock, never revoked", removedBy: "least_privilege" },
    { from: "admin",    to: "backups",       how: "DROP and purge, time travel included", removedBy: "immutable_backups" }
  ];

  var CONTROLS = [
    { id: "mfa",              family: "Identity",  label: "MFA on every human login",
      blurb: "Closes the phishing door for analysts and admins alike. The single highest-value edge removal on the graph." },
    { id: "key_rotation",     family: "Identity",  label: "Rotate service keys, expire the old ones",
      blurb: "A key in git history stops being a door once it no longer authenticates." },
    { id: "least_privilege",  family: "Access",    label: "Least privilege on the analyst role",
      blurb: "The analyst can still work; they can no longer SELECT the crown jewels with a broad role." },
    { id: "private_bucket",   family: "Storage",   label: "Export bucket private, no public listing",
      blurb: "The nightly extract stops being readable by anyone with the URL." },
    { id: "pinned_deps",      family: "Supply chain", label: "Pin and verify build dependencies",
      blurb: "A malicious package cannot land in the CI runner that holds the ETL key." },
    { id: "query_logging",    family: "Detection", label: "Query logging on the crown-jewel table",
      blurb: "Every SELECT against customers is recorded and reviewed. Does not stop a read; makes it visible." },
    { id: "egress_alerting",  family: "Detection", label: "Egress alerting on external stages",
      blurb: "A COPY INTO an external location pages somebody. Again: visible, not blocked." },
    { id: "immutable_backups",family: "Recovery",  label: "Immutable backups, restore-tested",
      blurb: "An attacker with the admin login can drop the warehouse and still cannot touch last night's copy." },
    { id: "perimeter_only",   family: "Over-correction", label: "Perimeter firewall only",
      blurb: "An IP allowlist on the warehouse and nothing else. It really does close one door." }
  ];

  var TABLES = 12;

  function activeEdges(on) {
    return EDGES.filter(function (e) {
      if (e.removedBy && on[e.removedBy]) return false;
      if (on.perimeter_only && e.firewallBlocks) return false;
      return true;
    }).map(function (e) {
      return { from: e.from, to: e.to, how: e.how, viaRole: e.viaRole || null,
               logged: !!(e.loggedBy && on[e.loggedBy]) };
    });
  }

  /* Enumerate simple paths start -> crown. The warehouse->crown edge is role-specific:
     it is usable only if the path arrived at the warehouse through that role's node. */
  function paths(start, edges) {
    var out = [];
    function walk(node, visited, trail, arrivedVia) {
      if (node === "crown") { out.push(trail.slice()); return; }
      edges.forEach(function (e) {
        if (e.from !== node) return;
        if (visited.indexOf(e.to) >= 0) return;
        if (e.viaRole && e.viaRole !== arrivedVia) return;
        var via = arrivedVia;
        if (e.to === "warehouse") via = node;
        walk(e.to, visited.concat([e.to]), trail.concat([e]), via);
      });
    }
    walk(start, [start], [], null);
    return out;
  }

  function reach(start, target, edges) {
    var seen = {}; seen[start] = true; var q = [start];
    while (q.length) {
      var n = q.shift();
      if (n === target) return true;
      edges.forEach(function (e) { if (e.from === n && !seen[e.to]) { seen[e.to] = true; q.push(e.to); } });
    }
    return false;
  }

  function run(on) {
    var edges = activeEdges(on);
    var all = paths("internet", edges).concat(paths("insider", edges));
    var undetected = all.filter(function (p) { return !p.some(function (e) { return e.logged; }); });
    /* exfiltration paths: the crown-jewel paths extended by the egress edge, if present */
    var egressEdge = edges.filter(function (e) { return e.from === "crown" && e.to === "egress"; })[0] || null;
    var exfilUndetected = egressEdge
      ? all.filter(function (p) { return !p.some(function (e) { return e.logged; }) && !egressEdge.logged; }).length
      : 0;
    var backupsLost = reach("internet", "backups", edges) || reach("insider", "backups", edges);
    return {
      paths: all.length,
      undetected: undetected.length,
      exfilUndetected: exfilUndetected,
      recoverable: backupsLost ? 0 : TABLES,
      tables: TABLES,
      pathList: all,
      edges: edges
    };
  }

  var RUNGS = [
    { label: "Nothing on", on: [] },
    { label: "+ MFA", on: ["mfa"] },
    { label: "+ key rotation", on: ["mfa","key_rotation"] },
    { label: "+ private export bucket", on: ["mfa","key_rotation","private_bucket"] },
    { label: "+ pinned dependencies", on: ["mfa","key_rotation","private_bucket","pinned_deps"] },
    { label: "+ query logging and egress alerting", on: ["mfa","key_rotation","private_bucket","pinned_deps","query_logging","egress_alerting"] },
    { label: "+ immutable backups", on: ["mfa","key_rotation","private_bucket","pinned_deps","query_logging","egress_alerting","immutable_backups"] },
    { label: "+ least privilege", on: ["mfa","key_rotation","private_bucket","pinned_deps","query_logging","egress_alerting","immutable_backups","least_privilege"] }
  ];
  function ladder() {
    return RUNGS.map(function (r) {
      var on = {}; r.on.forEach(function (id) { on[id] = true; });
      var res = run(on);
      return { label: r.label, paths: res.paths, undetected: res.undetected, recoverable: res.recoverable };
    });
  }

  root.SEC_ENGINE = { NODES: NODES, EDGES: EDGES, CONTROLS: CONTROLS, RUNGS: RUNGS, TABLES: TABLES, run: run, ladder: ladder };
})(typeof window !== "undefined" ? window : globalThis);

/* ============================================================
   the widget - renders the attack-path bench into [data-sec-bench]
   ============================================================ */
(function () {
  "use strict";
  if (typeof document === "undefined") return;
  var E = window.SEC_ENGINE; if (!E) return;
  function el(t, c, x) { var n = document.createElement(t); if (c) n.className = c; if (x !== undefined && x !== null) n.textContent = x; return n; }

  var PRESETS = [
    { label: "Nothing on", on: [] },
    { label: "Identity only", on: ["mfa", "key_rotation"] },
    { label: "Prevention, no detection", on: ["mfa","key_rotation","private_bucket","pinned_deps","least_privilege","immutable_backups"] },
    { label: "The whole design", on: ["mfa","key_rotation","private_bucket","pinned_deps","query_logging","egress_alerting","immutable_backups","least_privilege"] }
  ];

  document.querySelectorAll("[data-sec-bench]").forEach(function (host) {
    var state = {};
    var wrap = el("div", "wk sb-wrap");
    var head = el("div", "wk-head");
    head.appendChild(el("b", null, "The attack-path bench"));
    head.appendChild(el("span", null, "Ironwood's estate · 12 nodes · two starting points · one crown-jewel table"));
    wrap.appendChild(head);
    var body = el("div", "wk-body");
    body.appendChild(el("p", "hb-honesty",
      "Nothing here is modelled. The estate is a written inventory of accounts, keys, buckets and tables with the " +
      "edges an attacker could use. Every control removes or logs specific edges, and the numbers are path counts " +
      "over what is left, computed in your browser."));

    var reads = el("div", "sb-reads");
    function readout(cls, label) { var b = el("div", "sb-read " + cls); var big = el("b", "sb-big", "-"); b.appendChild(big); b.appendChild(el("span", "sb-rlab", label)); reads.appendChild(b); return big; }
    var outPaths = readout("sb-r1", "paths to the crown jewels");
    var outUndet = readout("sb-r2", "of them undetected");
    var outRecov = readout("sb-r3", "tables recoverable of 12");
    body.appendChild(reads);

    var presets = el("div", "sb-presets"); presets.appendChild(el("span", "sb-plab", "Presets"));
    PRESETS.forEach(function (p) { var b = el("button", "hb-btn", p.label); b.type = "button";
      b.addEventListener("click", function () { state = {}; p.on.forEach(function (id) { state[id] = true; }); sync(); paint(); }); presets.appendChild(b); });
    body.appendChild(presets);

    var boxes = {}; var list = el("div", "sb-controls");
    E.CONTROLS.forEach(function (c) {
      var row = el("label", "sb-ctl" + (c.family === "Over-correction" ? " sb-anti" : ""));
      var cb = document.createElement("input"); cb.type = "checkbox";
      cb.addEventListener("change", function () { state[c.id] = cb.checked; paint(); }); boxes[c.id] = cb;
      var txt = el("span", "sb-ctxt"); txt.appendChild(el("b", null, c.label)); txt.appendChild(el("span", "sb-cblurb", c.blurb));
      row.appendChild(cb); row.appendChild(el("span", "sb-fam", c.family)); row.appendChild(txt); list.appendChild(row);
    });
    body.appendChild(list);

    body.appendChild(el("p", "sb-pathlab", "Every open path, start to crown jewels. Hover an edge for the attacker's move."));
    var pathBox = el("div", "sb-paths"); body.appendChild(pathBox);
    var notes = el("div", "sb-notes"); body.appendChild(notes);
    wrap.appendChild(body);
    var foot = el("div", "wk-foot");
    foot.appendChild(el("span", null, "A path is undetected when it crosses no logged edge. Recoverable means an attacker who reaches the admin login still cannot destroy last night's copy."));
    wrap.appendChild(foot);
    host.appendChild(wrap);

    function sync() { Object.keys(boxes).forEach(function (id) { boxes[id].checked = !!state[id]; }); }
    function paint() {
      var r = E.run(state);
      outPaths.textContent = r.paths; outUndet.textContent = r.undetected; outRecov.textContent = r.recoverable;
      pathBox.textContent = "";
      if (!r.paths) pathBox.appendChild(el("p", "hb-empty", "No open path from either starting point to the crown jewels."));
      r.pathList.forEach(function (p) {
        var logged = p.some(function (e) { return e.logged; });
        var row = el("div", "sb-path" + (logged ? " sb-seen" : " sb-blind"));
        row.appendChild(el("span", "sb-start", E.NODES[p[0].from].label));
        p.forEach(function (e) {
          var hop = el("span", "sb-hop" + (e.logged ? " sb-hop-logged" : "")); hop.textContent = "→ " + E.NODES[e.to].label; hop.title = e.how + (e.logged ? "  [logged]" : ""); row.appendChild(hop);
        });
        row.appendChild(el("span", "sb-verdict", logged ? "seen" : "unseen"));
        pathBox.appendChild(row);
      });
      notes.textContent = "";
      if (r.paths === 1 && r.undetected === 0 && r.recoverable === 12) {
        notes.appendChild(el("p", "dh-verdict", "One path left and it is the insider's own legitimate read, which no control can remove without stopping the work. It is logged. That is what a finished design looks like: not zero, but nothing unseen."));
      }
      if (r.paths > 0 && r.undetected === r.paths && Object.keys(state).some(function (k) { return state[k]; })) {
        notes.appendChild(el("p", "dh-verdict warn", r.undetected + " open " + (r.undetected === 1 ? "path crosses" : "paths cross") + " no logged edge. Prevention that closes doors without watching the rest is a bet that you closed the right ones."));
      }
      if (r.recoverable === 0 && Object.keys(state).some(function (k) { return state[k]; })) {
        notes.appendChild(el("p", "dh-verdict warn", "Backups reachable from an attacker who gets the admin login. Time travel goes with the account; a copy the account cannot delete is the only one that counts."));
      }
    }
    sync(); paint();
  });
})();
