// server.js — multi-project & multi-baseNode (key ở cấp root, data ở dưới baseNode)
const express = require("express");
const admin = require("firebase-admin");
const CryptoJS = require("crypto-js");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 10000;

const START_STAGGER_MS = Number(process.env.START_STAGGER_MS || 800);
const BATCH_WINDOW_MS  = Number(process.env.BATCH_WINDOW_MS  || 250);
const KEY_FORMAT       = (process.env.KEY_FORMAT || "utf8").toLowerCase(); // utf8|base64|hex

function ts() { return new Date().toISOString(); }
function j(x) { try { return JSON.stringify(x); } catch { return String(x); } }
function log(msg, ctx = {}) { console.log(`${ts()} ${msg} ${Object.keys(ctx).length ? j(ctx) : ""}`); }

function readProjects() {
  let arr = [];
  try { arr = JSON.parse(process.env.PROJECTS_JSON || "[]"); }
  catch (e) { log("❌ PROJECTS_JSON parse error", { error: e.message }); process.exit(1); }
  if (!Array.isArray(arr) || arr.length === 0) { log("❌ PROJECTS_JSON must be a non-empty array"); process.exit(1); }
  for (const p of arr) {
    if (!p.name)               { log("❌ PROJECTS_JSON missing field", { field: "name" }); process.exit(1); }
    if (!p.serviceAccountPath) { log("❌ PROJECTS_JSON missing field", { project: p.name, field: "serviceAccountPath" }); process.exit(1); }
    if (!p.databaseURL)        { log("❌ PROJECTS_JSON missing field", { project: p.name, field: "databaseURL" });        process.exit(1); }
    if (!p.baseNode && !p.baseNodes) { log("❌ PROJECTS_JSON must have baseNode or baseNodes", { project: p.name }); process.exit(1); }
    if (!p.keyNode)            { log("❌ PROJECTS_JSON missing field", { project: p.name, field: "keyNode" }); process.exit(1); }
    if (!p.dataNode)           { log("❌ PROJECTS_JSON missing field", { project: p.name, field: "dataNode" }); process.exit(1); }
  }
  return arr;
}

function loadServiceAccount(p) {
  const abs = path.resolve(p);
  if (!fs.existsSync(abs)) throw new Error(`Service account not found: ${abs}`);
  return require(abs);
}

function parseKey(str) {
  if (KEY_FORMAT === "utf8")   return CryptoJS.enc.Utf8.parse(str);
  if (KEY_FORMAT === "base64") return CryptoJS.enc.Base64.parse(str);
  if (KEY_FORMAT === "hex")    return CryptoJS.enc.Hex.parse(str);
  return CryptoJS.enc.Utf8.parse(str);
}
function decryptAES(ciphertext, keyStr, ivStr) {
  const KEY = parseKey(keyStr);
  const IV  = parseKey(ivStr);
  const bytes = CryptoJS.AES.decrypt(ciphertext, KEY, { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return bytes.toString(CryptoJS.enc.Utf8);
}

function splitCsv(s) { return (s || "").split(",").map(x=>x.trim()).filter(Boolean); }
function diffNewIDs(currCsv, prevCsv) { const curr = splitCsv(currCsv); const prev = new Set(splitCsv(prevCsv)); return curr.filter(id => !prev.has(id)); }

const PROJECTS = readProjects();

// appState[project] = { app, db }
const appState  = Object.create(null);
// nodeState[project/baseNode] = {...}
const nodeState = Object.create(null);
function nodeKeyOf(projectName, baseNode) { return `${projectName}/${baseNode}`; }

function ensureProjectApp(project) {
  if (appState[project.name]) return appState[project.name];
  const svc = loadServiceAccount(project.serviceAccountPath);
  const appInst = admin.initializeApp({ credential: admin.credential.cert(svc), databaseURL: project.databaseURL }, project.name);
  const db = appInst.database();
  appState[project.name] = { app: appInst, db };
  log(`[${project.name}] 🧩 app initialized`, { databaseURL: project.databaseURL });
  return appState[project.name];
}

// debounce flush per node
function scheduleFlushNode(projectName, baseNode) {
  const nk = nodeKeyOf(projectName, baseNode);
  const st = nodeState[nk];
  if (st.debounceTimer) return;
  const { db } = appState[projectName];

  st.debounceTimer = setTimeout(async () => {
    const started = Date.now();
    const payload = st.updatesQueue; st.updatesQueue = {}; st.debounceTimer = null;
    const paths = Object.keys(payload);
    if (!paths.length) { log(`[${nk}] ⏭️ flush skipped (empty queue)`); return; }
    try {
      log(`[${nk}] ⬆️ flushing`, { paths: paths.length });
      await db.ref().update(payload);
      const took = Date.now() - started;
      const onCount  = paths.filter(p => p.includes("/listIDON/")).length;
      const oncCount = paths.filter(p => p.includes("/listIDONC/")).length;
      log(`[${nk}] ✅ flushed`, { paths: paths.length, onCount, oncCount, tookMs: took });
    } catch (e) {
      log(`[${nk}] ❌ flush error`, { error: e.message, retryQueued: paths.length });
      st.updatesQueue = { ...payload, ...st.updatesQueue };
      scheduleNodeReconnect({ name: projectName }, baseNode, true);
    }
  }, BATCH_WINDOW_MS);
}

function scheduleNodeReconnect(project, baseNode) {
  const nk = nodeKeyOf(project.name, baseNode);
  const st = nodeState[nk] || (nodeState[nk] = { failures: 0, backoffMs: 1000 });
  st.failures = (st.failures || 0) + 1;
  st.listenersAttached = false;
  const next = Math.min((st.backoffMs || 1000) * 2, 30000) + Math.floor(Math.random() * 500);
  st.backoffMs = next;
  log(`[${nk}] 🔁 scheduling reconnect`, { failures: st.failures, backoffMs: next });
  setTimeout(() => {
    try {
      if (st.keyRef)  { try { st.keyRef.off(); }  catch {} }
      if (st.dataRef && st._handleDataValue) { try { st.dataRef.off("value", st._handleDataValue); } catch {} }
    } catch {}
    attachBaseNodeListener(project, baseNode);
  }, next);
}

// === CHỖ SỬA CHÍNH: key ở root, data ở dưới baseNode ===
function attachBaseNodeListener(project, baseNode) {
  const { name: projectName, databaseURL, keyNode = "ENCKEY", dataNode = "SetRuContent" } = project;
  const { db } = ensureProjectApp(project);
  const nk = nodeKeyOf(projectName, baseNode);

  if (!nodeState[nk]) {
    nodeState[nk] = {
      projectName, baseNode, databaseURL, keyNode, dataNode,
      aesKey: null, aesIv: null, prevON: "", prevONC: "",
      lastEventAt: 0, updatesQueue: {}, debounceTimer: null,
      listenersAttached: false, failures: 0, backoffMs: 1000,
      keyRef: null, dataRef: null, dataListenerAttached: false, _handleDataValue: null
    };
  }
  const st = nodeState[nk];
  if (st.listenersAttached) return;

  // key ở root (đường dẫn tuyệt đối do bạn chỉ định bằng keyNode)
  const keyPathAbs = keyNode.startsWith("/") ? keyNode.slice(1) : keyNode;
  st.keyRef  = db.ref(keyPathAbs);

  // data nằm dưới baseNode
  const dataPath = `${baseNode}/${dataNode}`;
  st.dataRef = db.ref(dataPath);

  // ENCKEY listener: khi có key/iv mới attach data listener
  st.keyRef.on("value",
    (snap) => {
      const v = snap.val();
      if (v?.key && v?.iv) {
        st.aesKey = v.key; st.aesIv = v.iv;
        log(`[${nk}] 🔐 AES key/iv loaded`, { keyPath: keyPathAbs, keyFormat: KEY_FORMAT });

        if (!st.dataListenerAttached) {
          st._handleDataValue = async (snap) => {
            st.lastEventAt = Date.now();
            const encrypted = snap.val();
            const len = String(encrypted || "").length;
            log(`[${nk}] ⬇️ payload`, { dataPath, length: len });
            if (!encrypted) { log(`[${nk}] ℹ️ empty encrypted payload`); return; }
            if (!st.aesKey || !st.aesIv) { log(`[${nk}] ℹ️ AES key/iv not ready (post-attach)`); return; }

            try {
              const t0 = Date.now();
              const decrypted = decryptAES(encrypted, st.aesKey, st.aesIv);
              const json = JSON.parse(decrypted);
              const decryptMs = Date.now() - t0;

              const currON  = json.listIDON  || "";
              const currONC = json.listIDONC || "";
              const newON   = diffNewIDs(currON,  st.prevON);
              const newONC  = diffNewIDs(currONC, st.prevONC);

              log(`[${nk}] 🔎 diff`, { decryptMs, currON_len: splitCsv(currON).length, currONC_len: splitCsv(currONC).length, newON: newON.length, newONC: newONC.length });

              if (newON.length || newONC.length) {
                const nowSec = Math.floor(Date.now() / 1000);
                for (const id of newON)  st.updatesQueue[`${baseNode}/ActivatedTime/listIDON/${id}`]  = nowSec;
                for (const id of newONC) st.updatesQueue[`${baseNode}/ActivatedTime/listIDONC/${id}`] = nowSec;
                log(`[${nk}] ➕ queue updates`, { addON: newON, addONC: newONC, queueSize: Object.keys(st.updatesQueue).length });
                scheduleFlushNode(projectName, baseNode);
              } else {
                log(`[${nk}] 🟰 no new IDs`);
              }

              st.prevON  = currON;
              st.prevONC = currONC;
            } catch (e) {
              log(`[${nk}] ❌ decrypt/json error`, { error: e.message });
            }
          };

          st.dataRef.on("value", st._handleDataValue, (err) => {
            log(`[${nk}] Data listener error`, { error: err?.message || String(err), dataPath });
            scheduleNodeReconnect(project, baseNode);
          });
          st.dataListenerAttached = true;
          log(`[${nk}] 📌 Data listener attached AFTER key ready`, { dataPath });
        }
      } else {
        log(`[${nk}] ⚠️ ENCKEY invalid`, { keyPath: keyPathAbs, type: typeof v });
      }
    },
    (err) => {
      log(`[${nk}] ENCKEY listener error`, { error: err?.message || String(err), keyPath: keyPathAbs });
      scheduleNodeReconnect(project, baseNode);
    }
  );

  st.listenersAttached = true;
  st.failures = 0; st.backoffMs = 1000;
  log(`[${nk}] ✅ key-listener attached`, { databaseURL, baseNode, keyPath: keyPathAbs, dataPath });
}

app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.get("/status", (_req, res) => {
  const projects = PROJECTS.map(p => ({
    name: p.name,
    databaseURL: p.databaseURL,
    baseNodes: Array.isArray(p.baseNodes) ? p.baseNodes : [p.baseNode || null].filter(Boolean),
    keyNode: p.keyNode,
    dataNode: p.dataNode
  }));
  const nodes = {};
  for (const [nk, st] of Object.entries(nodeState)) {
    nodes[nk] = {
      projectName: st.projectName,
      baseNode: st.baseNode,
      listenersAttached: !!st.listenersAttached,
      dataListenerAttached: !!st.dataListenerAttached,
      lastEventAt: st.lastEventAt || 0,
      queueSize: st.updatesQueue ? Object.keys(st.updatesQueue).length : 0,
      failures: st.failures || 0,
      backoffMs: st.backoffMs || 0
    };
  }
  res.json({ keyFormat: KEY_FORMAT, startStaggerMs: START_STAGGER_MS, batchWindowMs: BATCH_WINDOW_MS, projects, nodes });
});

app.listen(PORT, () => {
  log(`HTTP listening`, { port: PORT });
  PROJECTS.forEach((p, pi) => {
    ensureProjectApp(p);
    const baseNodes = Array.isArray(p.baseNodes) ? p.baseNodes : [p.baseNode];
    baseNodes.forEach((bn, bi) => {
      setTimeout(() => attachBaseNodeListener(p, bn), (pi * baseNodes.length + bi) * START_STAGGER_MS);
    });
  });
});

process.on("SIGTERM", async () => {
  log("SIGTERM received - shutting down...");
  try {
    for (const st of Object.values(nodeState)) {
      try { st.keyRef?.off(); }  catch {}
      try { if (st.dataRef && st._handleDataValue) st.dataRef.off("value", st._handleDataValue); } catch {}
    }
    await Promise.all(Object.values(appState).map(s => s.app?.delete().catch(()=>{})));
  } finally { process.exit(0); }
});
