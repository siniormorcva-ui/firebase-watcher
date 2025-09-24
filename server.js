// server.js
// Realtime multi-project Firebase RTDB listener for Render Web Service
// - Mỗi project = 1 admin.app() + 2 listener (ENCKEY, SetRuContent)
// - Log chi tiết theo từng sự kiện
// - Debounce ghi (reduce update spam)
// - Exponential backoff + jitter khi gặp lỗi listener/flush
// - Endpoints: /healthz, /status

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

// ========== Logger ==========
function ts() { return new Date().toISOString(); }
function j(obj) { try { return JSON.stringify(obj); } catch { return String(obj); } }
function log(msg, ctx = {}) {
  // Log một dòng thống nhất: thời gian + message + context JSON
  const line = `${ts()} ${msg} ${Object.keys(ctx).length ? j(ctx) : ""}`;
  console.log(line);
}

// ========== Config đọc từ env ==========
function readProjects() {
  let arr = [];
  try {
    arr = JSON.parse(process.env.PROJECTS_JSON || "[]");
  } catch (e) {
    log("❌ PROJECTS_JSON parse error", { error: e.message });
    process.exit(1);
  }
  if (!Array.isArray(arr) || arr.length === 0) {
    log("❌ PROJECTS_JSON must be a non-empty array");
    process.exit(1);
  }
  // sanitize field bắt buộc
  for (const p of arr) {
    for (const k of ["name", "serviceAccountPath", "databaseURL", "baseNode"]) {
      if (!p[k]) {
        log("❌ PROJECTS_JSON missing required field", { project: p.name || "unknown", field: k });
        process.exit(1);
      }
    }
  }
  return arr;
}

function loadServiceAccount(p) {
  const abs = path.resolve(p);
  if (!fs.existsSync(abs)) throw new Error(`Service account not found: ${abs}`);
  return require(abs);
}

// Parse key theo KEY_FORMAT
function parseKey(dataStr) {
  if (KEY_FORMAT === "utf8")   return CryptoJS.enc.Utf8.parse(dataStr);
  if (KEY_FORMAT === "base64") return CryptoJS.enc.Base64.parse(dataStr);
  if (KEY_FORMAT === "hex")    return CryptoJS.enc.Hex.parse(dataStr);
  // fallback
  return CryptoJS.enc.Utf8.parse(dataStr);
}

function decryptAES(ciphertext, keyStr, ivStr) {
  const KEY = parseKey(keyStr);
  const IV  = parseKey(ivStr);
  const bytes = CryptoJS.AES.decrypt(ciphertext, KEY, {
    iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7
  });
  return bytes.toString(CryptoJS.enc.Utf8);
}

// CSV helper
function splitCsv(s) { return (s || "").split(",").map(x=>x.trim()).filter(Boolean); }
function diffNewIDs(currCsv, prevCsv) {
  const curr = splitCsv(currCsv);
  const prev = new Set(splitCsv(prevCsv));
  return curr.filter(id => !prev.has(id));
}

const PROJECTS = readProjects();

// ========== Global state ==========
/*
state[name] = {
  app, db,
  aesKey, aesIv,
  prevON, prevONC,
  lastEventAt, // epoch ms
  updatesQueue, // {path: value}
  debounceTimer,
  listenersAttached, // boolean
  failures, backoffMs
}
*/
const state = Object.create(null);

// ========== Attach listener cho 1 project ==========
function attachProject(project) {
  const {
    name, serviceAccountPath, databaseURL,
    baseNode, keyNode = "ENCKEY", dataNode = "SetRuContent"
  } = project;

  // init state nếu chưa có
  state[name] = state[name] || {
    app: null, db: null,
    aesKey: null, aesIv: null,
    prevON: "", prevONC: "",
    lastEventAt: 0,
    updatesQueue: {},
    debounceTimer: null,
    listenersAttached: false,
    failures: 0,
    backoffMs: 1000
  };

  // đã attach rồi thì bỏ qua
  if (state[name].listenersAttached) return;

  try {
    const svc = loadServiceAccount(serviceAccountPath);
    const appInst = admin.initializeApp({
      credential: admin.credential.cert(svc),
      databaseURL
    }, name);

    const db = appInst.database();
    state[name].app = appInst;
    state[name].db  = db;

    const keyRef  = db.ref(`${baseNode}/${keyNode}`);
    const dataRef = db.ref(`${baseNode}/${dataNode}`);

    // --- ENCKEY listener ---
    keyRef.on("value",
      (snap) => {
        const v = snap.val();
        if (v?.key && v?.iv) {
          state[name].aesKey = v.key;
          state[name].aesIv  = v.iv;
          log(`[${name}] 🔐 AES key/iv loaded`, { node: `${baseNode}/${keyNode}`, keyFormat: KEY_FORMAT });
        } else {
          log(`[${name}] ⚠️ ENCKEY invalid`, { node: `${baseNode}/${keyNode}`, valueType: typeof v });
        }
      },
      (err) => {
        log(`[${name}] ENCKEY listener error`, { error: err?.message || String(err) });
        scheduleReconnect(name, project);
      }
    );

    // --- Data listener ---
    dataRef.on("value",
      async (snap) => {
        state[name].lastEventAt = Date.now();
        const encrypted = snap.val();
        const len = String(encrypted || "").length;
        log(`[${name}] ⬇️ payload`, { node: `${baseNode}/${dataNode}`, length: len });

        const { aesKey, aesIv } = state[name];
        if (!encrypted || !aesKey || !aesIv) {
          // có thể key chưa nạp kịp; bỏ qua
          if (!encrypted) log(`[${name}] ℹ️ empty encrypted payload`);
          if (!aesKey || !aesIv) log(`[${name}] ℹ️ AES key/iv not ready yet`);
          return;
        }

        try {
          const t0 = Date.now();
          const decrypted = decryptAES(encrypted, aesKey, aesIv);
          const json = JSON.parse(decrypted);
          const decryptMs = Date.now() - t0;

          const currON  = json.listIDON  || "";
          const currONC = json.listIDONC || "";

          const newON   = diffNewIDs(currON,  state[name].prevON);
          const newONC  = diffNewIDs(currONC, state[name].prevONC);

          log(`[${name}] 🔎 diff`, {
            decryptMs,
            currON_len: splitCsv(currON).length,
            currONC_len: splitCsv(currONC).length,
            newON: newON.length, newONC: newONC.length
          });

          if (newON.length || newONC.length) {
            const nowSec = Math.floor(Date.now() / 1000);
            for (const id of newON)  {
              state[name].updatesQueue[`${baseNode}/ActivatedTime/listIDON/${id}`]  = nowSec;
            }
            for (const id of newONC) {
              state[name].updatesQueue[`${baseNode}/ActivatedTime/listIDONC/${id}`] = nowSec;
            }
            log(`[${name}] ➕ queue updates`, {
              addON: newON, addONC: newONC,
              queueSize: Object.keys(state[name].updatesQueue).length
            });
            scheduleFlush(name);
          } else {
            log(`[${name}] 🟰 no new IDs`);
          }

          state[name].prevON  = currON;
          state[name].prevONC = currONC;
        } catch (e) {
          log(`[${name}] ❌ decrypt/json error`, { error: e.message });
        }
      },
      (err) => {
        log(`[${name}] Data listener error`, { error: err?.message || String(err), node: `${baseNode}/${dataNode}` });
        scheduleReconnect(name, project);
      }
    );

    state[name].listenersAttached = true;
    state[name].failures = 0;
    state[name].backoffMs = 1000;

    log(`[${name}] ✅ listeners attached`, { databaseURL, baseNode, keyNode, dataNode });
  } catch (e) {
    log(`[${name}] ❌ attachProject error`, { error: e.message });
    scheduleReconnect(name, project);
  }
}

// Debounce & flush multi-path update
function scheduleFlush(name) {
  const st = state[name];
  if (st.debounceTimer) return;

  st.debounceTimer = setTimeout(async () => {
    const started = Date.now();
    const payload = st.updatesQueue;
    st.updatesQueue = {};
    st.debounceTimer = null;

    const paths = Object.keys(payload);
    if (paths.length === 0) {
      log(`[${name}] ⏭️ flush skipped (empty queue)`);
      return;
    }

    try {
      log(`[${name}] ⬆️ flushing`, { paths: paths.length });
      await st.db.ref().update(payload);
      const took = Date.now() - started;

      // đếm theo nhóm
      const onCount  = paths.filter((p) => p.includes("/listIDON/")).length;
      const oncCount = paths.filter((p) => p.includes("/listIDONC/")).length;

      log(`[${name}] ✅ flushed`, { paths: paths.length, onCount, oncCount, tookMs: took });
    } catch (e) {
      log(`[${name}] ❌ flush error`, { error: e.message, retryQueued: paths.length });
      // trả lại queue để thử lại
      st.updatesQueue = { ...payload, ...st.updatesQueue };
      scheduleReconnect(name, null, true);
    }
  }, BATCH_WINDOW_MS);
}

// Reconnect với exponential backoff + jitter
function scheduleReconnect(name, project, onlyReattach = false) {
  const st = state[name] || (state[name] = {});
  st.failures = (st.failures || 0) + 1;
  st.listenersAttached = false;

  const next = Math.min((st.backoffMs || 1000) * 2, 30000) + Math.floor(Math.random() * 500);
  st.backoffMs = next;

  log(`[${name}] 🔁 scheduling reconnect`, { failures: st.failures, backoffMs: next });

  setTimeout(() => {
    try {
      if (st.app) {
        st.app.delete().then(() => {
          log(`[${name}] 🧹 app deleted before reattach`);
        }).catch(() => {});
      }
    } catch {}
    if (project) {
      log(`[${name}] 🔗 reattaching listeners...`);
      attachProject(project);
    }
  }, next);
}

// ========== HTTP endpoints ==========
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

app.get("/status", (_req, res) => {
  const summary = {};
  for (const [name, st] of Object.entries(state)) {
    summary[name] = {
      listenersAttached: !!st.listenersAttached,
      lastEventAt: st.lastEventAt || 0,
      queueSize: st.updatesQueue ? Object.keys(st.updatesQueue).length : 0,
      failures: st.failures || 0,
      backoffMs: st.backoffMs || 0
    };
  }
  res.json({
    projects: PROJECTS.map(p => ({
      name: p.name,
      databaseURL: p.databaseURL,
      baseNode: p.baseNode
    })),
    keyFormat: KEY_FORMAT,
    startStaggerMs: START_STAGGER_MS,
    batchWindowMs: BATCH_WINDOW_MS,
    state: summary
  });
});

// ========== Start server & attach listeners so le ==========
app.listen(PORT, () => {
  log(`HTTP listening`, { port: PORT });
  PROJECTS.forEach((p, i) => {
    setTimeout(() => attachProject(p), i * START_STAGGER_MS);
  });
});

// Graceful shutdown (Render)
process.on("SIGTERM", async () => {
  log("SIGTERM received - shutting down...");
  await Promise.all(Object.values(state).map(s => s.app?.delete().catch(()=>{})));
  process.exit(0);
});
