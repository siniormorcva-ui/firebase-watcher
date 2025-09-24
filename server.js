// server.js
// Multi-project & multi-baseNode RTDB listener (Render Web Service)
// - ENCKEY ở root (keyNode là path tuyệt đối), SetRuContent nằm dưới baseNode
// - Chỉ attach data listener sau khi key/iv sẵn sàng
// - Debounce ghi, backoff + jitter, log chi tiết
// - Cleanup: chỉ sửa listIDON & listIDONC trong SetRuContent, xoá dấu thời gian ở ActivatedTime
// - Endpoints: /healthz, /status

const express = require("express");
const admin = require("firebase-admin");
const CryptoJS = require("crypto-js");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 10000;

const START_STAGGER_MS   = Number(process.env.START_STAGGER_MS || 800);
const BATCH_WINDOW_MS    = Number(process.env.BATCH_WINDOW_MS  || 250);
const KEY_FORMAT         = (process.env.KEY_FORMAT || "utf8").toLowerCase(); // utf8|base64|hex
const TTL_SEC            = Number(process.env.TTL_SEC || 3600);              // 1 giờ
const CLEAN_INTERVAL_SEC = Number(process.env.CLEAN_INTERVAL_SEC || 60);     // quét mỗi 60s

// ---------- Logger ----------
function ts(){return new Date().toISOString();}
function j(x){try{return JSON.stringify(x);}catch{return String(x);}}
function log(msg, ctx = {}){console.log(`${ts()} ${msg} ${Object.keys(ctx).length?j(ctx):""}`);}

// ---------- Config ----------
function readProjects(){
  let arr = [];
  try{arr = JSON.parse(process.env.PROJECTS_JSON || "[]");}
  catch(e){log("❌ PROJECTS_JSON parse error",{error:e.message});process.exit(1);}
  if(!Array.isArray(arr)||arr.length===0){log("❌ PROJECTS_JSON must be a non-empty array");process.exit(1);}
  for(const p of arr){
    if(!p.name)               {log("❌ PROJECTS_JSON missing field",{field:"name"});process.exit(1);}
    if(!p.serviceAccountPath) {log("❌ PROJECTS_JSON missing field",{project:p.name,field:"serviceAccountPath"});process.exit(1);}
    if(!p.databaseURL)        {log("❌ PROJECTS_JSON missing field",{project:p.name,field:"databaseURL"});process.exit(1);}
    if(!p.baseNode && !p.baseNodes){log("❌ PROJECTS_JSON must have baseNode or baseNodes",{project:p.name});process.exit(1);}
    if(!p.keyNode)            {log("❌ PROJECTS_JSON missing field",{project:p.name,field:"keyNode"});process.exit(1);}
    if(!p.dataNode)           {log("❌ PROJECTS_JSON missing field",{project:p.name,field:"dataNode"});process.exit(1);}
  }
  return arr;
}

function loadServiceAccount(p){
  const abs = path.resolve(p);
  if(!fs.existsSync(abs)) throw new Error(`Service account not found: ${abs}`);
  return require(abs);
}

function parseKey(str){
  if(KEY_FORMAT==="utf8")   return CryptoJS.enc.Utf8.parse(str);
  if(KEY_FORMAT==="base64") return CryptoJS.enc.Base64.parse(str);
  if(KEY_FORMAT==="hex")    return CryptoJS.enc.Hex.parse(str);
  return CryptoJS.enc.Utf8.parse(str);
}
function decryptAES(ciphertext, keyStr, ivStr){
  const KEY=parseKey(keyStr), IV=parseKey(ivStr);
  const bytes = CryptoJS.AES.decrypt(ciphertext, KEY, {iv:IV, mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7});
  return bytes.toString(CryptoJS.enc.Utf8);
}
function encryptAES(plaintext, keyStr, ivStr){
  const KEY=parseKey(keyStr), IV=parseKey(ivStr);
  return CryptoJS.AES.encrypt(plaintext, KEY, {iv:IV, mode:CryptoJS.mode.CBC, padding:CryptoJS.pad.Pkcs7}).toString(); // base64
}

function splitCsv(s){return (s||"").split(",").map(x=>x.trim()).filter(Boolean);}
function diffNewIDs(currCsv, prevCsv){
  const curr = splitCsv(currCsv);
  const prev = new Set(splitCsv(prevCsv));
  return curr.filter(id=>!prev.has(id));
}

const PROJECTS = readProjects();

// ---------- Global State ----------
const appState  = Object.create(null); // appState[projectName] = { app, db }
const nodeState = Object.create(null); // nodeState["proj/base"] = {...}
function nodeKeyOf(projectName, baseNode){return `${projectName}/${baseNode}`;}

function ensureProjectApp(project){
  if(appState[project.name]) return appState[project.name];
  const svc = loadServiceAccount(project.serviceAccountPath);
  const appInst = admin.initializeApp({credential:admin.credential.cert(svc), databaseURL:project.databaseURL}, project.name);
  const db = appInst.database();
  appState[project.name] = { app:appInst, db };
  log(`[${project.name}] 🧩 app initialized`,{databaseURL:project.databaseURL});
  return appState[project.name];
}

// ---------- Debounce flush per node ----------
function scheduleFlushNode(projectName, baseNode){
  const nk = nodeKeyOf(projectName, baseNode);
  const st = nodeState[nk];
  if(st.debounceTimer) return;

  const { db } = appState[projectName];

  st.debounceTimer = setTimeout(async()=>{
    const started = Date.now();
    const payload = st.updatesQueue; st.updatesQueue = {}; st.debounceTimer = null;
    const paths = Object.keys(payload);
    if(!paths.length){log(`[${nk}] ⏭️ flush skipped (empty queue)`);return;}
    try{
      log(`[${nk}] ⬆️ flushing`,{paths:paths.length});
      await db.ref().update(payload);
      const took = Date.now()-started;
      const onCount  = paths.filter(p=>p.includes("/listIDON/")).length;
      const oncCount = paths.filter(p=>p.includes("/listIDONC/")).length;
      log(`[${nk}] ✅ flushed`,{paths:paths.length,onCount,oncCount,tookMs:took});
    }catch(e){
      log(`[${nk}] ❌ flush error`,{error:e.message,retryQueued:paths.length});
      st.updatesQueue = {...payload, ...st.updatesQueue};
      scheduleNodeReconnect({name:projectName}, baseNode, true);
    }
  }, BATCH_WINDOW_MS);
}

// ---------- Reconnect per node ----------
function scheduleNodeReconnect(project, baseNode){
  const nk = nodeKeyOf(project.name, baseNode);
  const st = nodeState[nk] || (nodeState[nk]={failures:0,backoffMs:1000});
  st.failures=(st.failures||0)+1; st.listenersAttached=false;
  const next=Math.min((st.backoffMs||1000)*2,30000)+Math.floor(Math.random()*500);
  st.backoffMs=next;
  log(`[${nk}] 🔁 scheduling reconnect`,{failures:st.failures,backoffMs:next});
  setTimeout(()=>{
    try{
      if(st.keyRef){try{st.keyRef.off();}catch{}}
      if(st.dataRef && st._handleDataValue){try{st.dataRef.off("value", st._handleDataValue);}catch{}}
    }catch{}
    attachBaseNodeListener(project, baseNode);
  }, next);
}

// ---------- Cleanup (ONLY listIDON & listIDONC) ----------
async function cleanupExpiredForNode(projectName, baseNode){
  const nk = nodeKeyOf(projectName, baseNode);
  const st = nodeState[nk];
  if(!st || st.cleaning) return;
  if(!st.aesKey || !st.aesIv){log(`[${nk}] 🕒 cleanup skip: AES key/iv not ready`);return;}
  const { db } = appState[projectName];

  st.cleaning = true;
  const started = Date.now();
  try{
    const actPath = `${baseNode}/ActivatedTime`;
    const actSnap = await db.ref(actPath).get();
    const act = actSnap.val() || {};
    const nowSec = Math.floor(Date.now()/1000);
    const expired = new Set();

    for(const listKey of ["listIDON","listIDONC"]){
      const m = act[listKey] || {};
      for(const [id, ts] of Object.entries(m)){
        const t = Number(ts)||0;
        if(t && nowSec - t >= TTL_SEC) expired.add(id);
      }
    }
    if(expired.size===0){log(`[${nk}] 🧹 cleanup: nothing expired`);return;}

    // đọc & giải mã SetRuContent
    const dataPath = `${baseNode}/${st.dataNode}`;
    const dataSnap = await db.ref(dataPath).get();
    const encrypted = dataSnap.val();

    let json = {};
    if(encrypted){
      try{
        json = JSON.parse(decryptAES(encrypted, st.aesKey, st.aesIv)) || {};
      }catch(e){
        log(`[${nk}] ❌ cleanup decrypt/JSON error`,{error:e.message});
        // vẫn tiếp tục xoá ActivatedTime để không kẹt TTL
      }
    }

    // GIỮ NGUYÊN các trường khác, CHỈ chỉnh 2 trường listIDON & listIDONC
    const beforeON  = splitCsv(json.listIDON  || "").length;
    const beforeONC = splitCsv(json.listIDONC || "").length;

    const removeIds = (csv)=> splitCsv(csv).filter(id=>!expired.has(id)).join(",");
    if(json.hasOwnProperty("listIDON"))  json.listIDON  = removeIds(json.listIDON  || "");
    if(json.hasOwnProperty("listIDONC")) json.listIDONC = removeIds(json.listIDONC || "");

    const afterON  = splitCsv(json.listIDON  || "").length;
    const afterONC = splitCsv(json.listIDONC || "").length;

    // Re-encrypt chỉ khi có SetRuContent trước đó; nếu chưa từng có, bỏ qua để không tạo mới ngoài ý muốn
    const updates = {};
    if(encrypted){
      try{
        updates[dataPath] = encryptAES(JSON.stringify(json), st.aesKey, st.aesIv);
      }catch(e){
        log(`[${nk}] ❌ cleanup re-encrypt error`,{error:e.message});
      }
    }

    // Xoá dấu thời gian cho các ID hết hạn
    for(const id of expired){
      updates[`${baseNode}/ActivatedTime/listIDON/${id}`]  = null;
      updates[`${baseNode}/ActivatedTime/listIDONC/${id}`] = null;
    }

    await db.ref().update(updates);

    log(`[${nk}] 🧽 cleanup done`,{
      expired:[...expired],
      listIDON_removed: beforeON - afterON,
      listIDONC_removed: beforeONC - afterONC,
      paths:Object.keys(updates).length,
      tookMs: Date.now()-started
    });
  }catch(e){
    log(`[${nk}] ❌ cleanup error`,{error:e.message});
  }finally{
    st.cleaning=false;
    st.lastCleanupAt=Date.now();
  }
}

// ---------- Attach listeners ----------
function attachBaseNodeListener(project, baseNode){
  const { name:projectName, databaseURL, keyNode="ENCKEY", dataNode="SetRuContent" } = project;
  const { db } = ensureProjectApp(project);
  const nk = nodeKeyOf(projectName, baseNode);

  if(!nodeState[nk]){
    nodeState[nk] = {
      projectName, baseNode, databaseURL, keyNode, dataNode,
      aesKey:null, aesIv:null,
      prevON:"", prevONC:"",
      lastEventAt:0,
      updatesQueue:{}, debounceTimer:null,
      listenersAttached:false, failures:0, backoffMs:1000,
      keyRef:null, dataRef:null, dataListenerAttached:false, _handleDataValue:null,
      cleaning:false, lastCleanupAt:0
    };
  }
  const st = nodeState[nk];
  if(st.listenersAttached) return;

  const keyPathAbs = keyNode.startsWith("/")? keyNode.slice(1): keyNode; // ENCKEY ở root
  st.keyRef  = db.ref(keyPathAbs);
  const dataPath = `${baseNode}/${dataNode}`;
  st.dataRef = db.ref(dataPath);

  // Chỉ khi có key/iv mới attach data listener
  st.keyRef.on("value",
    (snap)=>{
      const v = snap.val();
      if(v?.key && v?.iv){
        st.aesKey=v.key; st.aesIv=v.iv;
        log(`[${nk}] 🔐 AES key/iv loaded`,{keyPath:keyPathAbs,keyFormat:KEY_FORMAT});

        if(!st.dataListenerAttached){
          st._handleDataValue = async (snap)=>{
            st.lastEventAt = Date.now();
            const encrypted = snap.val();
            const len = String(encrypted||"").length;
            log(`[${nk}] ⬇️ payload`,{dataPath,length:len});
            if(!encrypted){log(`[${nk}] ℹ️ empty encrypted payload`);return;}
            if(!st.aesKey || !st.aesIv){log(`[${nk}] ℹ️ AES key/iv not ready (post-attach)`);return;}

            try{
              const t0=Date.now();
              const json = JSON.parse(decryptAES(encrypted, st.aesKey, st.aesIv));
              const decryptMs = Date.now()-t0;

              const currON  = json.listIDON  || "";
              const currONC = json.listIDONC || "";

              const newON  = diffNewIDs(currON,  st.prevON);
              const newONC = diffNewIDs(currONC, st.prevONC);

              log(`[${nk}] 🔎 diff`,{decryptMs,currON_len:splitCsv(currON).length,currONC_len:splitCsv(currONC).length,newON:newON.length,newONC:newONC.length});

              if(newON.length || newONC.length){
                const nowSec=Math.floor(Date.now()/1000);
                for(const id of newON)  st.updatesQueue[`${baseNode}/ActivatedTime/listIDON/${id}`]  = nowSec;
                for(const id of newONC) st.updatesQueue[`${baseNode}/ActivatedTime/listIDONC/${id}`] = nowSec;
                log(`[${nk}] ➕ queue updates`,{addON:newON,addONC:newONC,queueSize:Object.keys(st.updatesQueue).length});
                scheduleFlushNode(projectName, baseNode);
              }else{
                log(`[${nk}] 🟰 no new IDs`);
              }

              st.prevON  = currON;
              st.prevONC = currONC;
            }catch(e){
              log(`[${nk}] ❌ decrypt/json error`,{error:e.message});
            }
          };

          st.dataRef.on("value", st._handleDataValue, (err)=>{
            log(`[${nk}] Data listener error`,{error:err?.message||String(err),dataPath});
            scheduleNodeReconnect(project, baseNode);
          });
          st.dataListenerAttached = true;
          log(`[${nk}] 📌 Data listener attached AFTER key ready`,{dataPath});
        }
      }else{
        log(`[${nk}] ⚠️ ENCKEY invalid`,{keyPath:keyPathAbs,type:typeof v});
      }
    },
    (err)=>{
      log(`[${nk}] ENCKEY listener error`,{error:err?.message||String(err),keyPath:keyPathAbs});
      scheduleNodeReconnect(project, baseNode);
    }
  );

  st.listenersAttached=true; st.failures=0; st.backoffMs=1000;
  log(`[${nk}] ✅ key-listener attached`,{databaseURL,baseNode,keyPath:keyPathAbs,dataPath});
}

// ---------- Endpoints ----------
app.get("/healthz", (_req,res)=>res.status(200).send("ok"));
app.get("/status", (_req,res)=>{
  const projects = PROJECTS.map(p=>({
    name:p.name, databaseURL:p.databaseURL,
    baseNodes: Array.isArray(p.baseNodes)?p.baseNodes:[p.baseNode||null].filter(Boolean),
    keyNode:p.keyNode, dataNode:p.dataNode
  }));
  const nodes={};
  for(const [nk,st] of Object.entries(nodeState)){
    nodes[nk]={
      projectName:st.projectName, baseNode:st.baseNode,
      listenersAttached:!!st.listenersAttached, dataListenerAttached:!!st.dataListenerAttached,
      lastEventAt:st.lastEventAt||0, queueSize:st.updatesQueue?Object.keys(st.updatesQueue).length:0,
      failures:st.failures||0, backoffMs:st.backoffMs||0, lastCleanupAt:st.lastCleanupAt||0
    };
  }
  res.json({keyFormat:KEY_FORMAT,startStaggerMs:START_STAGGER_MS,batchWindowMs:BATCH_WINDOW_MS,ttlSec:TTL_SEC,cleanIntervalSec:CLEAN_INTERVAL_SEC,projects,nodes});
});

// ---------- Start ----------
app.listen(PORT, ()=>{
  log(`HTTP listening`,{port:PORT});
  PROJECTS.forEach((p,pi)=>{
    ensureProjectApp(p);
    const baseNodes = Array.isArray(p.baseNodes)?p.baseNodes:[p.baseNode];
    baseNodes.forEach((bn,bi)=>{
      setTimeout(()=>attachBaseNodeListener(p,bn),(pi*baseNodes.length+bi)*START_STAGGER_MS);
    });
  });

  // Interval cleanup cho mọi node
  setInterval(()=>{
    for(const st of Object.values(nodeState)){
      cleanupExpiredForNode(st.projectName, st.baseNode)
        .catch(e=>log(`[${st.projectName}/${st.baseNode}] ❌ cleanup interval error`,{error:e.message}));
    }
  }, CLEAN_INTERVAL_SEC*1000);
});

// ---------- Graceful shutdown ----------
process.on("SIGTERM", async ()=>{
  log("SIGTERM received - shutting down...");
  try{
    for(const st of Object.values(nodeState)){
      try{st.keyRef?.off();}catch{}
      try{if(st.dataRef && st._handleDataValue) st.dataRef.off("value", st._handleDataValue);}catch{}
    }
    await Promise.all(Object.values(appState).map(s=>s.app?.delete().catch(()=>{})));
  }finally{process.exit(0);}
});
