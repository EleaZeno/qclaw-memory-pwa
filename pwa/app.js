// QClaw 记忆体 PWA — iPhone Face ID decrypt client.
// Crypto path verified byte-identical against the Node engine (test-interop.mjs).
//
// Trust model:
//  - GitHub token: read-only, stored only in this device's localStorage.
//  - WebAuthn passkey (Face ID) with PRF extension derives a stable 32-byte secret.
//  - That secret (AES-GCM) wraps the device X25519 private key in localStorage.
//  - Face ID -> PRF -> unwrap device priv -> unwrap DEK from keyring -> decrypt memory.
//  - Nothing decryptable leaves the device; GitHub only ever holds ciphertext.

const REPO = 'EleaZeno/qclaw-memory';
const BRANCH = 'main';
const RP_ID = location.hostname;               // passkey bound to this origin
const PRF_SALT = new TextEncoder().encode('qclaw-mem-prf-v2');
const subtle = crypto.subtle;

const $ = id => document.getElementById(id);
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = new TextEncoder(), dec = new TextDecoder();
const LS = {
  token: 'qclaw.ghtoken',
  cred:  'qclaw.cred',        // passkey credential id
  dev:   'qclaw.devblob',     // PRF-encrypted device private key
};

function setStatus(id, msg, cls=''){ const e=$(id); e.textContent=msg; e.className='status '+cls; }

// ---------- GitHub read ----------
async function ghGet(path){
  const token = localStorage.getItem(LS.token);
  const r = await fetch(`https://api.github.com/repos/${REPO}/contents/${path}?ref=${BRANCH}`,{
    headers:{ Authorization:`token ${token}`, Accept:'application/vnd.github.raw+json', 'User-Agent':'qclaw-pwa' }
  });
  if(r.status===404) return null;
  if(!r.ok) throw new Error(`GitHub ${path} -> ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}
async function ghGetJson(path){ const b=await ghGet(path); return b? JSON.parse(dec.decode(b)) : null; }

// ---------- X25519 / AES helpers (match Node engine) ----------
function rawToSpki(raw32){ const p=unb64('MCowBQYDK2VuAyEA'); const o=new Uint8Array(p.length+32); o.set(p); o.set(raw32,p.length); return o; }
function spkiToRaw(der){ return der.slice(-32); }

async function aesGcmDecrypt(keyBytes, obj, aad){
  const key = await subtle.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['decrypt']);
  const combined = new Uint8Array([...unb64(obj.ct), ...unb64(obj.tag)]);
  const params = {name:'AES-GCM', iv:unb64(obj.iv)};
  if(aad) params.additionalData = aad;
  return new Uint8Array(await subtle.decrypt(params, key, combined));
}

// unwrap DEK from a keyring wrap {ephPub, iv, ct, tag} using device raw priv (32b)
async function unwrapDEK(devPrivRaw, wrap){
  // import device private key (PKCS8). WebCrypto can't import raw X25519 priv directly,
  // so the device blob stores PKCS8 DER.
  const priv = await subtle.importKey('pkcs8', devPrivRaw, {name:'X25519'}, false, ['deriveBits']);
  const ephRaw = spkiToRaw(unb64(wrap.ephPub));
  const ephPub = await subtle.importKey('raw', ephRaw, {name:'X25519'}, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({name:'X25519', public:ephPub}, priv, 256));
  const hk = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const wrapKeyBits = await subtle.deriveBits(
    {name:'HKDF', hash:'SHA-256', salt:unb64(wrap.ephPub), info:enc.encode('qclaw-mem-wrap-v2')}, hk, 256);
  return aesGcmDecrypt(new Uint8Array(wrapKeyBits), wrap);
}

// AES-GCM encrypt (match Node: returns {iv,ct,tag} with tag split off the WebCrypto blob)
async function aesGcmEncrypt(keyBytes, plain, aad){
  const key = await subtle.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = {name:'AES-GCM', iv};
  if(aad) params.additionalData = aad;
  const combined = new Uint8Array(await subtle.encrypt(params, key, plain)); // ct||tag(16)
  const ct = combined.slice(0, combined.length-16);
  const tag = combined.slice(combined.length-16);
  return { iv:b64(iv), ct:b64(ct), tag:b64(tag) };
}

// ECIES seal: wrap a DEK to a recipient X25519 public key (SPKI DER, b64). Mirrors Node sealToRecipient.
async function sealToRecipient(recipientPubDerB64, dek){
  const recipRaw = spkiToRaw(unb64(recipientPubDerB64));
  const recipPub = await subtle.importKey('raw', recipRaw, {name:'X25519'}, false, []);
  const eph = await subtle.generateKey({name:'X25519'}, true, ['deriveBits']);
  const shared = new Uint8Array(await subtle.deriveBits({name:'X25519', public:recipPub}, eph.privateKey, 256));
  const ephPubRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const ephPubDer = rawToSpki(ephPubRaw);
  const hk = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const wrapKeyBits = await subtle.deriveBits(
    {name:'HKDF', hash:'SHA-256', salt:ephPubDer, info:enc.encode('qclaw-mem-wrap-v2')}, hk, 256);
  const wrapped = await aesGcmEncrypt(new Uint8Array(wrapKeyBits), dek);
  return { ephPub:b64(ephPubDer), ...wrapped };
}

async function deviceIdFromPubDer(pubDerB64){
  const idBuf = new Uint8Array(await subtle.digest('SHA-256', enc.encode(pubDerB64)));
  return [...idBuf].map(x=>x.toString(16).padStart(2,'0')).join('').slice(0,16);
}

// Find OUR enrolled wrap in the keyring and recover the DEK with the unlocked device priv.
async function recoverDEK(){
  const keyring = await ghGetJson('keyring.json');
  if(!keyring) throw new Error('仓库缺 keyring.json');
  for(const id of Object.keys(keyring.wraps)){
    try{ return await unwrapDEK(SESSION.devPriv, keyring.wraps[id]); }catch(e){}
  }
  throw new Error('本机私钥解不开任何 keyring 信封（未授权？）');
}

// APPROVE a new device: take its recover-request, seal the DEK to its pubkey, emit grant.
async function grantNewDevice(reqJson){
  let req; try{ req = JSON.parse(reqJson.trim()); }catch{ throw new Error('恢复请求不是合法 JSON'); }
  if(req.kind!=='qclaw.recover-request.v1' || !req.pubDer || !req.id) throw new Error('不是 recover-request.v1 令牌');
  if(await deviceIdFromPubDer(req.pubDer)!==req.id) throw new Error('请求 id 与公钥不符（可能被篡改）');
  if(!SESSION.devPriv) throw new Error('请先 Face ID 解锁');
  const dek = await recoverDEK();                      // iPhone recovers DEK
  const wrap = await sealToRecipient(req.pubDer, dek);  // seal DEK to NEW device pubkey
  // figure out our own device id (the approver), best-effort
  let approver = localStorage.getItem('qclaw.devid') || null;
  const grant = { kind:'qclaw.grant.v1', id:req.id, label:req.label||'recovered-device',
                  pubDer:req.pubDer, wrap, approver, at:new Date().toISOString() };
  return JSON.stringify(grant);
}

// ---------- WebAuthn (Face ID) with PRF ----------
async function enrollPasskey(){
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const cred = await navigator.credentials.create({ publicKey:{
    rp:{ id:RP_ID, name:'QClaw Memory' },
    user:{ id:userId, name:'EleaZeno', displayName:'QClaw 记忆体' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams:[{type:'public-key', alg:-7},{type:'public-key', alg:-257}],
    authenticatorSelection:{ residentKey:'required', userVerification:'required' },
    extensions:{ prf:{} },
  }});
  localStorage.setItem(LS.cred, b64(cred.rawId));
  return cred;
}
async function prfSecret(){
  const credId = localStorage.getItem(LS.cred);
  const assertion = await navigator.credentials.get({ publicKey:{
    rpId: RP_ID,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: credId ? [{type:'public-key', id:unb64(credId)}] : [],
    userVerification:'required',
    extensions:{ prf:{ eval:{ first: PRF_SALT } } },
  }});
  const res = assertion.getClientExtensionResults();
  if(!res.prf || !res.prf.results || !res.prf.results.first)
    throw new Error('PRF 不支持（需 iOS 18+ Safari / 支持 PRF 的 passkey）。');
  return new Uint8Array(res.prf.results.first); // 32 bytes, stable per credential+salt
}

// ---------- bootstrap / unlock ----------
let SESSION = { devPriv:null };  // in-memory only, cleared on lock

// Generate this phone's OWN X25519 keypair. Private key (PKCS8) is encrypted with
// the Face-ID PRF secret and stored locally. Public key is shown for the laptop to
// authorize via `add-device`.
async function genDeviceKeypair(){
  const kp = await subtle.generateKey({name:'X25519'}, true, ['deriveBits']);
  const privPkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  const pubRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const pubDer = rawToSpki(pubRaw);
  // encrypt private key with Face ID PRF
  const prf = await prfSecret();                       // Face ID
  const key = await subtle.importKey('raw', prf, {name:'AES-GCM'}, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({name:'AES-GCM', iv}, key, privPkcs8));
  localStorage.setItem(LS.dev, JSON.stringify({ iv:b64(iv), ct:b64(ct) }));
  // device id = first 16 hex of sha256(pubDer base64) to match Node engine
  const idBuf = new Uint8Array(await subtle.digest('SHA-256', enc.encode(b64(pubDer))));
  const id = [...idBuf].map(x=>x.toString(16).padStart(2,'0')).join('').slice(0,16);
  localStorage.setItem('qclaw.devid', id);
  return { id, label:'iPhone', pubDer:b64(pubDer) };
}

async function unlockDevice(){
  const stored = JSON.parse(localStorage.getItem(LS.dev));
  const prf = await prfSecret();                       // Face ID
  const key = await subtle.importKey('raw', prf, {name:'AES-GCM'}, false, ['decrypt']);
  SESSION.devPriv = new Uint8Array(await subtle.decrypt({name:'AES-GCM', iv:unb64(stored.iv)}, key, unb64(stored.ct)));
}

// ---------- memory pull ----------
async function pullMemory(){
  const keyring = await ghGetJson('keyring.json');
  const manifest = await ghGetJson('manifest.v2.json');
  if(!keyring || !manifest) throw new Error('仓库缺 keyring/manifest（先在电脑端 push）。');
  // find our device's wrap: match by deriving our pubkey? simpler: try each wrap.
  let dek=null;
  for(const id of Object.keys(keyring.wraps)){
    try{ dek = await unwrapDEK(SESSION.devPriv, keyring.wraps[id]); break; }catch(e){}
  }
  if(!dek) throw new Error('本设备私钥无法解开任何 keyring 信封（未授权或绑错 blob）。');
  const files=[];
  for(const f of manifest.files){
    const encObj = await ghGetJson(f.enc);
    const pt = await aesGcmDecrypt(dek, encObj, enc.encode(f.path));
    files.push({ path:f.path, bytes:f.bytes, text: dec.decode(pt) });
  }
  return files;
}

// ---------- UI wiring ----------
function refreshCards(){
  $('card-auth').classList.toggle('hidden', !localStorage.getItem(LS.token));
  const hasDev = !!localStorage.getItem(LS.dev);
  $('card-bootstrap').classList.toggle('hidden', !localStorage.getItem(LS.cred) || hasDev);
  $('btn-enroll').classList.toggle('hidden', !!localStorage.getItem(LS.cred));
  if(hasDev){ $('card-mem').classList.remove('hidden'); if($('card-grant')) $('card-grant').classList.remove('hidden'); }
}

$('btn-save-token').onclick = ()=>{
  const t=$('ghtoken').value.trim();
  if(!t){ setStatus('setup-status','请输入 token','err'); return; }
  localStorage.setItem(LS.token, t);
  setStatus('setup-status','✅ 已保存（仅本机）','ok'); refreshCards();
};
$('btn-enroll').onclick = async ()=>{
  try{ setStatus('auth-status','请看屏幕完成 Face ID…'); await enrollPasskey();
    setStatus('auth-status','✅ passkey 已注册','ok'); refreshCards();
  }catch(e){ setStatus('auth-status','❌ '+e.message,'err'); }
};
$('btn-gen').onclick = async ()=>{
  try{ setStatus('bind-status','Face ID 生成并加密密钥…'); const dev=await genDeviceKeypair();
    const payload=JSON.stringify(dev);
    $('pubout').value=payload; $('pubout').classList.remove('hidden');
    setStatus('bind-status','✅ 已生成。把上面整段发给电脑端运行：node mem-sync.mjs add-device \'<粘贴>\'','ok');
    $('card-mem').classList.remove('hidden');
  }catch(e){ setStatus('bind-status','❌ '+e.message,'err'); }
};
$('btn-unlock').onclick = async ()=>{
  try{ if(!localStorage.getItem(LS.dev)){setStatus('auth-status','请先绑定设备密钥(③)','err');return;}
    setStatus('auth-status','Face ID 解锁中…'); await unlockDevice();
    setStatus('auth-status','✅ 已解锁','ok'); $('card-mem').classList.remove('hidden'); if($('card-grant')) $('card-grant').classList.remove('hidden');
  }catch(e){ setStatus('auth-status','❌ '+e.message,'err'); }
};
$('btn-pull').onclick = async ()=>{
  try{ if(!SESSION.devPriv){setStatus('mem-status','请先 Face ID 解锁','err');return;}
    setStatus('mem-status','拉取解密中…'); const files=await pullMemory();
    setStatus('mem-status',`✅ 解密 ${files.length} 个文件`,'ok');
    const list=$('filelist'); list.innerHTML='';
    for(const f of files){ const d=document.createElement('div'); d.className='file';
      d.innerHTML=`<span class="n">${f.path}</span><span class="b">${f.bytes}b</span>`;
      d.onclick=()=>{ $('viewer').textContent=f.text; $('viewer').classList.remove('hidden'); window.scrollTo(0,document.body.scrollHeight); };
      list.appendChild(d); }
  }catch(e){ setStatus('mem-status','❌ '+e.message,'err'); }
};
$('btn-lock').onclick = ()=>{ SESSION.devPriv=null; $('filelist').innerHTML=''; $('viewer').classList.add('hidden');
  setStatus('mem-status','已锁定'); };

// ---------- authorize a NEW device (laptop-free recovery) ----------
if($('btn-grant')) $('btn-grant').onclick = async ()=>{
  try{
    if(!SESSION.devPriv){ setStatus('grant-status','请先 Face ID 解锁(②)','err'); return; }
    const reqJson = $('grant-req').value;
    if(!reqJson.trim()){ setStatus('grant-status','请粘贴新设备的恢复请求','err'); return; }
    setStatus('grant-status','刷脸授权中…');
    const token = await grantNewDevice(reqJson);
    $('grant-out').value = token; $('grant-out').classList.remove('hidden');
    setStatus('grant-status','✅ 已生成授权令牌。把上面整段回传给新设备/助手运行 ingest-grant','ok');
  }catch(e){ setStatus('grant-status','❌ '+e.message,'err'); }
};

// boot
if(localStorage.getItem(LS.token)) $('ghtoken').placeholder='已保存（重输可覆盖）';
refreshCards();
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});
