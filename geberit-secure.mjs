/**
 * Geberit DuoFresh BLE control — Security + DataPoint read/write
 *
 * Protocol stack: inner CobsFraming → HdlcFlowControl → SecurityServer →
 *                 outer CobsFraming → ConfigurationManager → FrameHandler
 *
 * Crypto: X25519 + HKDF-SHA256 + AES-CTR (stateful, per aj.cs) + AES-CMAC
 * DataPoint wire format: [CommandId, DpId_lo, DpId_hi(+bit7 if instanced), (instance?), value...]
 *
 * Usage:
 *   node geberit-secure.mjs --scan [--timeout <seconds>]
 *   node geberit-secure.mjs --get   <BLE_address>
 *   node geberit-secure.mjs --dump  <BLE_address> <file.json>
 *   node geberit-secure.mjs --write <BLE_address> <file.json>
 */

import { createBluetooth } from 'node-ble';
import dbus, { Variant } from 'dbus-next';
import { readFileSync, writeFileSync } from 'fs';
import {
  randomBytes, createPrivateKey, createPublicKey, diffieHellman,
  hkdfSync, createCipheriv,
} from 'crypto';

// ── BLE constants ──────────────────────────────────────────────────────────────
const CMD_SVC     = '0000fd48-0000-1000-8000-00805f9b34fb';
const WRITE_CHAR  = '559eb001-2390-11e8-b467-0ed5f89f718b';
const NOTIFY_CHAR = '559eb002-2390-11e8-b467-0ed5f89f718b';
const DIS_SVC     = '0000180a-0000-1000-8000-00805f9b34fb';

// Bridge key (pre-shared, hardcoded in SecurityServer.cs, keyset 0)
const BRIDGE_KEY = Buffer.from([
  0xD1, 0x21, 0x8A, 0x89, 0xF6, 0x0A, 0xC2, 0x94,
  0x2D, 0x44, 0x20, 0x79, 0x74, 0x50, 0x97, 0xBE,
]);

// ── DataPoint IDs ──────────────────────────────────────────────────────────────
// All 1-byte (Enum/OffOn/OffOnAuto) unless noted
const DP = {
  ODOUR_POWER:       27,   // Enum 0-4, fan intensity
  ODOUR_MODE:        23,   // OffOnAuto 0-2
  ODOUR_FOLLOW_UP:   29,   // Enum 0-4, run-on time
  ODOUR_SENS:        32,   // Enum 0-4, sensor sensitivity
  LIGHT_MODE:        44,   // OffOnAuto 0-2
  LIGHT_INTENSITY:   48,   // Enum 0-4
  LIGHT_FOLLOW_UP:   50,   // Enum 0-4
  LIGHT_SENS:        53,   // Enum 0-4
  // Time slots (instanced 0-9):
  SLOT_ENABLE:       346,  // OffOn 0=disabled, 1=enabled
  SLOT_START:        347,  // Counter uint32 LE (seconds since midnight)
  SLOT_END:          348,  // Counter uint32 LE (seconds since midnight)
  SLOT_LIGHT_MODE:   610,  // OffOnAuto 0=Off, 1=On, 2=Auto
  SLOT_LIGHT_INT:    760,  // Enum 0-4 (brightness steps)
  SLOT_FAN_MODE:     609,  // OffAuto 0=Off, 1=Auto
  SLOT_FAN_INT:      561,  // Enum 0-4 (fan intensity steps)
  // Slot names: NOT instanced — one DpId per slot, String up to 80 bytes, NVM
  SLOT_NAME:        [1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109],
  // Device info — all return ReadError on RS8.0; use BLE DIS (0x180A) instead
  // Filter maintenance:
  FILTER_USAGE:       39,  // Enum 0-4 (0=OK … 4=replace now) — confirmed working
  // 924/925/928 (remaining credits/days/replacements) return ReadError on RS8.0 TS107
};

// ── CLI parsing ────────────────────────────────────────────────────────────────
function usage() {
  console.error([
    'Usage:',
    '  node geberit-secure.mjs --scan [--timeout <seconds>]',
    '  node geberit-secure.mjs --get   <BLE_address>',
    '  node geberit-secure.mjs --dump  <BLE_address> <file.json>',
    '  node geberit-secure.mjs --write <BLE_address> <file.json>',
  ].join('\n'));
  process.exit(1);
}

const argv = process.argv.slice(2);
let MODE, BLE_ADDRESS, JSON_FILE, SCAN_TIMEOUT = 10000;

if (argv[0] === '--scan') {
  MODE = 'scan';
  const ti = argv.indexOf('--timeout');
  if (ti !== -1) SCAN_TIMEOUT = parseInt(argv[ti + 1], 10) * 1000;
} else if (argv[0] === '--get' && argv[1]) {
  MODE = 'get'; BLE_ADDRESS = argv[1].toUpperCase();
} else if (argv[0] === '--dump' && argv[1] && argv[2]) {
  MODE = 'dump'; BLE_ADDRESS = argv[1].toUpperCase(); JSON_FILE = argv[2];
} else if (argv[0] === '--write' && argv[1] && argv[2]) {
  MODE = 'write'; BLE_ADDRESS = argv[1].toUpperCase(); JSON_FILE = argv[2];
} else {
  usage();
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

function hkdf(ikm, salt, info, len) {
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, len));
}

function aesCmac(key, data) {
  const ecb = createCipheriv('aes-128-ecb', key, null);
  ecb.setAutoPadding(false);
  const L = Buffer.concat([ecb.update(Buffer.alloc(16)), ecb.final()]);
  function leftShift(b) {
    const r = Buffer.alloc(16); let carry = 0;
    for (let i = 15; i >= 0; i--) { r[i] = ((b[i] << 1) | carry) & 0xff; carry = (b[i] & 0x80) ? 1 : 0; }
    return r;
  }
  const K1 = leftShift(L); if (L[0] & 0x80) K1[15] ^= 0x87;
  const K2 = leftShift(K1); if (K1[0] & 0x80) K2[15] ^= 0x87;
  let M = Buffer.from(data);
  if (M.length > 0 && M.length % 16 === 0) {
    const xored = Buffer.from(M);
    for (let i = 0; i < 16; i++) xored[xored.length - 16 + i] ^= K1[i];
    M = xored;
  } else {
    const pad = 16 - (M.length % 16 || 16);
    const padded = Buffer.alloc(M.length + pad); M.copy(padded); padded[M.length] = 0x80;
    for (let i = 0; i < 16; i++) padded[padded.length - 16 + i] ^= K2[i];
    M = padded;
  }
  const cbc = createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
  cbc.setAutoPadding(false);
  return Buffer.concat([cbc.update(M), cbc.final()]).slice(-16);
}

const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420'.replace(/\s/g, ''), 'hex');
const SPKI_PREFIX  = Buffer.from('302a300506032b656e032100', 'hex');

function x25519Generate() {
  const privRaw = randomBytes(32);
  privRaw[0] &= 0xf8; privRaw[31] &= 0x7f; privRaw[31] |= 0x40;
  const privKey = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, privRaw]), format: 'der', type: 'pkcs8' });
  const pubRaw  = createPublicKey(privKey).export({ type: 'spki', format: 'der' }).slice(-32);
  return { privKey, pubRaw };
}

function x25519DH(privKey, peerPubRaw) {
  const peerPubKey = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, peerPubRaw]), format: 'der', type: 'spki' });
  return diffieHellman({ privateKey: privKey, publicKey: peerPubKey });
}

// Stateful AES-CTR stream cipher matching aj.cs:
//   counter block = IV (mutable), last 4 bytes big-endian, incremented per 16-byte block
function makeAesCtrStream(key, iv) {
  const counter = Buffer.from(iv);
  let ks = Buffer.alloc(16);
  let pos = 16;

  function nextBlock() {
    const cipher = createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    ks = Buffer.concat([cipher.update(counter), cipher.final()]);
    pos = 0;
    counter.writeUInt32BE((counter.readUInt32BE(12) + 1) >>> 0, 12);
  }

  return function process(data) {
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      if (pos >= 16) nextBlock();
      out[i] = data[i] ^ ks[pos++];
    }
    return out;
  };
}

// ── COBS + CRC-16/Kermit ──────────────────────────────────────────────────────

function crc16kermit(data) {
  let crc = 0;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    for (let j = 0; j < 8; j++) {
      const bit = (b ^ crc) & 1; crc >>>= 1; b >>>= 1;
      if (bit) crc ^= 0x8408;
    }
  }
  return Buffer.from([crc & 0xFF, (crc >> 8) & 0xFF]);
}

function cobsEncode(data) {
  const out = []; let codePos = 0; out.push(0x01); let code = 1;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === 0x00) { out[codePos] = code; codePos = out.length; out.push(0x01); code = 1; }
    else { out.push(data[i]); code++; if (code === 0xFF) { out[codePos] = 0xFF; codePos = out.length; out.push(0x01); code = 1; } }
  }
  out[codePos] = code;
  return Buffer.from(out);
}

function cobsDecode(encoded) {
  const out = []; let i = 0;
  while (i < encoded.length) {
    const code = encoded[i++];
    for (let j = 0; j < code - 1; j++) out.push(encoded[i++]);
    if (i < encoded.length) out.push(0x00);
  }
  return Buffer.from(out);
}

// Wrap payload in inner COBS frame: [0x00, COBS(hdlcCtrl + payload + CRC16K), 0x00]
function buildFrame(hdlcCtrl, payload) {
  const data = Buffer.concat([Buffer.from([hdlcCtrl]), payload]);
  const crc  = crc16kermit(data);
  const enc  = cobsEncode(Buffer.concat([data, crc]));
  return Buffer.concat([Buffer.from([0x00]), enc, Buffer.from([0x00])]);
}

// ── HDLC session tracking ─────────────────────────────────────────────────────
// After handshake: client sent NS=0,1,2; device sent NS=1,2 → ourNR=3, ourNS=3
function makeSession() { return { ourNS: 3, ourNR: 3 }; }
function getCtrl(s)    { return (s.ourNR << 5) | (s.ourNS << 1); }
function advanceNS(s)  { s.ourNS = (s.ourNS + 1) & 7; }
function recvDeviceNS(s, deviceNS) { s.ourNR = (deviceNS + 1) & 7; }

// ── BLE helpers ────────────────────────────────────────────────────────────────

function dvToBuffer(dv) { return Buffer.from(dv.buffer, dv.byteOffset, dv.byteLength); }

// Guard: only echo raw sensor packets (buf[0] !== 0x00) so COBS frames are not echoed
function startKeepAlive(nch, wch) {
  nch.on('valuechanged', (dv) => {
    const buf = dvToBuffer(dv);
    if (buf.length >= 2 && buf[0] !== 0x00 && buf[1] === 0x04)
      wch.writeValue(buf, { type: 'command' }).catch(() => {});
  });
}

// Collect one inner COBS frame matching a Security type code; returns payload after type byte
function collectSecurityResponse(nch, typeCode, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { nch.removeListener('valuechanged', h); reject(new Error(`Timeout 0x${typeCode.toString(16)}`)); }, timeoutMs);
    let cobsBuf = [], inFrame = false;

    function tryFrame() {
      if (!cobsBuf.length) return false;
      const ts = new Date().toISOString().slice(11, 23);
      const raw = Buffer.from(cobsBuf);
      console.log(`  [frame ${ts}] cobs(${raw.length}): ${raw.toString('hex')}`);
      try {
        const decoded = cobsDecode(raw);
        if (decoded.length < 3) return false;
        const data = decoded.slice(0, decoded.length - 2);
        if (!decoded.slice(-2).equals(crc16kermit(data))) { console.log('  [frame] CRC fail'); return false; }
        const payload = data.slice(1);
        if (!payload.length) { console.log('  [frame] S/U-frame'); return false; }
        const type = payload[0];
        console.log(`  [frame] type=0x${type.toString(16)} routing=0x${data[0].toString(16)}`);
        if (type === typeCode) { clearTimeout(timer); nch.removeListener('valuechanged', h); resolve(payload.slice(1)); return true; }
      } catch {}
      return false;
    }

    function h(dv) {
      const buf = dvToBuffer(dv);
      const ts  = new Date().toISOString().slice(11, 23);
      console.log(`  [rx ${ts}] ${buf.toString('hex')}  len=${buf.length}`);
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (b === 0x00) { if (!inFrame) { inFrame = true; cobsBuf = []; } else { if (tryFrame()) return; cobsBuf = []; } }
        else if (inFrame) cobsBuf.push(b);
      }
    }
    nch.on('valuechanged', h);
  });
}

// ── Security handshake ─────────────────────────────────────────────────────────

async function runSecurityHandshake(wch, nch) {
  console.log('\n[Security] Starting handshake...');

  // Phase 0: Version
  const versionFrame = buildFrame(0x20, Buffer.from([0x00]));
  console.log(`[Security] → VersionRequest: ${versionFrame.toString('hex')}`);
  const verProm = collectSecurityResponse(nch, 0x01, 1500).catch(() => null);
  await wch.writeValue(versionFrame, { type: 'command' });
  const verData = await verProm;
  if (verData) {
    const proto = verData[5] + 1;
    console.log(`[Security] ← VersionResponse: fw=${verData[0]}.${verData[1]} proto=${proto}`);
    if (proto < 2) throw new Error(`Device protocol v${proto} — encryption disabled`);
  } else {
    console.log('[Security]   (no version response — assuming proto v2)');
  }

  // Phase 1: EncryptParam
  const epFrame = buildFrame(0x22, Buffer.from([0x10]));
  console.log(`[Security] → EncryptParamRequest: ${epFrame.toString('hex')}`);
  const epProm = collectSecurityResponse(nch, 0x11, 4000);
  await wch.writeValue(epFrame, { type: 'command' });
  const stData = await epProm;
  const S = stData.slice(0, 16);
  const T = stData.slice(16, 32);
  console.log(`[Security] ← EncryptParamResponse  S=${S.toString('hex')}  T=${T.toString('hex')}`);

  // Phase 2: KeyExchange
  const r = hkdf(BRIDGE_KEY, S, Buffer.alloc(0), 16);
  const { privKey, pubRaw: P_pub } = x25519Generate();
  const cmac = aesCmac(r, P_pub);
  const keSecurity = Buffer.concat([Buffer.from([0x12]), P_pub, cmac, Buffer.from([0x00])]);
  const keFrame    = buildFrame(0x24, keSecurity);
  console.log(`[Security] → KeyExchangeRequest (${keFrame.length} bytes)`);
  const keProm = collectSecurityResponse(nch, 0x13, 4000);
  for (let off = 0; off < keFrame.length; off += 20) {
    await wch.writeValue(keFrame.slice(off, off + 20), { type: 'command' });
    if (off + 20 < keFrame.length) await new Promise(r2 => setTimeout(r2, 10));
  }
  const keData = await keProm;
  const D_pub = keData.slice(0, 32);
  const D_mac = keData.slice(32, 48);
  const expectedMac = aesCmac(r, D_pub);
  if (!expectedMac.equals(D_mac)) throw new Error('Key exchange MAC mismatch');
  console.log('[Security]   Device MAC verified ✓');

  const sharedSecret = x25519DH(privKey, D_pub);
  const keys = hkdf(sharedSecret, S, Buffer.alloc(0), 32);
  const recvKey = keys.slice(0, 16);
  const sendKey = keys.slice(16, 32);
  console.log(`[Security]   sendKey = ${sendKey.toString('hex')}`);
  console.log(`[Security]   IV(T)   = ${T.toString('hex')}`);

  return { sendStream: makeAesCtrStream(sendKey, T), recvStream: makeAesCtrStream(recvKey, T) };
}

// ── DataPoint frame builders ───────────────────────────────────────────────────

// Outer COBS frame containing a ReadCmd AddressFrame
function buildDataPointRead(dpId, instance) {
  const hasInst = instance != null;
  const dpIdHi  = hasInst ? ((dpId >> 8) & 0x7F) | 0x80 : (dpId >> 8) & 0x7F;
  const parts   = [0x10, dpId & 0xFF, dpIdHi];
  if (hasInst) parts.push(instance & 0xFF);
  const data = Buffer.from(parts);
  const crc  = crc16kermit(data);
  const enc  = cobsEncode(Buffer.concat([data, crc]));
  return Buffer.concat([Buffer.from([0x00]), enc, Buffer.from([0x00])]);
}

// Outer COBS frame containing a WriteCmd AddressFrame
// value: 1-byte number (Enum/OffOn) or Buffer (e.g. 4-byte uint32 LE for Counter DPs)
function buildDataPointWrite(dpId, value, instance) {
  const hasInst = instance != null;
  const dpIdHi  = hasInst ? ((dpId >> 8) & 0x7F) | 0x80 : (dpId >> 8) & 0x7F;
  const header  = [0x20, dpId & 0xFF, dpIdHi];
  if (hasInst) header.push(instance & 0xFF);
  const valBuf  = Buffer.isBuffer(value) ? value : Buffer.from([value & 0xFF]);
  const data    = Buffer.concat([Buffer.from(header), valBuf]);
  const crc     = crc16kermit(data);
  const enc     = cobsEncode(Buffer.concat([data, crc]));
  return Buffer.concat([Buffer.from([0x00]), enc, Buffer.from([0x00])]);
}

// ── Encrypted frame send ───────────────────────────────────────────────────────

async function sendEncryptedFrame(wch, sendStream, session, outerCobsFrame) {
  const encrypted  = sendStream(outerCobsFrame);
  const secPayload = Buffer.concat([Buffer.from([0x20]), encrypted]);
  const ctrl       = getCtrl(session);
  const frame      = buildFrame(ctrl, secPayload);
  advanceNS(session);
  for (let off = 0; off < frame.length; off += 20)
    await wch.writeValue(frame.slice(off, off + 20), { type: 'command' });
}

// ── Encrypted response collector ──────────────────────────────────────────────

function collectEncryptedResponse(nch, recvStream, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      nch.removeListener('valuechanged', h);
      reject(new Error('Timeout waiting for encrypted DataPoint response'));
    }, timeoutMs);

    let cobsBuf = [], inFrame = false;

    function tryFrame() {
      if (!cobsBuf.length) return false;
      try {
        const raw = Buffer.from(cobsBuf);
        const decoded = cobsDecode(raw);
        if (decoded.length < 3) return false;
        const data = decoded.slice(0, decoded.length - 2);
        if (!decoded.slice(-2).equals(crc16kermit(data))) return false;
        const routing = data[0];
        if (routing & 1) return false;        // S-frame, skip
        const payload = data.slice(1);
        if (payload.length < 2) return false;
        if (payload[0] !== 0x20) return false; // not encrypted
        const encrypted = payload.slice(1);
        const decrypted = recvStream(encrypted);
        if (decrypted.length < 3 || decrypted[0] !== 0x00) return false;
        const cobsInner = decrypted.slice(1, decrypted.length - 1);
        const outerDec  = cobsDecode(cobsInner);
        if (outerDec.length < 3) return false;
        const outerData = outerDec.slice(0, outerDec.length - 2);
        const outerCrc  = outerDec.slice(-2);
        if (!outerCrc.equals(crc16kermit(outerData))) {
          console.log('  [recv] outer CRC mismatch (counter out of sync?)');
          return false;
        }
        const deviceNS = (routing >> 1) & 7;
        clearTimeout(timer);
        nch.removeListener('valuechanged', h);
        resolve({ data: outerData, deviceNS });
        return true;
      } catch { return false; }
    }

    function h(dv) {
      const buf = dvToBuffer(dv);
      for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (b === 0x00) {
          if (!inFrame) { inFrame = true; cobsBuf = []; }
          else          { if (tryFrame()) return; cobsBuf = []; }
        } else if (inFrame) cobsBuf.push(b);
      }
    }
    nch.on('valuechanged', h);
  });
}

// ── High-level DataPoint read ─────────────────────────────────────────────────
// Returns raw value bytes. Counter DPs → 4 bytes uint32 LE; Enum/OffOn → 1 byte.

async function readDataPoint(wch, nch, sendStream, recvStream, session, dpId, instance) {
  const frame = buildDataPointRead(dpId, instance);
  await sendEncryptedFrame(wch, sendStream, session, frame);
  const resp = await collectEncryptedResponse(nch, recvStream, 3000);
  recvDeviceNS(session, resp.deviceNS);
  const d = resp.data;
  if (d[0] === 0x12) throw new Error(`ReadError DpId=${dpId}${instance != null ? ` inst=${instance}` : ''}`);
  if (d[0] !== 0x11) throw new Error(`Unexpected cmd=0x${d[0].toString(16)} DpId=${dpId}`);
  const hasInst  = (d[2] & 0x80) !== 0;
  const valStart = hasInst ? 4 : 3;
  return d.slice(valStart);
}

// ── High-level DataPoint write ────────────────────────────────────────────────

async function writeDataPoint(wch, nch, sendStream, recvStream, session, dpId, value, instance) {
  const frame = buildDataPointWrite(dpId, value, instance);
  await sendEncryptedFrame(wch, sendStream, session, frame);
  const resp = await collectEncryptedResponse(nch, recvStream, 3000);
  recvDeviceNS(session, resp.deviceNS);
  const d = resp.data;
  if (d[0] === 0x22) throw new Error(`WriteError DpId=${dpId}${instance != null ? ` inst=${instance}` : ''}`);
  if (d[0] !== 0x21) throw new Error(`Unexpected write response 0x${d[0].toString(16)} DpId=${dpId}`);
}

// ── Display helpers ────────────────────────────────────────────────────────────

const OOA          = ['Off', 'On', 'Auto'];
const FILTER_STATUS = ['OK', 'Good', 'Fair', 'Replace soon', 'Replace now'];

function fmtSecs(s) {
  return `${String(Math.floor(s / 3600)).padStart(2, '0')}:${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}`;
}

// ── Read all settings → structured object ─────────────────────────────────────

async function readSettings(wch, nch, sendStream, recvStream, session) {
  const ctx = [wch, nch, sendStream, recvStream, session];
  const rd1 = (dpId, inst) => readDataPoint(...ctx, dpId, inst).then(b => b[0]);
  const rd4 = (dpId, inst) => readDataPoint(...ctx, dpId, inst).then(b => b.readUInt32LE(0));
  const rdStr = (dpId)     => readDataPoint(...ctx, dpId, 0)
    .then(b => { const e = b.indexOf(0); return (e === -1 ? b : b.slice(0, e)).toString('utf8'); });

  const oPower    = await rd1(DP.ODOUR_POWER);
  const oMode     = await rd1(DP.ODOUR_MODE);
  const oFollowUp = await rd1(DP.ODOUR_FOLLOW_UP);
  const oSens     = await rd1(DP.ODOUR_SENS);

  const lMode     = await rd1(DP.LIGHT_MODE);
  const lInt      = await rd1(DP.LIGHT_INTENSITY);
  const lFollowUp = await rd1(DP.LIGHT_FOLLOW_UP);
  const lSens     = await rd1(DP.LIGHT_SENS);

  const fUsage = await rd1(DP.FILTER_USAGE, 0).catch(() => null);

  const slots = [];
  for (let i = 0; i < 10; i++) {
    const enable = await rd1(DP.SLOT_ENABLE, i);
    if (!enable) { slots.push({ index: i, enable: false }); continue; }
    const name    = await rdStr(DP.SLOT_NAME[i]).catch(() => null);
    const start   = await rd4(DP.SLOT_START, i);
    const end     = await rd4(DP.SLOT_END, i);
    const lMode2  = await rd1(DP.SLOT_LIGHT_MODE, i);
    const lInt2   = await rd1(DP.SLOT_LIGHT_INT, i);
    const fMode   = await rd1(DP.SLOT_FAN_MODE, i);
    const fInt    = await rd1(DP.SLOT_FAN_INT, i);
    slots.push({ index: i, enable: true, name, start, end,
                 lightMode: lMode2, lightInt: lInt2, fanMode: fMode, fanInt: fInt });
  }

  return {
    odour:  { power: oPower, mode: oMode, followUp: oFollowUp, sensitivity: oSens },
    light:  { mode: lMode, intensity: lInt, followUp: lFollowUp, sensitivity: lSens },
    filter: { usage: fUsage },
    slots,
  };
}

// ── Print settings to stdout ───────────────────────────────────────────────────

function printSettings(s) {
  if (s.filter.usage != null)
    console.log(`\n═══ Filter Maintenance ═══\n  Status : ${FILTER_STATUS[s.filter.usage] ?? s.filter.usage} (${s.filter.usage}/4)`);

  console.log('\n═══ Odour Extraction ═══');
  console.log(`  Power      : ${s.odour.power}/4`);
  console.log(`  Mode       : ${OOA[s.odour.mode] ?? s.odour.mode}`);
  console.log(`  Follow-up  : ${s.odour.followUp}/4`);
  console.log(`  Sensitivity: ${s.odour.sensitivity}/4`);

  console.log('\n═══ Orientation Light ═══');
  console.log(`  Mode       : ${OOA[s.light.mode] ?? s.light.mode}`);
  console.log(`  Intensity  : ${s.light.intensity}/4`);
  console.log(`  Follow-up  : ${s.light.followUp}/4`);
  console.log(`  Sensitivity: ${s.light.sensitivity}/4`);

  console.log('\n═══ Time Slots ═══');
  for (const slot of s.slots) {
    if (!slot.enable) { console.log(`  Slot ${slot.index}: disabled`); continue; }
    console.log(`  Slot ${slot.index}: ${slot.name ? `"${slot.name}"  ` : ''}${fmtSecs(slot.start)}–${fmtSecs(slot.end)}`);
    console.log(`    Light: ${OOA[slot.lightMode] ?? slot.lightMode}, brightness ${slot.lightInt}/4`);
    console.log(`    Fan:   ${slot.fanMode ? 'Auto' : 'Off'}, intensity ${slot.fanInt}/4`);
  }
}

// ── Validate settings for --write ─────────────────────────────────────────────

function validateSettings(s) {
  const errs = [];
  const int = (v, min, max, name) => {
    if (typeof v !== 'number' || !Number.isInteger(v) || v < min || v > max)
      errs.push(`${name}: must be integer ${min}–${max}, got ${JSON.stringify(v)}`);
  };

  int(s.odour?.power,       0, 4, 'odour.power');
  int(s.odour?.mode,        0, 2, 'odour.mode');
  int(s.odour?.followUp,    0, 4, 'odour.followUp');
  int(s.odour?.sensitivity, 0, 4, 'odour.sensitivity');
  int(s.light?.mode,        0, 2, 'light.mode');
  int(s.light?.intensity,   0, 4, 'light.intensity');
  int(s.light?.followUp,    0, 4, 'light.followUp');
  int(s.light?.sensitivity, 0, 4, 'light.sensitivity');

  if (!Array.isArray(s.slots) || s.slots.length !== 10) {
    errs.push('slots: must be array of exactly 10 entries');
  } else {
    for (const sl of s.slots) {
      if (!sl.enable) continue;
      const p = `slots[${sl.index}]`;
      int(sl.start,     0, 86399, `${p}.start`);
      int(sl.end,       0, 86399, `${p}.end`);
      int(sl.lightMode, 0, 2,     `${p}.lightMode`);
      int(sl.lightInt,  0, 4,     `${p}.lightInt`);
      int(sl.fanMode,   0, 1,     `${p}.fanMode`);
      int(sl.fanInt,    0, 4,     `${p}.fanInt`);
    }
  }
  return errs;
}

// ── Write settings from object ─────────────────────────────────────────────────

async function writeSettings(wch, nch, sendStream, recvStream, session, s) {
  const ctx = [wch, nch, sendStream, recvStream, session];
  const wr1 = (dpId, v, inst) => writeDataPoint(...ctx, dpId, v, inst);
  const wr4 = (dpId, v, inst) => {
    const buf = Buffer.alloc(4); buf.writeUInt32LE(v, 0);
    return writeDataPoint(...ctx, dpId, buf, inst);
  };

  console.log('\n═══ Writing Odour Extraction ═══');
  await wr1(DP.ODOUR_POWER,     s.odour.power);       console.log(`  Power      : ${s.odour.power}/4`);
  await wr1(DP.ODOUR_MODE,      s.odour.mode);         console.log(`  Mode       : ${OOA[s.odour.mode]}`);
  await wr1(DP.ODOUR_FOLLOW_UP, s.odour.followUp);     console.log(`  Follow-up  : ${s.odour.followUp}/4`);
  await wr1(DP.ODOUR_SENS,      s.odour.sensitivity);  console.log(`  Sensitivity: ${s.odour.sensitivity}/4`);

  console.log('\n═══ Writing Orientation Light ═══');
  await wr1(DP.LIGHT_MODE,      s.light.mode);         console.log(`  Mode       : ${OOA[s.light.mode]}`);
  await wr1(DP.LIGHT_INTENSITY, s.light.intensity);    console.log(`  Intensity  : ${s.light.intensity}/4`);
  await wr1(DP.LIGHT_FOLLOW_UP, s.light.followUp);     console.log(`  Follow-up  : ${s.light.followUp}/4`);
  await wr1(DP.LIGHT_SENS,      s.light.sensitivity);  console.log(`  Sensitivity: ${s.light.sensitivity}/4`);

  console.log('\n═══ Writing Time Slots ═══');
  for (const slot of s.slots) {
    await wr1(DP.SLOT_ENABLE, slot.enable ? 1 : 0, slot.index);
    if (!slot.enable) { console.log(`  Slot ${slot.index}: disabled`); continue; }
    await wr4(DP.SLOT_START,      slot.start,     slot.index);
    await wr4(DP.SLOT_END,        slot.end,       slot.index);
    await wr1(DP.SLOT_LIGHT_MODE, slot.lightMode, slot.index);
    await wr1(DP.SLOT_LIGHT_INT,  slot.lightInt,  slot.index);
    await wr1(DP.SLOT_FAN_MODE,   slot.fanMode,   slot.index);
    await wr1(DP.SLOT_FAN_INT,    slot.fanInt,    slot.index);
    console.log(`  Slot ${slot.index}: ${fmtSecs(slot.start)}–${fmtSecs(slot.end)}  light=${OOA[slot.lightMode]}/${slot.lightInt}  fan=${slot.fanMode ? 'Auto' : 'Off'}/${slot.fanInt}`);
  }
}

// ── Read BLE Device Information Service (no encryption needed) ────────────────

async function readDIS(gatt) {
  const out = {};
  try {
    const svc = await gatt.getPrimaryService(DIS_SVC);
    const rd = async (uuid) => {
      try {
        const ch = await svc.getCharacteristic(uuid);
        const dv = await ch.readValue();
        return Buffer.from(dv.buffer, dv.byteOffset, dv.byteLength).toString('utf8').replace(/\0/g, '');
      } catch { return null; }
    };
    const fields = [
      ['00002a29-0000-1000-8000-00805f9b34fb', 'manufacturer'],
      ['00002a24-0000-1000-8000-00805f9b34fb', 'model'],
      ['00002a25-0000-1000-8000-00805f9b34fb', 'serial'],
      ['00002a26-0000-1000-8000-00805f9b34fb', 'fwRevision'],
      ['00002a27-0000-1000-8000-00805f9b34fb', 'hwRevision'],
      ['00002a28-0000-1000-8000-00805f9b34fb', 'swRevision'],
    ];
    for (const [uuid, key] of fields) {
      const v = await rd(uuid);
      if (v != null) out[key] = v;
    }
  } catch {}
  return out;
}

// ── Scan mode ─────────────────────────────────────────────────────────────────
// Uses BlueZ SetDiscoveryFilter to pre-filter by CMD_SVC UUID (0xFD48, Geberit-assigned).
// Only devices that advertise this UUID in their BLE advertisement are reported.

async function scanMode(timeoutMs) {
  const { bluetooth, destroy } = createBluetooth();
  try {
    const adapter = await bluetooth.defaultAdapter();

    // SetDiscoveryFilter as an optimization: BlueZ pre-filters advertising events.
    // Not relied on for correctness — we post-filter by UUIDs property instead.
    try {
      await adapter.helper.callMethod('SetDiscoveryFilter', {
        UUIDs:     new Variant('as', [CMD_SVC]),
        Transport: new Variant('s',  'le'),
      });
    } catch {
      // not critical; post-filter will still identify Geberit devices
    }

    if (!await adapter.isDiscovering()) await adapter.startDiscovery();
    console.log(`Scanning for ${timeoutMs / 1000}s...`);
    await new Promise(r => setTimeout(r, timeoutMs));
    await adapter.stopDiscovery().catch(() => {});

    await adapter.helper.callMethod('SetDiscoveryFilter', {}).catch(() => {});

    // Post-filter: read each device's UUIDs property from BlueZ via D-Bus.
    // BlueZ stores which service UUIDs a device advertised; RemoveDevice + filter
    // alone is unreliable because actively-advertising devices resist removal.
    const adapterPath = adapter.helper.objectPath ?? '/org/bluez/hci0';
    const addresses = await adapter.devices();
    const found = [];

    // Open a separate D-Bus connection to read each device's UUIDs property.
    // adapter.helper.bus is not exposed by node-ble, so we use dbus-next directly.
    const bus = dbus.systemBus();
    try {
      for (const addr of addresses) {
        const devPath = `${adapterPath}/dev_${addr.replace(/:/g, '_').toUpperCase()}`;
        try {
          const devObj = await bus.getProxyObject('org.bluez', devPath);
          const propsIface = devObj.getInterface('org.freedesktop.DBus.Properties');
          const uuidsVar = await propsIface.Get('org.bluez.Device1', 'UUIDs');
          const uuids = Array.isArray(uuidsVar.value) ? uuidsVar.value : [];
          if (uuids.some(u => u.toLowerCase() === CMD_SVC)) found.push(addr);
        } catch {
          // device removed from cache between devices() and Get, or no UUIDs — skip
        }
      }
    } finally {
      bus.disconnect();
    }

    if (!found.length) {
      console.log('No Geberit devices found.');
      return;
    }
    console.log('\nGeberit devices found:');
    for (const addr of found) console.log(`  ${addr}`);
  } finally {
    destroy();
  }
}

// ── Connect to device, run action, disconnect ──────────────────────────────────

async function withDevice(address, action) {
  const { bluetooth, destroy } = createBluetooth();
  try {
    const adapter = await bluetooth.defaultAdapter();
    let device;
    try {
      device = await adapter.getDevice(address);
    } catch {
      console.log('Device not in cache, scanning...');
      if (!await adapter.isDiscovering()) await adapter.startDiscovery().catch(() => {});
      device = await adapter.waitDevice(address);
      await adapter.stopDiscovery().catch(() => {});
    }

    console.log('Connecting...');
    await device.connect();
    console.log('Connected');

    try {
      await action(device);
    } finally {
      await device.disconnect();
      console.log('\nDisconnected.');
    }
  } finally {
    destroy();
  }
}

// ── CMAC self-test ─────────────────────────────────────────────────────────────
{
  const got = aesCmac(
    Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'),
    Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'),
  ).toString('hex');
  if (got !== '070a16b46b4d4144f79bdd9dd04a287c') { console.error('CMAC self-test FAILED'); process.exit(1); }
  console.log('[CMAC self-test] OK');
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  if (MODE === 'scan') {
    await scanMode(SCAN_TIMEOUT);
    return;
  }

  await withDevice(BLE_ADDRESS, async (device) => {
    const gatt = await device.gatt();

    // Device info from BLE DIS (no encryption)
    if (MODE === 'get') {
      const dis = await readDIS(gatt);
      if (Object.keys(dis).length) {
        console.log('\n═══ Device Info (BLE DIS) ═══');
        if (dis.manufacturer) console.log(`  Manufacturer: ${dis.manufacturer}`);
        if (dis.model)        console.log(`  Model       : ${dis.model}`);
        if (dis.serial)       console.log(`  Serial      : ${dis.serial}`);
        if (dis.fwRevision)   console.log(`  FW revision : ${dis.fwRevision}`);
        if (dis.hwRevision)   console.log(`  HW revision : ${dis.hwRevision}`);
        if (dis.swRevision)   console.log(`  SW revision : ${dis.swRevision}`);
      }
    }

    const cmdSvc = await gatt.getPrimaryService(CMD_SVC);
    const wch    = await cmdSvc.getCharacteristic(WRITE_CHAR);
    const nch    = await cmdSvc.getCharacteristic(NOTIFY_CHAR);
    await nch.startNotifications();
    startKeepAlive(nch, wch);

    let sendStream, recvStream;
    try {
      ({ sendStream, recvStream } = await runSecurityHandshake(wch, nch));
    } catch (e) {
      throw new Error(`Security handshake failed: ${e.message}`);
    }

    const session = makeSession();

    if (MODE === 'get') {
      const settings = await readSettings(wch, nch, sendStream, recvStream, session);
      printSettings(settings);

    } else if (MODE === 'dump') {
      const settings = await readSettings(wch, nch, sendStream, recvStream, session);
      const dump = { odour: settings.odour, light: settings.light, slots: settings.slots };
      writeFileSync(JSON_FILE, JSON.stringify(dump, null, 2));
      console.log(`\nSaved to ${JSON_FILE}`);

    } else if (MODE === 'write') {
      let raw;
      try { raw = JSON.parse(readFileSync(JSON_FILE, 'utf8')); }
      catch (e) { throw new Error(`Cannot read ${JSON_FILE}: ${e.message}`); }
      const errs = validateSettings(raw);
      if (errs.length) {
        console.error('Validation errors:\n' + errs.map(e => `  - ${e}`).join('\n'));
        process.exit(1);
      }
      await writeSettings(wch, nch, sendStream, recvStream, session, raw);
      console.log('\nAll settings written successfully.');
    }
  });
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
