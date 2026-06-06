# Geberit DuoFresh BLE Protocol — Reverse Engineering Notes

Fully working as of 2026-06-06. Able to read config and write any DataPoint (fan power, sensitivity, mode, light) via BLE from a Linux host using Node.js.

---

## Device

- **Model**: Geberit DuoFresh (bathroom ventilation and air-purifying system)
- **BLE address**: `XX:XX:XX:XX:XX:XX` (replace with your device's address)
- **Services / characteristics**:

| Name | UUID |
|------|------|
| Command service | `0000fd48-0000-1000-8000-00805f9b34fb` |
| Write characteristic | `559eb001-2390-11e8-b467-0ed5f89f718b` |
| Notify characteristic | `559eb002-2390-11e8-b467-0ed5f89f718b` |
| Status service | `559eb100-2390-11e8-b467-0ed5f89f718b` |
| Status characteristic | `559eb110-2390-11e8-b467-0ed5f89f718b` |

- ATT MTU = 20 bytes — all writes are fragmented into 20-byte chunks
- Write type: Write Without Response (`type: 'command'` in node-ble)

---

## Protocol Stack (device side)

```
BLE ATT writes / notifications
        │
        ▼
  by = inner CobsFraming      ← COBS + CRC16/Kermit, 0x00 as frame delimiter
        │
        ▼
  bw = HdlcFlowControl        ← HDLC I-frames (data) and S-frames (ACK)
        │
        ▼
  bx = SecurityServer         ← X25519 + HKDF-SHA256 + AES-CTR + AES-CMAC
        │
        ▼
  bz = outer CobsFraming      ← COBS + CRC16/Kermit again, 0x00 delimiter
        │
        ▼
  bv = ConfigurationManager   ← delegates to FrameHandler
        │
        ▼
       FrameHandler            ← DataPoint protocol (WriteCmd/ReadCmd/NotifyData)
```

Source: decompiled `Geberit.ComLib.Bluetooth.Ble20Product.cs` (`geberit-gidx-53.dll`)

---

## Wire Format

### BLE stream (ATT level)

Writes are a raw byte stream, fragmented at 20 bytes. All frames use the same COBS convention: `0x00` is the delimiter, used at both start and end. The same applies to incoming notifications.

### Inner COBS frame (BLE → HDLC layer)

```
[0x00]  [COBS-encoded payload]  [0x00]
```

The COBS-encoded payload, after decoding, is:
```
[HDLC_ctrl]  [Security_type]  [Security_payload...]  [CRC16K_lo]  [CRC16K_hi]
```

CRC16/Kermit covers `[HDLC_ctrl, Security_type, Security_payload...]`.

### HDLC control byte

**I-frame** (carries data, bit0 = 0):
```
ctrl = (N(R) << 5) | (N(S) << 1)
```

**S-frame** (ACK/NAK, bits 1:0 = 01):
```
ctrl = (N(R) << 5) | (type << 2) | 1
```

Sequence numbers across a typical session:

| Step | Our N(S) | Our N(R) | ctrl | Description |
|------|----------|----------|------|-------------|
| VersionRequest | 0 | 0 | 0x20 | |
| EncryptParamRequest | 1 | 0 | 0x22 | N(S)=1 |
| KeyExchangeRequest | 2 | 0 | 0x24 | N(S)=2 |
| DataPoint Write | 3 | 3 | 0x66 | N(S)=3, N(R)=3 ACKs device N(S)=0,1,2 |

### Outer COBS frame (Security plaintext)

The Security layer (`bx`) encrypts/decrypts the outer COBS frame. The outer CobsFraming (`bz`) sees the decrypted bytes, waits for `0x00` delimiters, and COBS-decodes to extract the DataPoint payload passed to FrameHandler.

```
[0x00]  [COBS-encoded DataPoint_payload + CRC16K]  [0x00]
```

After COBS decode:
```
[DataPoint_payload...]  [CRC16K_lo]  [CRC16K_hi]
```

**Critical**: The AES-CTR plaintext must be this complete outer COBS frame including the `0x00` delimiters. If raw bytes without COBS framing are passed, the outer CobsFraming on the device fails the COBS decode silently (exception caught, discarded) and ConfigurationManager never receives anything. This was the root cause of all early failures.

---

## CRC-16/Kermit

Used at both inner and outer COBS levels.

- Poly: `0x1021` (reflected = `0x8408`)
- Init: `0`
- Input reflected: yes
- Output reflected: yes
- Final XOR: `0`
- Byte order: little-endian (lo byte first)

```javascript
function crc16kermit(data) {
  let crc = 0;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    for (let j = 0; j < 8; j++) {
      const bit = (b ^ crc) & 1;
      crc >>>= 1;
      b >>>= 1;
      if (bit) crc ^= 0x8408;
    }
  }
  return Buffer.from([crc & 0xFF, (crc >> 8) & 0xFF]);
}
```

---

## Security Protocol

Source: decompiled `Geberit.ComLib.Bluetooth.Crypto.SecurityServer.cs`

### Security type bytes

| Type | Direction | Meaning |
|------|-----------|---------|
| `0x00` | client → device | VersionRequest |
| `0x01` | device → client | VersionResponse |
| `0x10` | client → device | EncryptParamRequest |
| `0x11` | device → client | EncryptParamResponse |
| `0x12` | client → device | KeyExchangeRequest |
| `0x13` | device → client | KeyExchangeResponse |
| `0x20` | both | Encrypted application data |

### Bridge key (keyset 0, hardcoded in SecurityServer.cs)

```javascript
const BRIDGE_KEY = Buffer.from([
  0xD1, 0x21, 0x8A, 0x89, 0xF6, 0x0A, 0xC2, 0x94,
  0x2D, 0x44, 0x20, 0x79, 0x74, 0x50, 0x97, 0xBE
]);
```

### Handshake sequence

**Phase 0 — VersionRequest** (optional, device may not respond):
```
client → [HDLC ctrl=0x20, SecurityType=0x00]         empty payload
device → [HDLC S-frame, SecurityType=0x01, fw_major, fw_minor, build_hi, build_lo, hw, proto-1]
```
- `proto = verData[5] + 1`. Only proto >= 2 supports encryption.
- If device does not respond within ~1.5s, assume proto v2 (encryption enabled).

**Phase 1 — EncryptParamRequest**:
```
client → [HDLC ctrl=0x22, SecurityType=0x10]          empty payload
device → [HDLC ctrl, SecurityType=0x11, S(16 bytes), T(16 bytes)]
```
- `S` = 16-byte random salt
- `T` = 16-byte value, used directly as AES-CTR IV

**Phase 2 — KeyExchangeRequest**:
```
client → [HDLC ctrl=0x24, SecurityType=0x12, P_pub(32), CMAC(16), keyset=0x00]
device → [HDLC ctrl, SecurityType=0x13, D_pub(32), D_mac(16)]
```

KeyExchangeRequest is 56 bytes — must be fragmented into 20-byte ATT writes.

### Key derivation

```
r             = HKDF-SHA256(ikm=BRIDGE_KEY, salt=S, info=empty, len=16)
{P_pub, P_priv} = X25519 keypair (random, client-generated each session)
CMAC          = AES-CMAC(key=r, data=P_pub)       ← authenticates client to device

sharedSecret  = X25519(P_priv, D_pub)
keys          = HKDF-SHA256(ikm=sharedSecret, salt=S, info=empty, len=32)
recvKey       = keys[0..15]     ← decrypt device→client encrypted frames
sendKey       = keys[16..31]    ← encrypt client→device frames
IV            = T                ← from EncryptParamResponse, used for AES-CTR
```

### Encryption

```
encrypted_outer_cobs = AES-128-CTR(key=sendKey, iv=IV, plaintext=outer_cobs_frame)
```

Node.js `aes-128-ctr` works directly (full 128-bit counter, big-endian, IV used as-is).

### Sending encrypted application data

```
security_payload  = [0x20, AES-CTR(sendKey, IV, outer_cobs_frame)]
inner_cobs_frame  = [0x00, COBS(HDLC_ctrl=0x66 + security_payload + CRC16K), 0x00]
```

Fragment `inner_cobs_frame` into 20-byte ATT writes.

---

## DataPoint Protocol

Source: decompiled `geberit-gidx-54.dll`, namespace `Geberit.ComLib.Core`

### CommandId enum (byte)

| Value | Name |
|-------|------|
| 0x00 | Inventory |
| 0x10 | ReadCmd |
| 0x11 | ReadAns |
| 0x12 | ReadError |
| 0x20 | WriteCmd |
| 0x21 | WriteAck |
| 0x22 | WriteError |
| 0x34 | NotifyData |
| 0x70 | ListInventoryCmd |
| 0x78 | ListNotifyData |
| 0xE0 | DeviceStatusData |
| 0xF1 | LinkTestNotify |
| 0xF2 | LoopbackRequest |

### AddressFrame wire format

```
[CommandId, DpId_lo, DpId_hi, (Instance?), value_bytes...]
```

- `DpId_hi` bit7 = 0 → no instance byte (all DuoFresh DataPoints have 1 instance)
- `DpId_hi` bit7 = 1 → instance byte present between DpId_hi and value
- `DataPointEnum`: `value_bytes` = 1 byte

### WriteCmd helper

```javascript
function buildDataPointWrite(dpId, value, instance) {
  // value: 1-byte number for Enum/OffOn/OffOnAuto DPs,
  //        or Buffer for Counter DPs (e.g. SLOT_START/SLOT_END — uint32 LE, 4 bytes)
  // instance: omit for global DPs; pass slot index 0–9 for instanced DPs
  const hasInst = instance != null;
  const dpIdHi  = hasInst ? ((dpId >> 8) & 0x7F) | 0x80 : (dpId >> 8) & 0x7F;
  const header  = [0x20, dpId & 0xFF, dpIdHi];
  if (hasInst) header.push(instance & 0xFF);
  const valBuf  = Buffer.isBuffer(value) ? value : Buffer.from([value & 0xFF]);
  const data    = Buffer.concat([Buffer.from(header), valBuf]);
  const crc     = crc16kermit(data);
  const enc     = cobsEncode(Buffer.concat([data, crc]));
  // returns a complete outer COBS frame: [0x00, COBS(data+crc), 0x00]
  return Buffer.concat([Buffer.from([0x00]), enc, Buffer.from([0x00])]);
}
```

Pass the returned buffer as `plaintext` to AES-CTR encryption.

---

## Device Information Service (BLE DIS, UUID 0x180A)

Read via standard GATT — no encryption, no DataPoint protocol. Available immediately after connecting.

| GATT characteristic | UUID | Value (tested device) | App label |
|---------------------|------|---------------------|-----------|
| Manufacturer Name | `0x2A29` | `Geberit` | — |
| Model Number | `0x2A24` | `831.497.00.0` | "Article number" |
| Serial Number | `0x2A25` | `111111` | "Serial number" (app prepends product-line prefix `FC010`) |
| Firmware Revision | `0x2A26` | `10.7 OTA4.3 20240202` | "Firmware" (app shows as `RS8.0 TS107`) |
| Hardware Revision | `0x2A27` | `08` | (part of `RS8.0` in app) |
| Software Revision | `0x2A28` | `1.10.0 1.2.0` | — |

**DIS ↔ App label mapping:**
- "Model" in app ("GamAutomatic") = app-local name looked up from the article number `831.497.00.0`
- "Article number" in app = DIS Model Number string
- "Serial number" in app = `FC010` + DIS Serial Number (prefix is product-line code, hard-coded in app)
- "Firmware" in app = `RS` + HW revision (`08` → `8.0`) + ` TS` + FW major.minor (`10.7` → `107`)

**DataPoint-based device info (DpIds 304, 351, 369, 371) all return ReadError on RS8.0 TS107.** Use DIS instead.

---

## App Menu Structure (GamAutomatic — observed 2026-06-06)

```
Device info:
  Model:          GamAutomatic
  Article:        831.497.00.0
  Serial:         FC010111111
  Firmware:       RS8.0 TS107

Maintenance:
  Firmware update
  Filter replacement — filter status: "replace soon"

Device settings:
  Odour extraction unit
    Activation: Off / On / Automatic
      (when Automatic) Sensor sensitivity: 5 steps
      (when Automatic) Run-on time: 30s / 1m / 2m / 5m / 10m
    Intensity: 5 steps

  Orientation light
    Activation: Off / On / Automatic
      (when Automatic) Distance activation: 5 steps
      (when Automatic) Illumination time: 30s / 1m / 2m / 5m / 10m
    Brightness: 5 steps

  Time settings
    [Slot N]
      Name: string
      Time period: from HH:MM — until HH:MM
      Orientation light
        Activation: Off / On / Automatic
        Standard brightness: 5 steps
      Odour extraction unit
        Activation: Off / Automatic   ← NOTE: no "On" option in time slots
        Intensity: 5 steps
```

---

## DataPoint IDs (DuoFresh)

Source: `Geberit.ComLib.Core.DataPoint.DpId` + `DataPointDefinitionProvider.cs`, cross-checked against live reads.

### Global settings (no instance)

| DpId | Hex | Name | Type | Values | Confirmed |
|------|-----|------|------|--------|-----------|
| 23 | 0x17 | `DP_ODOUR_EXTRACTION_MODE` | OffOnAuto | 0=Off, 1=On, 2=Auto | ✓ read |
| 27 | 0x1B | `DP_ODOUR_EXTRACTION_POWER` | Enum | 0–4 (intensity steps) | ✓ read+write |
| 29 | 0x1D | `DP_ODOUR_EXTRACTION_FOLLOW_UP_TIME` | Enum | 0–4 (run-on time steps) | ✓ read |
| 32 | 0x20 | `DP_ODOUR_EXTRACTION_SENSOR_SENS` | Enum | 0–4 (sensitivity steps) | ✓ read |
| 44 | 0x2C | `DP_ORIENTATION_LIGHT_MODE` | OffOnAuto | 0=Off, 1=On, 2=Auto | ✓ read |
| 48 | 0x30 | `DP_ORIENTATION_LIGHT_INTENSITY` | Enum/Percent | 0–4 (brightness steps) | ✓ read |
| 50 | 0x32 | `DP_ORIENTATION_LIGHT_FOLLOW_UP_TIME` | Enum | 0–4 (illumination time steps) | ✓ read |
| 53 | 0x35 | `DP_ORIENTATION_LIGHT_SENSOR_SENS` | Enum | 0–4 (distance activation steps) | ✓ read |

All global DataPoints above: `isInternal = false`, `NoOfInstances = 1`, `Storage = NVM`.

**Device info DataPoints (not readable on RS8.0 — use BLE DIS instead):**

| DpId | Name | Type | Notes |
|------|------|------|-------|
| 304 | `DP_DEVICE_MODEL` | Counter | 2 version defs (0–255 / 0–15); ReadError on RS8.0 |
| 351 | `DP_MANUFACTURER_FW_VERSION` | Counter | isInternal=true; ReadError on RS8.0 |
| 369 | `DP_SALES_PRODUCT_SERIAL_NUMBER` | String | Protected; ReadError on RS8.0 |
| 371 | `DP_SALES_PRODUCT_SAP_NUMBER` | String | Protected, up to 12 bytes; ReadError on RS8.0 |

### Time slot DataPoints (instanced, instance = slot index 0–9)

| DpId | Hex | Name | Type | Values | Confirmed |
|------|-----|------|------|--------|-----------|
| 346 | 0x15A | `DP_SLOT_ENABLE` | OffOn | 0=disabled, 1=enabled | ✓ verified |
| 347 | 0x15B | `DP_SLOT_START` | Counter | uint32 LE, seconds since midnight | ✓ verified |
| 348 | 0x15C | `DP_SLOT_END` | Counter | uint32 LE, seconds since midnight | ✓ verified |
| 349 | 0x15D | (mood?) | — | **ReadError on RS8.0** — DpId wrong or absent | ✗ |
| 561 | 0x231 | `DP_ODOUR_EXTRACTION_TIME_CONTROL_SLOT_POWER` | Enum | 0–4 (intensity steps) | ✓ verified |
| 609 | 0x261 | `DP_SLOT_FAN_MODE` | OffAuto | 0=Off, 1=Auto | ✓ verified |
| 610 | 0x262 | `DP_SLOT_LIGHT_MODE` | OffOnAuto | 0=Off, 1=On, 2=Auto | ✓ verified |
| 760 | 0x2F8 | `DP_SLOT_LIGHT_INT` | Enum | 0–4 (brightness steps) | ✓ verified |
| 1100–1109 | 0x44C–0x455 | `DP_TIMESLOT_NAME_0` … `_9` | String | UTF-8, max 80 bytes, inst=0 | ReadError code 1 on RS8.0 |

**Known configured slots (as of 2026-06-06, verified by live script read)**:

| Slot idx | Name (Slovak) | Time period | START (s) | END (s) | Light | Fan mode | Fan intensity |
|----------|--------------|-------------|-----------|---------|-------|----------|---------------|
| 0 | "od polnoci do rana" (midnight to morning) | 00:00–06:00 | 0 | 21600 | On, brightness 0/4 | Off | 0/4 |
| 1 | "cez den" (during the day) | 06:01–22:00 | 21660 | 79200 | Off, brightness 0/4 | Auto | 1/4 |
| 2 | "od desiatej vecer do polnoci" (10pm to midnight) | 22:01–23:59 | 79260 | 86340 | On, brightness 0/4 | Auto | 0/4 |
| 3–9 | — | disabled | — | — | — | — | — |

SLOT_START and SLOT_END values matched exactly — DpIds 347 and 348 confirmed correct.

**Slot name design**: Unlike all other slot DataPoints, names are **not instanced** — each slot has a dedicated DpId (1100–1109). One DpId per slot, `NoOfInstances=1`, String up to 80 bytes, NVM. Read with instance=0.

**Slot names not on device (RS8.0 TS107)**: Reading DpId 1100 returns ReadError code `0x01` (DataPoint not supported). The device receives the frame correctly (it echoes back the right DpId and instance) but does not implement this DataPoint. **The slot names shown in the Geberit Android app are stored locally in the app on the phone, not on the device.** Newer firmware versions may implement these DataPoints.

**Notes on time slot fan**: The Geberit app shows "Off / Automatic" (no "On") for fan mode, and a separate 5-step intensity setting. `DP_SLOT_FAN_MODE` (609) uses `0=Off, 1=Auto`; `DP_ODOUR_EXTRACTION_TIME_CONTROL_SLOT_POWER` (561) stores the fan intensity step 0–4.

**Confirmed working**: `DP_ODOUR_EXTRACTION_POWER = 27`, value 4 = maximum fan power. Verified by Geberit Android app after writing `buildDataPointWrite(27, 4)`.

**Filter counter DataPoints (not implemented on RS8.0):**

| DpId | Name | Notes |
|------|------|-------|
| 924 | `DP_ODOUR_EXTRACTION_FILTER_REMAINING_CREDITS` | Counter; ReadError on RS8.0 |
| 925 | `DP_ODOUR_EXTRACTION_FILTER_REMAINING_DAYS` | Counter; ReadError on RS8.0 |
| 928 | `DP_ODOUR_EXTRACTION_FILTER_REPLACEMENTS` | Counter; ReadError on RS8.0 |

Only `FILTER_USAGE` (DpId 39) is readable — returns the overall status as Enum 0–4.

---

## Raw Config Notification

Device broadcasts a raw (not encrypted, not HDLC-wrapped) packet on every BLE connect:

```
buf[0] = 0x00
buf[1] = 0x03   ← packet type identifier
buf[2] = current light brightness output (raw scale, ~0–100)
buf[3] = light mode (1 = automatic)
buf[4] = fan mode (matches ODOUR_MODE DataPoint: 0=Off, 1=On, 2=Auto)
buf[5] = unknown — possibly live odour sensor reading
buf[6..] = tail bytes (partially unknown)
```

**Note**: `buf[4]` is the configured fan **mode**, not the current fan speed. A value of `2` (Auto) with the fan physically off is consistent — the device is in Auto mode but the sensor hasn't triggered the fan. The raw notification does not directly indicate whether the fan is currently running.

`buf[2]` (light brightness) shows the current actual PWM output, which differs from the configured `DP_ORIENTATION_LIGHT_INTENSITY` step — in Auto mode the device adjusts brightness continuously.

### Reading the raw notification

```javascript
const READ_CMD = Buffer.from([0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]);
await wch.writeValue(READ_CMD, { type: 'command' });
// device responds with raw config notification (buf[1] === 0x03)
```

---

## Keep-Alive

Device sends periodic type-`0x04` sensor packets (raw, non-encrypted). Echo them back to keep the connection alive:

```javascript
nch.on('valuechanged', (dv) => {
  const buf = dvToBuffer(dv);
  if (buf.length >= 2 && buf[0] !== 0x00 && buf[1] === 0x04) {
    wch.writeValue(buf, { type: 'command' }).catch(() => {});
  }
});
```

**Guard `buf[0] !== 0x00` is required.** COBS frames also start with `0x00` and happen to have `0x04` as the first COBS code byte during handshake. Echoing a COBS frame injects a `0x00` delimiter into the device's receive stream and corrupts any in-progress COBS frame.

---

## Failed Approaches

### Wrong plaintext format (all early attempts)

- **Symptom**: Device ACKs at HDLC level (N(R) increments in S-frame), but config never changes.
- **Root cause**: Plaintext was raw bytes, not a valid outer COBS frame. The outer `CobsFraming` (`bz`) accumulated the decrypted bytes until a `0x00` appeared, then tried COBS-decode. The decode failed (exception silently caught and discarded). `ConfigurationManager` never received data.
- **Fix**: Plaintext = `[0x00, COBS(DataPoint_payload + CRC16K), 0x00]`.

### Wrong DataPoint payload format (early attempts)

- Tried `[0x02, brightness, mode, fan, sensitivity, tail...]` mirroring the raw config notification.
- **Root cause**: Raw config notification is a raw firmware broadcast that bypasses the entire protocol stack. The DataPoint/FrameHandler protocol uses a completely different format: `[CommandId, DpId_lo, DpId_hi, value]`.
- **Fix**: Use `buildDataPointWrite(dpId, value)`.

---

## Decompilation

Tool: `.dotnet/tools/ilspycmd`

```
ilspycmd -p -o <output_dir> <dll_path>
```

Key DLLs (extracted from Geberit Android app APK `assets/` or `lib/`):

| DLL | Contents |
|-----|----------|
| `geberit-gidx-53.dll` | BLE transport, CobsFraming, HdlcFlowControl, SecurityServer, Ble20Product |
| `geberit-gidx-54.dll` | ConfigurationManager, FrameHandler, CommandId, AddressFrame, DataPoint types, DpId |
| `Geberit.ComLib.Iot.Core.dll` | Kotlin/JNI wrapper — not useful |

Key source files after decompilation:

| File | Namespace | Key info |
|------|-----------|----------|
| `CobsFraming.cs` | `Geberit.ComLib.Bluetooth.Protocol` | COBS encode/decode, CRC16K, 0x00 delimiter logic |
| `HdlcFlowControl.cs` | `Geberit.ComLib.Bluetooth.Protocol` | I-frame/S-frame ctrl byte format, N(S)/N(R) |
| `SecurityServer.cs` | `Geberit.ComLib.Bluetooth.Crypto` | Full handshake, key derivation, AES-CTR |
| `Ble20Product.cs` | `Geberit.ComLib.Bluetooth` | Protocol stack wiring (`by`→`bw`→`bx`→`bz`→`bv`) |
| `ConfigurationManager.cs` | `Geberit.ComLib.Core.Configuration` | Delegates to FrameHandler |
| `FrameHandler.cs` | `Geberit.ComLib.Core.Frame` | Write()/Read() methods, AddressFrame assembly |
| `CommandId.cs` | `Geberit.ComLib.Core.Frame` | CommandId enum |
| `AddressFrame.cs` | `Geberit.ComLib.Core.Frame` | DataPoint frame wire format |
| `DataPointEnum.cs` | `Geberit.ComLib.Core.DataPoint` | Single-byte enum DataPoint |
| `DpId.cs` | `Geberit.ComLib.Core.DataPoint` | DataPoint ID constants |
| `DataPointDefinitionProvider.cs` | `Geberit.ComLib.Core.DataPoint` | Per-DpId min/max/default/type/NVM flags |

---

## Implementation

Script: [`geberit-secure.mjs`](geberit-secure.mjs) (Node.js ESM, Linux + BlueZ required)

### Requirements

- Linux with BlueZ
- Node.js ≥ 18
- `node-ble` and `dbus-next` (see [`package.json`](package.json))

```bash
npm install
```

### Usage

```bash
# Scan for nearby Geberit devices (identified by CMD_SVC UUID via D-Bus UUIDs property)
node geberit-secure.mjs --scan [--timeout <seconds>]

# Print all settings to stdout
node geberit-secure.mjs --get <BLE_address>

# Save writable settings (fan, light, time slots) to JSON
node geberit-secure.mjs --dump <BLE_address> <file.json>

# Validate and write settings from JSON back to device
node geberit-secure.mjs --write <BLE_address> <file.json>
```

`--scan` uses `SetDiscoveryFilter` (UUID `0xFD48`) as a BlueZ-level optimization, then post-filters by reading each device's `UUIDs` property via D-Bus Properties.Get. This correctly excludes cached non-Geberit devices that resist `RemoveDevice` because they are actively advertising.

`--get`, `--dump`, and `--write` all: connect → read BLE DIS (no encryption) → Security handshake → DataPoint read/write.

`--dump` saves only the writable fields: odour extraction settings, orientation light settings, and all 10 time slots (enable, start/end in seconds, light mode/intensity, fan mode/intensity). Slot names are not dumped — they are stored in the app, not on the device (RS8.0 TS107).

`--write` validates all fields (integer ranges, slot start ≤ end ≤ 86399) before connecting.

### Sample output (`--get`)

```
[CMAC self-test] OK
Connecting...
Connected

═══ Device Info (BLE DIS) ═══
  Manufacturer: Geberit
  Model       : 831.497.00.0
  Serial      : 111111
  FW revision : 10.7 OTA4.3 20240202
  HW revision : 08
  SW revision : 1.10.0 1.2.0

[Security] Starting handshake...
[Security] → VersionRequest: 00022003332300
  [rx 18:08:45.643] 0004218b3000  len=6
  [frame 18:08:45.643] cobs(4): 04218b30
  [frame] S/U-frame
  [rx 18:08:45.975] 0004218b3000  len=6
  [frame 18:08:45.976] cobs(4): 04218b30
  [frame] S/U-frame
[Security]   (no version response — assuming proto v2)
[Security] → EncryptParamRequest: 00042210020100
  [rx 18:08:47.363] 00244211xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  len=20
  [rx 18:08:47.364] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  len=20
  [rx 18:08:47.366] 00  len=1
  [frame 18:08:47.366] cobs(39): 4211xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  [frame] type=0x11 routing=0x42
[Security] ← EncryptParamResponse  S=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  T=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[Security] → KeyExchangeRequest (56 bytes)
  [rx 18:08:47.371] 0004418d5300  len=6
  [frame 18:08:47.371] cobs(4): 04418d53
  [frame] S/U-frame
  [rx 18:08:47.476] 00356413xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  len=20
  [rx 18:08:47.476] xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  len=20
  [rx 18:08:47.478] xxxxxxxxxxxxxxxxxxxxxxxxxxxx00  len=15
  [frame 18:08:47.478] cobs(53): 6413xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  [frame] type=0x13 routing=0x64
[Security]   Device MAC verified ✓
[Security]   sendKey = <session key>
[Security]   IV(T)   = <session IV>

═══ Filter Maintenance ═══
  Status : Replace soon (3/4)

═══ Odour Extraction ═══
  Power      : 4/4
  Mode       : Auto
  Follow-up  : 2/4
  Sensitivity: 4/4

═══ Orientation Light ═══
  Mode       : Auto
  Intensity  : 0/4
  Follow-up  : 1/4
  Sensitivity: 2/4

═══ Time Slots ═══
  Slot 0: 00:00–06:00
    Light: On, brightness 0/4
    Fan:   Off, intensity 0/4
  Slot 1: 06:01–22:00
    Light: Off, brightness 0/4
    Fan:   Auto, intensity 1/4
  Slot 2: 22:01–23:59
    Light: On, brightness 0/4
    Fan:   Auto, intensity 0/4
  Slot 3–9: disabled

Disconnected.
```

Salt/IV/sendKey are random per session.
