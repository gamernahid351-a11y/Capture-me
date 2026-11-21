# FFCapture — Free Fire Packet Capture & Editor

Android app that captures, decodes and re-sends Free Fire network traffic.  
**No root required** — uses Android `VpnService` as a local MITM.

---

## Features

| Feature | Detail |
|---|---|
| VPN capture | Hooks Free Fire packets (no root) |
| AES decrypt | Static key (MajorLogin) + session key (auto-extracted) |
| Protobuf decode | Wire-format parser → flat map + tree |
| Deep scan | Auto-tags UIDs, team codes, GIDs |
| UDP msg names | Full message ID → name table (970+ entries) |
| **Packet editor** | Edit any protobuf field value inline |
| **Raw hex editor** | Edit raw hex directly |
| **Resend** | Send edited TCP or UDP packet to custom host:port |
| **Varint tool** | `var(v)` / `zz(v)` encode + decode + build_mark_info |
| JSON export | HTTP / TCP / UDP / All — downloadable |
| Session key log | Auto-captured from MajorLogin response |

---

## Packet Editor

1. Tap any packet in the list → **Detail screen**
2. Scroll to **EDITABLE FIELDS** — each protobuf field is shown with its type and current value
3. Edit any field value inline
4. The rebuilt hex updates live in **RAW HEX EDIT**
5. Set target host/port (defaults from packet's channel)
6. Optionally enable **Encrypt (session key)** to AES-CBC the body
7. Tap **Send UDP** or **Send TCP**
8. Response is decoded and added to the capture list

---

## Varint / ZigZag Tool

Menu → **Varint Tool**

```
ENCODE:
  Input: 300        (decimal or 0x12C hex)
  var(v) → ac 02    (2 bytes)
  zz(v)  → d804     (zigzag)

DECODE:
  Input: ac 02 → 300

BUILD mark_info:
  Fills: owner_id, TarPlayID, MarkerType, MarkFlag, ScannerMarkFlag, seq, flags
  Output: full serialize_packet(0, 970, 0, flags, build_mark_info(...))
```

Python equivalent:
```python
def var(v):
    out = bytearray()
    while True:
        b = v & 0x7F; v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v: return bytes(out)

def zz(v):
    return var((v << 1) ^ (v >> 63))

def build_mark_info(owner_id, infos):
    out = bytearray(var(owner_id))
    out += zz(len(infos))
    for m in infos:
        out += var(m["TarPlayID"])
        out += bytes([m["MarkerType"] & 0xFF])
        out += var(m["MarkFlag"])
        out += var(m["ScannerMarkFlag"])
    return bytes(out)

moco = serialize_packet(0, 970, 0, flags,
                        build_mark_info(self.owner_id, marks),
                        self.tea_key, self.udp_mask)
```

All of this is implemented identically in `PacketBuilder.kt`.

---

## Build with GitHub Actions

### 1. Push to GitHub

```bash
git init
git remote add origin https://github.com/YOUR/FFCapture.git
git add .
git commit -m "initial"
git push -u origin main
```

### 2. Automatic build

Every push to `main` / `dev` triggers `.github/workflows/build.yml`:

- Builds **debug APK** → download from Actions → Artifacts
- Builds **release APK** (unsigned by default)

### 3. Signed release (optional)

Add these **Repository Secrets** (`Settings → Secrets → Actions`):

| Secret | Value |
|---|---|
| `KEYSTORE_BASE64` | `base64 -w0 my.keystore` |
| `KEY_ALIAS` | Your key alias |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_PASSWORD` | Key password |

### 4. Release APK on tag

```bash
git tag v1.0.0
git push origin v1.0.0
```
→ GitHub Release created automatically with APK attached.

---

## Manual Build

```bash
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk

./gradlew assembleRelease
# APK: app/build/outputs/apk/release/app-release-unsigned.apk
```

Requires JDK 17 + Android SDK.

---

## Project Structure

```
app/src/main/java/com/ffcapture/
├── decoder/
│   ├── MessageIds.kt      # 970+ UDP msg ID → name table
│   ├── PacketDecoder.kt   # AES decrypt + protobuf parser + deep scan
│   └── PacketBuilder.kt   # var() / zz() / build_mark_info() / serialize_packet()
├── model/
│   ├── Constants.kt       # Ports, AES keys, FF IND hosts, route map
│   ├── Packet.kt          # Data classes (Packet, ScanEntry, CaptureDump)
│   └── CaptureRepository.kt  # In-memory store + LiveData + JSON export
├── vpn/
│   ├── CaptureVpnService.kt  # VPN TUN → IP parser → TCP/UDP capture
│   └── PacketSender.kt       # Resend edited packets (bypass VPN)
└── ui/
    ├── MainActivity.kt        # Packet list, filter, search, export
    ├── MainViewModel.kt
    ├── PacketListAdapter.kt
    ├── PacketDetailActivity.kt  # Full decode view + field editor + send
    ├── PacketEditViewModel.kt
    ├── RawFieldAdapter.kt       # Editable protobuf field rows
    └── VarintToolActivity.kt    # var/zz calculator + mark_info builder
```
