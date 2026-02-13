#include <WiFi.h>
#include "esp_wifi.h"
#include <map>

// ===================== Branding =====================
#define TOOL_NAME     "ESP32 Miracast Sniffer"
#define TOOL_VERSION  "v2.0.0"
#define TOOL_AUTHOR   "0xDaVinci (github.com/davinci0x01)"

// ===================== Modes =====================
enum Mode {
  MODE_SNIFF = 0,
  MODE_VERIFY_AP = 1
};

static Mode currentMode = MODE_SNIFF;

// ===================== Sniffer DB =====================
struct MacEntry {
  std::map<String, uint32_t> nameCounts; // name -> count
  int8_t lastRssi = 0;
  uint8_t lastCh = 0;
  uint32_t lastSeenMs = 0;
};

static std::map<String, MacEntry> db;

// ===================== Sniffer Settings =====================
static bool sniffEnabled = true;

// Channels that worked well for you
static int channels[] = {11, 1, 6, 8, 10};
static int chIdx = 0;

static String lastSeenMac = "";
static String targetMac = ""; // for verification matching

// ===================== Verify AP Settings =====================
static const char *AP_SSID = "Cast-Verify-0xDaVinci";
static const char *AP_PASS = "12345678";   // change if you want
static uint32_t lastApListMs = 0;

// ===================== Helpers =====================
static uint16_t be16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static uint16_t le16(const uint8_t *p) { return ((uint16_t)p[1] << 8) | p[0]; }

static String macToString(const uint8_t *mac) {
  char s[18];
  snprintf(s, sizeof(s), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(s);
}

static bool isAllZeroMac(const String &m) { return m == "00:00:00:00:00:00"; }
static bool isBogusMac(const String &m) { return (m == "02:00:00:00:00:00") || isAllZeroMac(m); }

static String trimSpaces(String s) {
  int start = 0;
  while (start < (int)s.length() && (s[start] == ' ' || s[start] == '\t')) start++;
  int end = (int)s.length() - 1;
  while (end >= start && (s[end] == ' ' || s[end] == '\t')) end--;
  if (end < start) return "";
  return s.substring(start, end + 1);
}

static String normalizeMac(String s) {
  s.trim();
  s.toUpperCase();
  s.replace("-", ":");
  s.replace(" ", "");
  return s;
}

static bool isBadName(const String &s) {
  String t = trimSpaces(s);
  return t.length() < 2;
}

// ===== WPS Device Name (0x1011) from WPS attribute block =====
static bool extractWpsDeviceNameFromBlock(const uint8_t *blk, int blen, String &out) {
  int pos = 0;
  while (pos + 4 <= blen) {
    uint16_t atype = be16(&blk[pos]);
    uint16_t alen  = be16(&blk[pos + 2]);
    pos += 4;
    if (pos + alen > blen) break;

    if (atype == 0x1011 && alen > 0) {
      out = "";
      for (int i = 0; i < alen; i++) {
        uint8_t b = blk[pos + i];
        if (b == 0x00 || b == 0x0A || b == 0x0D) out += ' ';
        else if (b < 0x09) out += ' ';
        else out += (char)b;
      }
      out = trimSpaces(out);
      return out.length() > 0;
    }
    pos += alen;
  }
  return false;
}

// Vendor IE WPS: OUI 00:50:F2 type 0x04
static bool extractWpsDeviceName(const uint8_t *frame, int len, String &outName) {
  if (len < 24) return false;
  int pos = 24;

  while (pos + 2 <= len) {
    uint8_t id = frame[pos];
    uint8_t ilen = frame[pos + 1];
    pos += 2;
    if (pos + ilen > len) break;

    if (id == 0xDD && ilen >= 4) {
      const uint8_t *ie = frame + pos;
      if (ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xF2 && ie[3] == 0x04) {
        if (ilen > 4) return extractWpsDeviceNameFromBlock(ie + 4, ilen - 4, outName);
      }
    }
    pos += ilen;
  }
  return false;
}

// P2P Device Name via Device Info attr (0x0D) -> embedded WPS attrs
static bool extractP2PDeviceName(const uint8_t *frame, int len, String &outName) {
  if (len < 24) return false;
  int pos = 24;

  while (pos + 2 <= len) {
    uint8_t id = frame[pos];
    uint8_t ilen = frame[pos + 1];
    pos += 2;
    if (pos + ilen > len) break;

    if (id == 0xDD && ilen >= 4) {
      const uint8_t *ie = frame + pos;

      // P2P OUI: 50:6F:9A type 0x09
      if (ie[0] == 0x50 && ie[1] == 0x6F && ie[2] == 0x9A && ie[3] == 0x09) {
        int p = 4, end = ilen;
        while (p + 3 <= end) {
          uint8_t attrId = ie[p];
          uint16_t aLen = le16(&ie[p + 1]);
          if (p + 3 + aLen > end) aLen = be16(&ie[p + 1]); // fallback
          if (p + 3 + aLen > end) break;

          const uint8_t *aVal = &ie[p + 3];

          // Device Info attribute
          if (attrId == 0x0D && aLen >= 6 + 2 + 8 + 1) {
            int q = 0;
            q += 6; // dev addr
            q += 2; // config
            q += 8; // primary type
            if (q >= (int)aLen) { p += 3 + aLen; continue; }

            uint8_t secCount = aVal[q];
            q += 1;
            int secBytes = (int)secCount * 8;
            if (q + secBytes > (int)aLen) { p += 3 + aLen; continue; }
            q += secBytes;

            int wpsLen = (int)aLen - q;
            if (wpsLen > 0) {
              String name;
              if (extractWpsDeviceNameFromBlock(aVal + q, wpsLen, name)) {
                outName = name;
                return true;
              }
            }
          }

          p += 3 + aLen;
        }
      }
    }

    pos += ilen;
  }

  return false;
}

static bool hasP2PorWPS(const uint8_t *frame, int len) {
  if (len < 24) return false;
  int pos = 24;
  while (pos + 2 <= len) {
    uint8_t id = frame[pos];
    uint8_t ilen = frame[pos + 1];
    pos += 2;
    if (pos + ilen > len) break;

    if (id == 0xDD && ilen >= 4) {
      const uint8_t *ie = frame + pos;
      bool isP2P = (ie[0]==0x50 && ie[1]==0x6F && ie[2]==0x9A && ie[3]==0x09);
      bool isWPS = (ie[0]==0x00 && ie[1]==0x50 && ie[2]==0xF2 && ie[3]==0x04);
      if (isP2P || isWPS) return true;
    }
    pos += ilen;
  }
  return false;
}

// ===================== Report + Help =====================
static void printHelp() {
  Serial.println("\nCommands:");
  Serial.println("  r            : print report now");
  Serial.println("  c            : clear database");
  Serial.println("  p            : pause/resume sniffing");
  Serial.println("  v            : enter VERIFY AP mode (stop sniff + start AP)");
  Serial.println("  s            : return to SNIFF mode");
  Serial.println("  L            : list connected stations (in VERIFY mode)");
  Serial.println("  T <MAC>      : set TARGET MAC for matching (example: T 66:D0:D6:69:14:54)");
  Serial.println("  h            : help\n");
}

static void printBanner() {
  Serial.println();
  Serial.println("=======================================");
  Serial.println(TOOL_NAME);
  Serial.print ("Version : "); Serial.println(TOOL_VERSION);
  Serial.print ("Author  : "); Serial.println(TOOL_AUTHOR);
  Serial.println("=======================================");
  Serial.println();
}

static void printReport() {
  Serial.println("\n===== REPORT (MAC -> names) =====");
  for (std::map<String, MacEntry>::iterator it = db.begin(); it != db.end(); ++it) {
    const String &mac = it->first;
    MacEntry &e = it->second;

    Serial.printf("MAC: %s\n", mac.c_str());
    Serial.printf("Last RSSI: %d\n", (int)e.lastRssi);
    Serial.println("Names:");

    for (std::map<String, uint32_t>::iterator nm = e.nameCounts.begin(); nm != e.nameCounts.end(); ++nm) {
      // Print name only (no counts)
      Serial.printf("  - %s\n", nm->first.c_str());
    }

    Serial.println("--------------------------------");
  }

  if (targetMac.length()) {
    Serial.print("TARGET MAC: ");
    Serial.println(normalizeMac(targetMac));
  } else {
    Serial.println("TARGET MAC: (not set)  -> use: T <MAC>");
  }

  if (lastSeenMac.length()) {
    Serial.print("Last seen MAC: ");
    Serial.println(lastSeenMac);
  }

  Serial.println("===== END REPORT =====\n");
}

// ===================== Promiscuous Callback =====================
static void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!sniffEnabled) return;
  if (currentMode != MODE_SNIFF) return;
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_pkt_rx_ctrl_t &rx = ppkt->rx_ctrl;
  const uint8_t *frame = ppkt->payload;
  int len = rx.sig_len;
  if (len < 24) return;

  uint8_t subType = (frame[0] >> 4) & 0xF;
  // probe req / action / auth / assoc req / reassoc req
  if (!(subType==4 || subType==13 || subType==11 || subType==0 || subType==2)) return;

  const uint8_t *src = frame + 10; // SA
  String mac = macToString(src);
  if (isBogusMac(mac)) return;

  if (!hasP2PorWPS(frame, len)) return;

  lastSeenMac = mac;

  MacEntry &e = db[mac];
  e.lastRssi = rx.rssi;
  e.lastCh = rx.channel;
  e.lastSeenMs = millis();

  String name;
  bool gotName = false;

  if (extractP2PDeviceName(frame, len, name)) gotName = true;
  else if (extractWpsDeviceName(frame, len, name)) gotName = true;

  if (gotName) {
    name = trimSpaces(name);
    if (!isBadName(name)) {
      uint32_t &cnt = e.nameCounts[name];
      cnt++;
      if (cnt == 1) {
        Serial.printf("[NEW NAME] MAC=%s  name='%s'  ch=%u  rssi=%d\n",
                      mac.c_str(), name.c_str(), (unsigned)e.lastCh, (int)e.lastRssi);
      }
    }
  }
}

// ===================== Mode Switching =====================
static void startSniffMode() {
  currentMode = MODE_SNIFF;
  sniffEnabled = true;

  // Ensure AP off
  WiFi.softAPdisconnect(true);
  delay(120);

  WiFi.mode(WIFI_MODE_STA);
  delay(150);
  WiFi.disconnect(false, false);
  delay(150);

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_start();
  delay(150);

  wifi_promiscuous_filter_t filt;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filt);

  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_promiscuous(true);

  chIdx = 0;
  esp_wifi_set_channel(channels[chIdx], WIFI_SECOND_CHAN_NONE);

  Serial.println("[MODE] SNIFF mode started (promiscuous ON).");
}

static void startVerifyAPMode() {
  // Stop sniffing first
  sniffEnabled = false;
  esp_wifi_set_promiscuous(false);
  delay(120);

  currentMode = MODE_VERIFY_AP;

  WiFi.mode(WIFI_AP);
  delay(200);

  bool ok = WiFi.softAP(AP_SSID, AP_PASS);
  delay(200);

  Serial.println("[MODE] VERIFY AP mode started (sniff stopped).");
  Serial.print("[VERIFY] SSID: "); Serial.println(AP_SSID);
  Serial.print("[VERIFY] PASS: "); Serial.println(AP_PASS);
  Serial.print("[VERIFY] AP IP: "); Serial.println(WiFi.softAPIP());

  if (!ok) Serial.println("[VERIFY] Failed to start AP!");
  Serial.println("[VERIFY] Type 'L' to show connected devices.");
  lastApListMs = 0;
}

// Convert MAC string to 6 bytes
static bool parseMacToBytes(const String &macIn, uint8_t out[6]) {
  String s = normalizeMac(macIn);

  if (s.length() != 17) return false;

  for (int i = 0; i < 6; i++) {
    int pos = i * 3;

    if (i < 5 && s[pos + 2] != ':') return false; // تأكد من وجود :

    auto hexVal = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
      return -1;
    };

    int h1 = hexVal(s[pos]);
    int h2 = hexVal(s[pos + 1]);
    if (h1 < 0 || h2 < 0) return false;

    out[i] = (uint8_t)((h1 << 4) | h2);
  }
  return true;
}

// Count matching bytes between two MACs
static int macByteMatches(const String &a, const String &b) {
  uint8_t A[6], B[6];
  if (!parseMacToBytes(a, A)) return -1;
  if (!parseMacToBytes(b, B)) return -1;

  int same = 0;
  for (int i = 0; i < 6; i++) {
    if (A[i] == B[i]) same++;
  }
  return same; // 0..6
}

// ===================== Verify: list stations =====================
static void listStationsOnce() {

  if (currentMode != MODE_VERIFY_AP) {
    Serial.println("[ERR] Not in VERIFY mode. Use 'v' first.");
    return;
  }

  wifi_sta_list_t sta_list;
  memset(&sta_list, 0, sizeof(sta_list));

  esp_err_t err = esp_wifi_ap_get_sta_list(&sta_list);
  if (err != ESP_OK) {
    Serial.printf("[VERIFY] esp_wifi_ap_get_sta_list error=%d\n", (int)err);
    return;
  }

  Serial.println("\n========== VERIFY MODE ==========");
  Serial.printf("Connected stations: %d\n", (int)sta_list.num);

  if (targetMac.length()) {
    Serial.print("Target MAC: ");
    Serial.println(normalizeMac(targetMac));
  } else {
    Serial.println("Target MAC: (not set)  -> use: T <MAC>");
  }

  Serial.println("----------------------------------");

  for (int i = 0; i < sta_list.num; i++) {

    uint8_t *m = sta_list.sta[i].mac;
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            m[0], m[1], m[2], m[3], m[4], m[5]);

    String staMac = String(macStr);

    Serial.print(" - ");
    Serial.print(staMac);

    if (targetMac.length()) {

      int same = macByteMatches(targetMac, staMac);

      if (same == 6) {
        Serial.println("   <-- MATCH ✅ (6/6)");
      }
      else if (same == 5) {
        Serial.println("   <-- NEAR MATCH ⭐ (5/6)");
      }
      else if (same >= 4) {
        Serial.printf("   <-- POSSIBLE ⚠️ (%d/6)\n", same);
      }
      else if (same >= 0) {
        Serial.printf("   (%d/6)\n", same);
      }
      else {
        Serial.println("   (MAC parse error)");
      }

    } else {
      Serial.println();
    }
  }

  Serial.println("=================================\n");
}

// ===================== Serial Line Parser =====================
static String lineBuf = "";

static void handleLine(String line) {
  line = trimSpaces(line);
  if (line.length() == 0) return;

  // single-letter commands
  if (line.equalsIgnoreCase("r")) { printReport(); return; }
  if (line.equalsIgnoreCase("c")) { db.clear(); Serial.println("[OK] Cleared database."); return; }
  if (line.equalsIgnoreCase("p")) { sniffEnabled = !sniffEnabled; Serial.printf("[OK] Sniffing %s.\n", sniffEnabled ? "RESUMED" : "PAUSED"); return; }
  if (line.equalsIgnoreCase("h")) { printHelp(); return; }

  if (line.equalsIgnoreCase("v")) { startVerifyAPMode(); return; }
  if (line.equalsIgnoreCase("s")) { startSniffMode(); return; }

  if (line.equalsIgnoreCase("L")) { listStationsOnce(); return; }

  // Target MAC command: T <mac>
  if (line.length() >= 1 && (line[0] == 'T' || line[0] == 't')) {
    String arg = trimSpaces(line.substring(1));
    if (arg.length() == 0) {
      Serial.println("[ERR] Usage: T 66:D0:D6:69:14:54");
      return;
    }
    arg.toUpperCase();
    targetMac = arg;
    Serial.print("[OK] Target MAC set to: ");
    Serial.println(targetMac);
    return;
  }

  Serial.println("[ERR] Unknown command. Type 'h' for help.");
}

// ===================== Setup / Loop =====================
void setup() {
  Serial.begin(115200);
  delay(500);

  printBanner();

  // Start in sniff mode
  startSniffMode();

  Serial.println("Tip: if Arabic appears as ???? use a UTF-8 serial monitor (Tera Term / VS Code).");
  printHelp();
}

void loop() {
  // Channel hop in sniff mode
  static uint32_t lastSwitch = 0;
  if (currentMode == MODE_SNIFF && sniffEnabled && millis() - lastSwitch > 1500) {
    lastSwitch = millis();
    chIdx = (chIdx + 1) % (sizeof(channels)/sizeof(channels[0]));
    esp_wifi_set_channel(channels[chIdx], WIFI_SECOND_CHAN_NONE);
  }

  // In verify mode, you may auto-list every few seconds (optional)
  if (currentMode == MODE_VERIFY_AP) {
    if (millis() - lastApListMs > 5000) {
      lastApListMs = millis();
      // listStationsOnce();   // uncomment this if you want auto listing
    }
  }

  // Read serial lines
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      handleLine(lineBuf);
      lineBuf = "";
    } else {
      // prevent very long input
      if (lineBuf.length() < 120) lineBuf += c;
    }
  }
}
