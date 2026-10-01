#include <ESP8266WiFi.h>

const char* DEVICE_ID = "ESP8266-DEMO-001";
const unsigned long FIRST_SCAN_DELAY_MS = 2000;
const unsigned long SCAN_INTERVAL_MS = 15000;

unsigned long nextScanAt = FIRST_SCAN_DELAY_MS;

String encryptionName(uint8_t encryptionType) {
  switch (encryptionType) {
    case ENC_TYPE_WEP:
      return "WEP";
    case ENC_TYPE_TKIP:
      return "WPA";
    case ENC_TYPE_CCMP:
      return "WPA2";
    case ENC_TYPE_NONE:
      return "OPEN";
    case ENC_TYPE_AUTO:
      return "AUTO";
    default:
      return "UNKNOWN";
  }
}

void appendJsonString(String& json, const String& value) {
  json += '"';
  for (size_t i = 0; i < value.length(); i++) {
    char c = value.charAt(i);
    switch (c) {
      case '"':
        json += "\\\"";
        break;
      case '\\':
        json += "\\\\";
        break;
      case '\b':
        json += "\\b";
        break;
      case '\f':
        json += "\\f";
        break;
      case '\n':
        json += "\\n";
        break;
      case '\r':
        json += "\\r";
        break;
      case '\t':
        json += "\\t";
        break;
      default:
        if ((uint8_t)c < 0x20) {
          json += " ";
        } else {
          json += c;
        }
        break;
    }
  }
  json += '"';
}

String buildScanJson(int networkCount) {
  String json;
  json.reserve(256 + networkCount * 120);

  json += "{\"device_id\":";
  appendJsonString(json, DEVICE_ID);
  json += ",\"networks\":[";

  for (int i = 0; i < networkCount; i++) {
    if (i > 0) {
      json += ',';
    }

    json += "{\"ssid\":";
    appendJsonString(json, WiFi.SSID(i));
    json += ",\"bssid\":";
    appendJsonString(json, WiFi.BSSIDstr(i));
    json += ",\"rssi\":";
    json += WiFi.RSSI(i);
    json += ",\"encryption_type\":";
    appendJsonString(json, encryptionName(WiFi.encryptionType(i)));
    json += '}';
  }

  json += "]}";
  return json;
}

void scanAndPrint() {
  int networkCount = WiFi.scanNetworks(false, true);

  if (networkCount < 0) {
    Serial.println("{\"device_id\":\"ESP8266-DEMO-001\",\"networks\":[]}");
    WiFi.scanDelete();
    return;
  }

  Serial.println(buildScanJson(networkCount));
  WiFi.scanDelete();
}

void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  delay(300);

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(200);
}

void loop() {
  unsigned long now = millis();
  if ((long)(now - nextScanAt) < 0) {
    delay(20);
    return;
  }

  scanAndPrint();
  nextScanAt = millis() + SCAN_INTERVAL_MS;
}
