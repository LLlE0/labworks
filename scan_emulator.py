import json
import random
import time

import requests

SERVER_URL = "http://localhost:5000/api/scan"
DEVICE_ID = "ESP8266-DEMO-001"

NETWORKS = [
    {"ssid": "SFEDU-SAFE", "bssid": "AA:BB:CC:DD:EE:01", "rssi": -42, "encryption_type": "WPA2"},
    {"ssid": "TP-Link_Guest", "bssid": "AA:BB:CC:DD:EE:02", "rssi": -58, "encryption_type": "WPA2"},
    {"ssid": "OpenNet", "bssid": "AA:BB:CC:DD:EE:03", "rssi": -65, "encryption_type": "OPEN"},
    {"ssid": "SFEDU-SAFE", "bssid": "AA:BB:CC:DD:EE:04", "rssi": -51, "encryption_type": "WPA2"},
    {"ssid": "UnknownAP", "bssid": "AA:BB:CC:DD:EE:05", "rssi": -72, "encryption_type": "WPA3"},
    {"ssid": "CoffeeShop", "bssid": "AA:BB:CC:DD:EE:06", "rssi": -80, "encryption_type": "WPA2"},
]


def send_scan():
    payload = {
        "device_id": DEVICE_ID,
        "networks": [
            {
                "ssid": n["ssid"],
                "bssid": n["bssid"],
                "rssi": n["rssi"] + random.randint(-3, 3),
                "encryption_type": n["encryption_type"],
            }
            for n in NETWORKS
        ],
    }

    resp = requests.post(SERVER_URL, json=payload, timeout=10)
    print(f"POST {SERVER_URL} -> {resp.status_code} {resp.text}")
    return resp


if __name__ == "__main__":
    print(f"Sending scan from {DEVICE_ID}...")
    send_scan()