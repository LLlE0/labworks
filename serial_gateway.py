import json
import os
import time

import requests
import serial


DEFAULT_SERIAL_PORT = os.getenv("SERIAL_PORT", "/dev/ttyUSB0")
DEFAULT_SERIAL_BAUDRATE = int(os.getenv("SERIAL_BAUDRATE", "115200"))
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000/api/scan")
CONFIG_URL = os.getenv("CONFIG_URL", "http://localhost:5000/api/serial-config")
CONFIG_REFRESH_SECONDS = 3
MAX_BUFFER_SIZE = 65536


def wait_for_server():
    health_url = SERVER_URL.rsplit("/", 1)[0].replace("/api", "/login")
    while True:
        try:
            requests.get(health_url, timeout=3)
            return
        except requests.RequestException:
            print("server is not ready, retrying...", flush=True)
            time.sleep(2)


def load_serial_config():
    try:
        response = requests.get(CONFIG_URL, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get("serial_port", DEFAULT_SERIAL_PORT), int(data.get("serial_baudrate", DEFAULT_SERIAL_BAUDRATE))
    except (requests.RequestException, ValueError, TypeError) as exc:
        print(f"serial config fallback: {exc}", flush=True)
        return DEFAULT_SERIAL_PORT, DEFAULT_SERIAL_BAUDRATE


def forward_payload(payload):
    response = requests.post(SERVER_URL, json=payload, timeout=10)
    response.raise_for_status()
    print(f"forwarded scan: {response.text}", flush=True)


def extract_json_objects(buffer):
    objects = []
    start = None
    depth = 0
    in_string = False
    escaped = False

    for index, char in enumerate(buffer):
        if start is None:
            if char == "{":
                start = index
                depth = 1
                in_string = False
                escaped = False
            continue

        if escaped:
            escaped = False
            continue

        if char == "\\" and in_string:
            escaped = True
            continue

        if char == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                objects.append(buffer[start:index + 1])
                remainder = buffer[index + 1:]
                return objects, remainder

    if start is None:
        return objects, ""
    return objects, buffer[start:]


def process_payload(raw_json):
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        print(f"bad json from serial: {exc}", flush=True)
        return

    if "device_id" not in payload or "networks" not in payload:
        return

    try:
        forward_payload(payload)
    except requests.RequestException as exc:
        print(f"backend post failed: {exc}", flush=True)


def read_serial_stream(port):
    buffer = ""
    while True:
        chunk = port.read(1024)
        if not chunk:
            yield None
            continue

        buffer += chunk.decode("utf-8", errors="ignore")
        if len(buffer) > MAX_BUFFER_SIZE:
            first_json = buffer.find("{")
            buffer = buffer[first_json:] if first_json >= 0 else ""

        while True:
            objects, buffer = extract_json_objects(buffer)
            if not objects:
                break
            for raw_json in objects:
                yield raw_json


def main():
    wait_for_server()
    active_port = None
    active_baudrate = None

    while True:
        serial_port, serial_baudrate = load_serial_config()
        if serial_port != active_port or serial_baudrate != active_baudrate:
            print(f"serial config: {serial_port} at {serial_baudrate} baud", flush=True)
            active_port = serial_port
            active_baudrate = serial_baudrate

        try:
            with serial.Serial(active_port, active_baudrate, timeout=0.5) as port:
                # CH340/ESP8266: keep DTR/RTS low so the board is not held in reset
                port.dtr = False
                port.rts = False
                time.sleep(0.3)
                port.reset_input_buffer()
                last_config_check = time.monotonic()

                for raw_json in read_serial_stream(port):
                    if time.monotonic() - last_config_check >= CONFIG_REFRESH_SECONDS:
                        new_port, new_baudrate = load_serial_config()
                        last_config_check = time.monotonic()
                        if new_port != active_port or new_baudrate != active_baudrate:
                            print(f"serial config changed: {new_port} at {new_baudrate} baud", flush=True)
                            active_port = new_port
                            active_baudrate = new_baudrate
                            break

                    if raw_json is not None:
                        process_payload(raw_json)
        except serial.SerialException as exc:
            print(f"serial port unavailable: {exc}", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
