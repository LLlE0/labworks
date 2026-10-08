import os
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(160), nullable=False, default="")
    role = db.Column(db.String(30), nullable=False, default="operator")
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class Building(db.Model):
    __tablename__ = "buildings"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(255), nullable=False, default="")
    description = db.Column(db.Text, nullable=False, default="")


class ESPDevice(db.Model):
    __tablename__ = "esp32_devices"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(80), unique=True, nullable=False)
    building_id = db.Column(db.Integer, db.ForeignKey("buildings.id"), nullable=False)
    firmware_version = db.Column(db.String(40), nullable=False, default="esp8266-1.0")
    is_online = db.Column(db.Boolean, nullable=False, default=False)
    building = db.relationship("Building", backref="devices")


class TrustedNetwork(db.Model):
    __tablename__ = "trusted_networks"
    __table_args__ = (UniqueConstraint("building_id", "bssid", name="uq_trusted_building_bssid"),)

    id = db.Column(db.Integer, primary_key=True)
    building_id = db.Column(db.Integer, db.ForeignKey("buildings.id"), nullable=False)
    ssid = db.Column(db.String(120), nullable=False)
    bssid = db.Column(db.String(20), nullable=False)
    encryption_type = db.Column(db.String(30), nullable=False, default="WPA2")
    building = db.relationship("Building", backref="trusted_networks")


class ScanSession(db.Model):
    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("esp32_devices.id"), nullable=False)
    building_id = db.Column(db.Integer, db.ForeignKey("buildings.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(30), nullable=False, default="completed")
    device = db.relationship("ESPDevice")
    building = db.relationship("Building")
    user = db.relationship("User")


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.BigInteger, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    scan_time = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    ssid = db.Column(db.String(120), nullable=False)
    bssid = db.Column(db.String(20), nullable=False)
    rssi = db.Column(db.Integer, nullable=False)
    encryption_type = db.Column(db.String(30), nullable=False, default="UNKNOWN")
    threat_level = db.Column(db.String(30), nullable=False, default="SAFE")
    scan_session = db.relationship("ScanSession", backref="results")


class Threat(db.Model):
    __tablename__ = "threats"

    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.BigInteger, db.ForeignKey("scan_results.id"), nullable=True)
    building_id = db.Column(db.Integer, db.ForeignKey("buildings.id"), nullable=False)
    ssid = db.Column(db.String(120), nullable=False, default="")
    bssid = db.Column(db.String(20), nullable=False, default="")
    threat_type = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="new")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    scan_result = db.relationship("ScanResult", backref="threat")
    building = db.relationship("Building")


class SystemSetting(db.Model):
    __tablename__ = "system_settings"

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "postgresql+psycopg://lab:lab_password@localhost:5433/lab"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_database()

    register_routes(app)
    return app


def seed_database():
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "admin")
    if not User.query.filter_by(username=username).first():
        db.session.add(
            User(
                username=username,
                password_hash=generate_password_hash(password),
                email="admin@lab.local",
                role="administrator",
            )
        )
    if not Building.query.first():
        building = Building(name="Учебный корпус", address="Таганрог", description="Демо-объект мониторинга")
        db.session.add(building)
        db.session.flush()
        db.session.add(ESPDevice(device_id="ESP8266-DEMO-001", building_id=building.id, firmware_version="esp8266-1.0"))
        db.session.add(
            TrustedNetwork(
                building_id=building.id,
                ssid="SFEDU-SAFE",
                bssid="AA:BB:CC:DD:EE:01",
                encryption_type="WPA2",
            )
        )
    ensure_setting("serial_port", os.getenv("SERIAL_PORT", "/dev/ttyUSB0"))
    ensure_setting("serial_baudrate", os.getenv("SERIAL_BAUDRATE", "115200"))
    db.session.commit()


def ensure_setting(key, default_value):
    if not SystemSetting.query.filter_by(key=key).first():
        db.session.add(SystemSetting(key=key, value=str(default_value)))


def get_setting(key, default_value=""):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else default_value


def set_setting(key, value):
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = str(value)
        setting.updated_at = datetime.now(timezone.utc)
    else:
        db.session.add(SystemSetting(key=key, value=str(value)))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    if not session.get("user_id"):
        return None
    return db.session.get(User, session["user_id"])


def normalize_bssid(value):
    return (value or "").strip().upper()


def analyze_network(building_id, ssid, bssid, encryption_type):
    bssid = normalize_bssid(bssid)
    trusted_bssid = TrustedNetwork.query.filter_by(building_id=building_id, bssid=bssid).first()
    if trusted_bssid:
        return "SAFE", None

    trusted_ssid = TrustedNetwork.query.filter_by(building_id=building_id, ssid=ssid).first()
    if trusted_ssid:
        return "CRITICAL", ("EVIL_TWIN", "CRITICAL")
    if encryption_type.upper() == "OPEN":
        return "WARNING", ("ROGUE_AP", "MEDIUM")
    return "WARNING", ("UNKNOWN_DEVICE", "LOW")


def find_active_threat(building_id, bssid):
    return (
        Threat.query.filter_by(building_id=building_id, bssid=normalize_bssid(bssid))
        .filter(Threat.status != "resolved")
        .first()
    )


def upsert_threat(building_id, scan_result_id, ssid, bssid, threat_type, severity):
    """Create or refresh one active threat per building+BSSID (no duplicates)."""
    bssid = normalize_bssid(bssid)
    existing = find_active_threat(building_id, bssid)
    now = datetime.now(timezone.utc)
    if existing:
        existing.scan_result_id = scan_result_id
        existing.ssid = ssid
        existing.threat_type = threat_type
        existing.severity = severity
        existing.updated_at = now
        return False

    db.session.add(
        Threat(
            scan_result_id=scan_result_id,
            building_id=building_id,
            ssid=ssid,
            bssid=bssid,
            threat_type=threat_type,
            severity=severity,
            updated_at=now,
        )
    )
    return True


def replace_device_scan_snapshot(device_id, keep_session_id):
    """Keep only the latest scan session/results for a device; threats stay in history."""
    old_sessions = ScanSession.query.filter(
        ScanSession.device_id == device_id,
        ScanSession.id != keep_session_id,
    ).all()
    if not old_sessions:
        return

    old_session_ids = [item.id for item in old_sessions]
    old_result_ids = [
        item.id for item in ScanResult.query.filter(ScanResult.session_id.in_(old_session_ids)).all()
    ]
    if old_result_ids:
        Threat.query.filter(Threat.scan_result_id.in_(old_result_ids)).update(
            {Threat.scan_result_id: None},
            synchronize_session=False,
        )
        ScanResult.query.filter(ScanResult.id.in_(old_result_ids)).delete(synchronize_session=False)
    ScanSession.query.filter(ScanSession.id.in_(old_session_ids)).delete(synchronize_session=False)


def resolve_threats_for_network(building_id, bssid):
    bssid = normalize_bssid(bssid)
    threats = (
        Threat.query.filter_by(building_id=building_id, bssid=bssid)
        .filter(Threat.status != "resolved")
        .all()
    )
    now = datetime.now(timezone.utc)
    for threat in threats:
        threat.status = "resolved"
        threat.updated_at = now
    return len(threats)


def register_routes(app):
    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user = User.query.filter_by(username=request.form["username"], is_active=True).first()
            if user and check_password_hash(user.password_hash, request.form["password"]):
                session["user_id"] = user.id
                flash("Вход выполнен", "success")
                return redirect(url_for("dashboard"))
            flash("Неверный логин или пароль", "danger")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        stats = {
            "buildings": Building.query.count(),
            "devices": ESPDevice.query.count(),
            "trusted": TrustedNetwork.query.count(),
            "threats": Threat.query.filter(Threat.status != "resolved").count(),
        }
        latest_session = ScanSession.query.order_by(ScanSession.started_at.desc()).first()
        latest_results = []
        if latest_session:
            latest_results = (
                ScanResult.query.filter_by(session_id=latest_session.id)
                .order_by(ScanResult.rssi.desc())
                .all()
            )
        threats = (
            Threat.query.filter(Threat.status != "resolved")
            .order_by(Threat.updated_at.desc())
            .limit(12)
            .all()
        )
        return render_template(
            "dashboard.html",
            stats=stats,
            latest_results=latest_results,
            latest_session=latest_session,
            threats=threats,
        )

    @app.route("/trust-network", methods=["POST"])
    @login_required
    def trust_network():
        building_id = request.form.get("building_id", type=int)
        ssid = (request.form.get("ssid") or "<hidden>").strip()
        bssid = normalize_bssid(request.form.get("bssid"))
        encryption_type = (request.form.get("encryption_type") or "WPA2").strip() or "WPA2"

        if not building_id or not bssid:
            flash("Не удалось добавить сеть в доверенные", "danger")
            return redirect(url_for("dashboard"))

        existing = TrustedNetwork.query.filter_by(building_id=building_id, bssid=bssid).first()
        if existing:
            existing.ssid = ssid
            existing.encryption_type = encryption_type
        else:
            db.session.add(
                TrustedNetwork(
                    building_id=building_id,
                    ssid=ssid,
                    bssid=bssid,
                    encryption_type=encryption_type,
                )
            )

        resolved = resolve_threats_for_network(building_id, bssid)
        db.session.commit()
        flash(f"Сеть {ssid} добавлена в доверенные" + (f", закрыто угроз: {resolved}" if resolved else ""), "success")
        return redirect(url_for("dashboard"))

    @app.route("/buildings", methods=["GET", "POST"])
    @login_required
    def buildings():
        if request.method == "POST":
            db.session.add(
                Building(
                    name=request.form["name"],
                    address=request.form.get("address", ""),
                    description=request.form.get("description", ""),
                )
            )
            db.session.commit()
            flash("Здание добавлено", "success")
            return redirect(url_for("buildings"))
        return render_template("buildings.html", buildings=Building.query.order_by(Building.name).all())

    @app.route("/buildings/<int:building_id>/delete", methods=["POST"])
    @login_required
    def delete_building(building_id):
        building = db.session.get(Building, building_id)
        if building:
            db.session.delete(building)
            db.session.commit()
            flash("Здание удалено", "success")
        return redirect(url_for("buildings"))

    @app.route("/devices", methods=["GET", "POST"])
    @login_required
    def devices():
        if request.method == "POST":
            db.session.add(
                ESPDevice(
                    device_id=request.form["device_id"],
                    building_id=request.form["building_id"],
                    firmware_version=request.form.get("firmware_version", "esp8266-1.0"),
                    is_online=bool(request.form.get("is_online")),
                )
            )
            db.session.commit()
            flash("Устройство зарегистрировано", "success")
            return redirect(url_for("devices"))
        return render_template(
            "devices.html",
            devices=ESPDevice.query.order_by(ESPDevice.device_id).all(),
            buildings=Building.query.order_by(Building.name).all(),
        )

    @app.route("/trusted-networks", methods=["GET", "POST"])
    @login_required
    def trusted_networks():
        if request.method == "POST":
            db.session.add(
                TrustedNetwork(
                    building_id=request.form["building_id"],
                    ssid=request.form["ssid"],
                    bssid=normalize_bssid(request.form["bssid"]),
                    encryption_type=request.form.get("encryption_type", "WPA2"),
                )
            )
            db.session.commit()
            flash("Доверенная сеть добавлена", "success")
            return redirect(url_for("trusted_networks"))
        return render_template(
            "trusted_networks.html",
            networks=TrustedNetwork.query.order_by(TrustedNetwork.ssid).all(),
            buildings=Building.query.order_by(Building.name).all(),
        )

    @app.route("/scan-sessions")
    @login_required
    def scan_sessions():
        sessions = ScanSession.query.order_by(ScanSession.started_at.desc()).all()
        return render_template("scan_sessions.html", sessions=sessions)

    @app.route("/threats", methods=["GET", "POST"])
    @login_required
    def threats():
        if request.method == "POST":
            threat = db.session.get(Threat, request.form["threat_id"])
            if threat:
                threat.status = request.form["status"]
                db.session.commit()
                flash("Статус угрозы обновлён", "success")
            return redirect(url_for("threats"))
        threats_list = Threat.query.order_by(Threat.created_at.desc()).all()
        return render_template("threats.html", threats=threats_list)

    @app.route("/users", methods=["GET", "POST"])
    @login_required
    def users():
        if request.method == "POST":
            db.session.add(
                User(
                    username=request.form["username"],
                    password_hash=generate_password_hash(request.form["password"]),
                    email=request.form.get("email", ""),
                    role=request.form.get("role", "operator"),
                    is_active=bool(request.form.get("is_active")),
                )
            )
            db.session.commit()
            flash("Пользователь добавлен", "success")
            return redirect(url_for("users"))
        return render_template("users.html", users=User.query.order_by(User.username).all())


    @app.route("/serial", methods=["GET", "POST"])
    @login_required
    def serial_settings():
        if request.method == "POST":
            serial_port = request.form.get("serial_port", "").strip() or "/dev/ttyUSB0"
            serial_baudrate = request.form.get("serial_baudrate", "115200").strip() or "115200"
            if not serial_port.startswith("/dev/tty"):
                flash("TTY должен начинаться с /dev/tty, например /dev/ttyUSB0", "danger")
                return redirect(url_for("serial_settings"))
            if not serial_baudrate.isdigit():
                flash("Скорость должна быть числом", "danger")
                return redirect(url_for("serial_settings"))
            set_setting("serial_port", serial_port)
            set_setting("serial_baudrate", serial_baudrate)
            db.session.commit()
            flash("Serial-интерфейс сохранён. Gateway переподключится автоматически.", "success")
            return redirect(url_for("serial_settings"))

        return render_template(
            "serial_settings.html",
            serial_port=get_setting("serial_port", "/dev/ttyUSB0"),
            serial_baudrate=get_setting("serial_baudrate", "115200"),
        )

    @app.route("/api/serial-config")
    def api_serial_config():
        return jsonify(
            {
                "serial_port": get_setting("serial_port", "/dev/ttyUSB0"),
                "serial_baudrate": int(get_setting("serial_baudrate", "115200")),
            }
        )

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        payload = request.get_json(force=True, silent=True) or {}
        device = ESPDevice.query.filter_by(device_id=payload.get("device_id")).first()
        if not device:
            return jsonify({"error": "unknown device_id"}), 404

        device.is_online = True
        scan_session = ScanSession(
            device_id=device.id,
            building_id=device.building_id,
            user_id=session.get("user_id"),
            status="completed",
        )
        db.session.add(scan_session)
        db.session.flush()

        created_threats = 0
        updated_threats = 0
        seen_bssids = set()

        for network in payload.get("networks", []):
            ssid = network.get("ssid") or "<hidden>"
            bssid = normalize_bssid(network.get("bssid"))
            if not bssid or bssid in seen_bssids:
                continue
            seen_bssids.add(bssid)

            encryption_type = network.get("encryption_type", "UNKNOWN")
            threat_level, threat_data = analyze_network(device.building_id, ssid, bssid, encryption_type)
            result = ScanResult(
                session_id=scan_session.id,
                ssid=ssid,
                bssid=bssid,
                rssi=int(network.get("rssi", -100)),
                encryption_type=encryption_type,
                threat_level=threat_level,
            )
            db.session.add(result)
            db.session.flush()

            if threat_data:
                created = upsert_threat(
                    device.building_id,
                    result.id,
                    ssid,
                    bssid,
                    threat_data[0],
                    threat_data[1],
                )
                if created:
                    created_threats += 1
                else:
                    updated_threats += 1
            else:
                # Trusted / safe again — close any leftover open threat for this BSSID
                resolve_threats_for_network(device.building_id, bssid)

        replace_device_scan_snapshot(device.id, scan_session.id)
        db.session.commit()
        return jsonify(
            {
                "session_id": scan_session.id,
                "networks": len(seen_bssids),
                "threats_created": created_threats,
                "threats_updated": updated_threats,
            }
        )


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
