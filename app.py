import os
import re
import csv
import json
import uuid
import logging
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_file, render_template
from email import message_from_string, message_from_bytes
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
import requests
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# Config
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Logging
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Optional MongoDB
mongo_client = None
db = None
if MONGO_URI:
    try:
        from pymongo import MongoClient
        mongo_client = MongoClient(MONGO_URI)
        db = mongo_client.email_header_analyzer
        logging.info("Connected to MongoDB")
    except Exception as e:
        logging.error(f"MongoDB connection failed: {e}")
        mongo_client = None
        db = None


def create_token(user_doc):
    payload = {
        "sub": str(user_doc["_id"]),
        "email": user_doc["email"],
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    claims = decode_token(token)
    return claims


def load_users_local():
    path = os.path.join(DATA_DIR, "users.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []


def save_users_local(users):
    path = os.path.join(DATA_DIR, "users.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def extract_ips_from_received(received_lines):
    ips = []
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for line in received_lines or []:
        for match in ip_regex.findall(line):
            try:
                ip_obj = ip_address(match)
                is_private = ip_obj.is_private
                ips.append({
                    "ip": match,
                    "is_private": is_private,
                })
            except ValueError:
                continue
    # Unique preserve order
    seen = set()
    unique = []
    for item in ips:
        if item["ip"] not in seen:
            unique.append(item)
            seen.add(item["ip"])
    return unique


def geolocate_ip(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else None
        resp = requests.get(url, timeout=5, params=params)
        if resp.status_code == 200:
            data = resp.json()
            loc = data.get("loc")
            lat, lon = (None, None)
            if loc and "," in loc:
                lat_str, lon_str = loc.split(",", 1)
                lat = float(lat_str)
                lon = float(lon_str)
            return {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),
                "latitude": lat,
                "longitude": lon,
            }
        else:
            return {"ip": ip}
    except Exception as e:
        logging.warning(f"Geolocation failed for {ip}: {e}")
        return {"ip": ip}


def parse_headers_from_text_or_eml(header_text=None, eml_bytes=None):
    if eml_bytes is not None:
        msg = message_from_bytes(eml_bytes)
    else:
        msg = message_from_string(header_text or "")

    received = msg.get_all("Received") or []
    ips = extract_ips_from_received(received)
    geo = []
    for item in ips:
        if not item["is_private"]:
            geo.append(geolocate_ip(item["ip"]))
        else:
            geo.append({"ip": item["ip"], "private": True})

    # Attempt simple hop timeline based on date at end of Received line
    hops = []
    for line in received:
        timestamp = None
        if ";" in line:
            date_part = line.split(";")[-1].strip()
            try:
                dt = parsedate_to_datetime(date_part)
                timestamp = dt.isoformat() if dt else None
            except Exception:
                timestamp = None
        hops.append({"received": line, "timestamp": timestamp})

    result = {
        "email_id": str(uuid.uuid4()),
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID"),
        "received": received,
        "ip_trace": ips,
        "geolocation": geo,
        "hops": hops,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Spoof detection: mismatched From domain vs Received path hosts
    try:
        from_domain = None
        if result["from"] and "@" in result["from"]:
            from_domain = result["from"].split("@")[-1].strip('> ')
        domains_in_received = []
        host_regex = re.compile(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
        for r in received:
            domains_in_received += host_regex.findall(r)
        mismatch = from_domain and (from_domain not in domains_in_received)
        result["spoof_check"] = {
            "from_domain": from_domain,
            "domains_in_received": list(sorted(set(domains_in_received))),
            "mismatch": bool(mismatch),
        }
    except Exception:
        result["spoof_check"] = {"error": "spoof check failed"}

    # SPF/DKIM/DMARC headers presence
    result["auth_headers"] = {
        "spf": msg.get("Received-SPF"),
        "dkim": msg.get("DKIM-Signature"),
        "dmarc": msg.get("Authentication-Results"),
    }

    return result


def save_analysis(doc, user_id=None):
    if user_id:
        doc["user_id"] = user_id
    if db:
        db.analyses.insert_one(doc)
        return doc
    # local file fallback
    path = os.path.join(DATA_DIR, f"{doc['email_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return doc


def load_history(user_id):
    results = []
    if db:
        cursor = db.analyses.find({"user_id": user_id}).sort("timestamp", -1)
        for d in cursor:
            d["_id"] = str(d["_id"])  # make JSON-safe
            results.append(d)
        return results
    # local
    for fname in os.listdir(DATA_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(DATA_DIR, fname), "r", encoding="utf-8") as f:
                try:
                    d = json.load(f)
                    if d.get("user_id") == user_id:
                        results.append(d)
                except Exception:
                    continue
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.post("/api/register")
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    if db:
        existing = db.users.find_one({"email": email})
        if existing:
            return jsonify({"error": "user exists"}), 409
        hashed = generate_password_hash(password)
        res = db.users.insert_one({"email": email, "password": hashed})
        user_doc = {"_id": res.inserted_id, "email": email}
        token = create_token(user_doc)
        return jsonify({"token": token})

    users = load_users_local()
    if any(u.get("email") == email for u in users):
        return jsonify({"error": "user exists"}), 409
    hashed = generate_password_hash(password)
    user_doc = {"_id": str(uuid.uuid4()), "email": email, "password": hashed}
    users.append(user_doc)
    save_users_local(users)
    token = create_token({"_id": user_doc["_id"], "email": email})
    return jsonify({"token": token})


@app.post("/api/login")
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    if db:
        user = db.users.find_one({"email": email})
        if not user or not check_password_hash(user.get("password", ""), password):
            return jsonify({"error": "invalid credentials"}), 401
        token = create_token(user)
        return jsonify({"token": token})

    for u in load_users_local():
        if u.get("email") == email and check_password_hash(u.get("password", ""), password):
            token = create_token({"_id": u["_id"], "email": email})
            return jsonify({"token": token})
    return jsonify({"error": "invalid credentials"}), 401


@app.post("/api/analyze")
def api_analyze():
    claims = require_auth()
    user_id = claims.get("sub") if claims else None

    header_text = request.form.get("header_text")
    file = request.files.get("eml_file")

    if not header_text and not file:
        return jsonify({"error": "Provide header_text or upload .eml file"}), 400

    try:
        if file:
            filename = file.filename or ""
            if not filename.lower().endswith(".eml"):
                return jsonify({"error": "Only .eml files are allowed"}), 400
            content = file.read()
            analysis = parse_headers_from_text_or_eml(eml_bytes=content)
        else:
            # Sanitize input
            safe_text = header_text.replace("\r", "\n")
            analysis = parse_headers_from_text_or_eml(header_text=safe_text)
        save_analysis(analysis, user_id=user_id)
        return jsonify(analysis)
    except Exception as e:
        logging.exception("Analysis failed")
        return jsonify({"error": str(e)}), 500


@app.get("/api/history")
def api_history():
    claims = require_auth()
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    user_id = claims.get("sub")
    results = load_history(user_id)

    # Filtering
    sender = request.args.get("sender")
    ip = request.args.get("ip")
    since = request.args.get("since")
    until = request.args.get("until")

    def within_date(ts):
        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            return True
        ok = True
        if since:
            try:
                ok = ok and dt >= datetime.fromisoformat(since)
            except Exception:
                pass
        if until:
            try:
                ok = ok and dt <= datetime.fromisoformat(until)
            except Exception:
                pass
        return ok

    filtered = []
    for r in results:
        if sender and sender.lower() not in (r.get("from") or "").lower():
            continue
        if ip and not any(item.get("ip") == ip for item in r.get("ip_trace", [])):
            continue
        if not within_date(r.get("timestamp", datetime.utcnow().isoformat())):
            continue
        filtered.append(r)
    return jsonify(filtered)


@app.get("/api/export")
def api_export():
    claims = require_auth()
    if not claims:
        return jsonify({"error": "unauthorized"}), 401
    user_id = claims.get("sub")
    results = load_history(user_id)
    # CSV export
    csv_path = os.path.join(DATA_DIR, f"export_{user_id}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email_id", "from", "to", "subject", "date", "ips", "timestamp"])
        for r in results:
            ips = ",".join([i.get("ip") for i in r.get("ip_trace", [])])
            writer.writerow([
                r.get("email_id"),
                r.get("from"),
                r.get("to"),
                r.get("subject"),
                r.get("date"),
                ips,
                r.get("timestamp"),
            ])
    return send_file(csv_path, as_attachment=True, download_name="analysis_export.csv")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)