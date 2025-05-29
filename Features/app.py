from flask import Flask, request, jsonify
from flask_cors import CORS
import whoise
import urlcheck
import stegnography
import sstegno
import ssltls
import spfdmarc
import header
import checkattach
import blacklist

app = Flask(__name__)
CORS(app)

@app.route("/all")
def home():
    return "Multi-API backend is running!"

# ===== WHOIS =====
@app.route("/whois", methods=["POST"])
def run_whois():
    domain = request.json.get("domain")
    result = whoise.lookup(domain)
    return jsonify(result)

# ===== URL CHECK =====
@app.route("/urlcheck", methods=["POST"])
def run_urlcheck():
    url = request.json.get("url")
    result = urlcheck.analyze_url(url)
    return jsonify(result)

# ===== STEGNOGRAPHY (photo) =====
@app.route("/stegnography", methods=["POST"])
def run_stegnography():
    photo = request.json.get("photo")  # base64
    result = stegnography.analyze_image(photo)
    return jsonify(result)

# ===== STEGNOGRAPHY (video) =====
@app.route("/sstegno", methods=["POST"])
def run_sstegno():
    video = request.files["video"]
    result = sstegno.analyze_video(video)
    return jsonify(result)

# ===== SSL/TLS =====
@app.route("/ssl", methods=["POST"])
def run_ssl():
    url = request.json.get("url")
    result = ssltls.check_ssl(url)
    return jsonify(result)

# ===== SPF & DMARC =====
@app.route("/checkspfdmark", methods=["POST"])
def run_spf():
    domain = request.json.get("domain")
    result = spfdmarc.check_spf(domain)
    return jsonify(result)

# ===== EMAIL HEADER =====
@app.route("/extract-emailheader", methods=["POST"])
def run_header():
    raw_bytes = request.files["file"].read()
    result = header.parse_headers(raw_bytes)
    return jsonify(result)

# ===== ATTACHMENT CHECK =====
@app.route("/check_attachment", methods=["POST"])
def run_attach_check():
    file = request.files["file"]
    result = checkattach.check_file(file)
    return jsonify(result)

# ===== BLACKLIST CHECK =====
@app.route("/blacklist", methods=["POST"])
def run_blacklist():
    ip = request.json.get("ip")
    result = blacklist.check_ip(ip)
    return jsonify(result)

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
