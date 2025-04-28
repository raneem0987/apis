from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse
import base64

app = Flask(__name__)


def extract_url_info(url):
    parsed_url = urlparse(url)
    url_info = {
        "Domain": parsed_url.netloc,
        "Path": parsed_url.path,
        "Query": parsed_url.query,
        "Scheme": parsed_url.scheme.upper(),
        "Port": parsed_url.port if parsed_url.port else ("80" if parsed_url.scheme == "http" else "443")
    }
    return url_info


def encode_url(url):
    url_bytes = url.encode("utf-8")
    base64_url = base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")
    return base64_url


def check_virustotal(api_key, url):
    base_url = "https://www.virustotal.com/api/v3/urls"
    encoded_url = encode_url(url)
    headers = {"x-apikey": api_key}
    response = requests.get(f"{base_url}/{encoded_url}", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"VirusTotal submission failed with status code {response.status_code}"}


API_KEY = "80622f5e7e38f3b81381aec0be8aa528bf6186411b8dfa92fe9d8084a89b3ddd"


@app.route('/check_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']

    url_info = extract_url_info(url)

    vt_result = check_virustotal(API_KEY, url)

    if "error" in vt_result:
        return jsonify({"error": vt_result["error"]}), 400

    # Prepare response
    response = {
        "url_info": url_info,
        "virustotal_result": vt_result
    }

    return jsonify(response), 200


if __name__ == '__main__':
    app.run(debug=False, port=5002, use_reloader=False)
