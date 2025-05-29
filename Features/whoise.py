from flask import Flask, request, jsonify
from flask_cors import CORS
import whois

app = Flask(__name__)
CORS(app)

def perform_whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)

        return {
            "domain_name": domain_info.domain_name,
            "registrar": domain_info.registrar,
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "updated_date": str(domain_info.updated_date),
            "name_servers": domain_info.name_servers,
            "status": domain_info.status,
            "organization": domain_info.org
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/whois', methods=['POST'])
def whois_api():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing "domain" in request'}), 400

    domain = data['domain']
    result = perform_whois_lookup(domain)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=False, port=5000, use_reloader=False)