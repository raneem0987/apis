from flask import Flask, request, jsonify
import dns.resolver

app = Flask(__name__)


def spf_analysis(domain):
    try:
        result = dns.resolver.resolve(domain, 'TXT')
        spf_records = []
        for rdata in result:
            record = str(rdata).strip('"')
            if record.startswith('v=spf1'):
                spf_records.append(record)

        if spf_records:
            status = "fail"
            mail_from = domain  # Simulating a scenario with phishing.com as the sending domain
            authorized = "No"
            comment = "SPF validation failed. Email claimed to be sent from phishing.com. Mail server authorization: No."
        else:
            status = "pass"
            mail_from = domain
            authorized = "Yes"
            comment = "SPF validation passed."

        return {
            "status": status,
            "mail_from": mail_from,
            "authorized": authorized,
            "comment": comment
        }
    except dns.resolver.NoAnswer:
        return {"status": "error", "comment": "No SPF record found."}
    except dns.resolver.NXDOMAIN:
        return {"status": "error", "comment": f"Domain {domain} not found."}
    except Exception as e:
        return {"status": "error", "comment": str(e)}


def dkim_analysis(domain):
    try:
        selectors = ['default', 'selector1', 'selector2']
        dkim_records = {}
        for selector in selectors:
            try:
                result = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in result:
                    record = str(rdata).strip('"')
                    if "v=DKIM1" in record:
                        dkim_records[selector] = record
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dkim_records[selector] = "No DKIM record found."

        if dkim_records:
            status = "fail"
            signing_domain = domain  # Simulating a case where malicious.com is the signing domain
            header_integrity = "Possibly Altered"
            comment = "DKIM validation failed. Email signed by malicious.com. Header integrity: Possibly Altered."
        else:
            status = "pass"
            signing_domain = domain
            header_integrity = "Intact"
            comment = "DKIM validation passed."

        return {
            "status": status,
            "signing_domain": signing_domain,
            "header_integrity": header_integrity,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}


def dmarc_analysis(domain):
    try:
        result = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_records = []
        for rdata in result:
            record = str(rdata).strip('"')
            if record.startswith('v=DMARC1'):
                dmarc_records.append(record)

        if dmarc_records:
            status = "fail"
            policy = "reject"  # Example: reject policy found
            alignment = "Failed"  # Simulating alignment failure
            comment = f"DMARC validation failed. Policy applied: {policy}. Domain alignment: {alignment}."
        else:
            status = "pass"
            policy = "none"
            alignment = "Passed"
            comment = "DMARC validation passed."

        return {
            "status": status,
            "policy": policy,
            "alignment": alignment,
            "comment": comment
        }
    except Exception as e:
        return {"status": "error", "comment": str(e)}


@app.route('/checkspfdmark', methods=['POST'])
def analyze_domain():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    results = {
        "domain": domain,
        "spf": spf_analysis(domain),
        "dkim": dkim_analysis(domain),
        "dmarc": dmarc_analysis(domain)
    }

    return jsonify(results)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5010, debug=False, use_reloader=False)
