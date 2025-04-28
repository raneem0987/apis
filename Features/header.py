from flask import Flask, request, jsonify
from flask_cors import CORS
from email import message_from_bytes

app = Flask(__name__)
CORS(app)  # عشان نسمح بالـ fetch من المتصفح

@app.route('/extract-emailheader', methods=['POST'])
def extract_emailheader():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        # قراءة الملف اللي بترفعه
        email_message = message_from_bytes(file.read())

        # استخراج المعلومات المطلوبة
        data = {
            "from": email_message.get('From', ''),
            "to": email_message.get('To', ''),
            "subject": email_message.get('Subject', ''),
            "date": email_message.get('Date', ''),
            "message_id": email_message.get('Message-ID', ''),
            "reply_to": email_message.get('Reply-To', ''),
        }

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(port=5000, debug=True)
