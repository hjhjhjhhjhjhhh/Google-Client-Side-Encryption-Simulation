# cloud_server.py
# Requires: pip install flask
import os
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

UPLOAD_DIR = "cloud"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    user = request.form.get("user", "").strip().lower()
    if not user:
        return jsonify({"error": "Missing user"}), 400

    if 'enc_file' not in request.files or 'enc_key' not in request.files:
        return jsonify({"error": "Missing file or key"}), 400

    enc_file = request.files['enc_file']
    enc_key = request.files['enc_key']

    user_dir = os.path.join(UPLOAD_DIR, user)
    os.makedirs(user_dir, exist_ok=True)

    filename = secure_filename(enc_file.filename)
    keyname = secure_filename(enc_key.filename)

    enc_file.save(os.path.join(user_dir, filename))
    enc_key.save(os.path.join(user_dir, keyname))

    return jsonify({"status": "File and key uploaded successfully"})

@app.route('/list/<user>', methods=['GET'])
def list_files(user):
    user = user.strip().lower()
    user_dir = os.path.join(UPLOAD_DIR, user)
    if not os.path.exists(user_dir):
        return jsonify([])
    files = os.listdir(user_dir)
    return jsonify(files)

@app.route('/download/<user>/<filename>', methods=['GET'])
def download_file(user, filename):
    user = user.strip().lower()
    filepath = os.path.join(UPLOAD_DIR, user, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    return send_from_directory(os.path.join(UPLOAD_DIR, user), filename, as_attachment=True)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
