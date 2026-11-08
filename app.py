import os
import uuid
from pathlib import Path
from flask import Flask, request, render_template, send_from_directory

app = Flask(__name__)

MAX_SECURE_SIZE = 2 * 1024 * 1024
# app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

UPLOAD_VULN = 'storage/uploads_vulnerable'
QUARANTINE = 'storage/quarantine'
SAFE_AREA = 'storage/safe_area'

for folder in [UPLOAD_VULN, QUARANTINE, SAFE_AREA]:
    os.makedirs(folder, exist_ok=True)

file_owners = {}

def check_magic_bytes(stream):
    header = stream.read(64)
    stream.seek(0)
    
    if header.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
        return 'png'
    elif header.startswith(b'\xFF\xD8\xFF'):
        return 'jpg'
    elif header.startswith(b'%PDF'):
        return 'pdf'
    
    try:
        header.decode('utf-8')
        if b'<?php' in header or b'<script>' in header:
            return None
        return 'txt'
    except UnicodeDecodeError:
        pass
        
    return None

@app.route('/')
def index():
    return render_template('index.html', files=file_owners)

# Insecure version
@app.route('/upload-vulnerable', methods=['POST'])
def upload_vulnerable():
    if 'file' not in request.files:
        return "File doesn't exist", 400
    file = request.files['file']

    if file.filename == '':
        return "Please choose file", 400
    
    filename = file.filename
    filepath = os.path.join(UPLOAD_VULN, filename)
    
    with open(filepath, 'wb') as f:
        while True:
            chunk = file.stream.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    
    return f"Saved vulnerable file as: {filepath}"

# Secure version
@app.route('/upload-secure', methods=['POST'])
def upload_secure():
    if 'file' not in request.files:
        return "File doesn't exist", 400
    file = request.files['file']
    
    if file.filename == '':
        return "Please choose file", 400
    
    content_length = request.content_length
    if content_length and content_length > MAX_SECURE_SIZE:
        return f"Size is too large (max {MAX_SECURE_SIZE}, got {content_length})", 400
    
    current_user = request.form.get('user_id', 'user_A')

    # Magic bytes check
    file_type = check_magic_bytes(file.stream)
    if not file_type:
        return "Byte mismatch found", 400
        
    safe_filename = f"{uuid.uuid4()}.{file_type}"
    
    # Quarantine
    quarantine_path = Path(QUARANTINE) / safe_filename
    file.save(quarantine_path)
    
    # Jail check
    safe_dir = Path(SAFE_AREA).resolve()
    final_path = (safe_dir / safe_filename).resolve()
    
    if not str(final_path).startswith(str(safe_dir)):
        if quarantine_path.exists():
            quarantine_path.unlink()
        return "Path traversal found", 403
        
    quarantine_path.rename(final_path)
    
    file_owners[safe_filename] = current_user
    
    return f"File has been validated and stored as: {safe_filename} (owner: {current_user})"

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    current_user = request.args.get('user_id', 'user_A')

    if filename not in file_owners:
        return "File doesn't exist", 404

    if file_owners[filename] != current_user:
        return "User is not authorized", 403

    return send_from_directory(SAFE_AREA, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)