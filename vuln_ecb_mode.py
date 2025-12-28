"""
漏洞版本3：ECB模式加密漏洞
使用ECB模式（不安全），相同明文块产生相同密文块
端口：5003
"""

import os
import secrets
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'protected_files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 使用持久化的JWT密钥而不是每次都生成新的
jwt_secret_file = Path('keys/jwt_secret_ecb.key')
if jwt_secret_file.exists():
    with open(jwt_secret_file, 'r') as f:
        app.config['JWT_SECRET_KEY'] = f.read()
else:
    jwt_secret = secrets.token_hex(32)
    with open(jwt_secret_file, 'w') as f:
        f.write(jwt_secret)
    app.config['JWT_SECRET_KEY'] = jwt_secret

CORS(app, resources={r"/api/*": {"origins": "*"}})

login_manager = LoginManager()
login_manager.init_app(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)

users = {
    'admin': {
        'password': generate_password_hash('admin123'),
        'id': 1
    },
    'user1': {
        'password': generate_password_hash('password123'),
        'id': 2
    }
}

class User(UserMixin):
    def __init__(self, username, user_id):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    for username, user_data in users.items():
        if user_data['id'] == int(user_id):
            return User(username, user_data['id'])
    return None

def get_encryption_key():
    # 使用独立的密钥文件，避免与其他服务冲突
    key_file = Path('keys/encryption_key_ecb.key')
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# ========== 这里是漏洞：使用ECB模式（不安全） ==========
def encrypt_file(file_data):
    """漏洞版本：使用ECB模式，相同明文产生相同密文"""
    key = get_encryption_key()
    # 使用ECB模式（不安全！）
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    # ECB模式不需要IV
    return encrypted_data  # 注意：不包含IV

def decrypt_file(encrypted_data):
    """漏洞版本：ECB模式解密"""
    key = get_encryption_key()
    # 使用ECB模式解密
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size)

def is_safe_path(basedir, path):
    try:
        resolved_path = Path(basedir).resolve() / path
        return Path(basedir).resolve() in resolved_path.parents or Path(basedir).resolve() == resolved_path.parent
    except (OSError, ValueError):
        return False

def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
                
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User(data['username'], data['id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

@app.route('/')
def index():
    return jsonify({'message': '漏洞版本：ECB模式漏洞，端口5003'})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    if username in users and check_password_hash(users[username]['password'], password):
        token = jwt.encode({
            'username': username,
            'id': users[username]['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'success': True,
            'token': token,
            'message': 'Login successful'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401

@app.route('/api/files', methods=['GET'])
@token_required
def api_list_files(current_user):
    files = []
    files_dir = Path(app.config['UPLOAD_FOLDER'])
    if files_dir.exists():
        for file_path in files_dir.glob('*.enc'):
            files.append({
                'name': file_path.stem,
                'size': file_path.stat().st_size,
                'encrypted_name': file_path.name
            })
    
    return jsonify({'files': files})

@app.route('/api/upload', methods=['POST'])
@token_required
def api_upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'message': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    file_data = file.read()
    encrypted_data = encrypt_file(file_data)
    
    encrypted_filename = filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return jsonify({
        'message': f'File {filename} uploaded! (ECB模式)',
        'success': True
    })

@app.route('/api/download/<filename>', methods=['GET'])
@token_required
def api_download_file(current_user, filename):
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    encrypted_filename = safe_filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    if not file_path.exists():
        return jsonify({'message': 'File not found'}), 404
    
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data)
        
        from io import BytesIO
        file_obj = BytesIO(decrypted_data)
        file_obj.seek(0)
        
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=safe_filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'message': f'Error decrypting file: {str(e)}'}), 500

if __name__ == '__main__':
    # 从环境变量获取主机和端口配置，如果没有则使用默认值
    import os
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5003))
    
    app.run(debug=True, host=host, port=port)