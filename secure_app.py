"""
Flask Secure File Portal
=========================
A secure web application that provides user authentication and AES-256 encrypted file storage.
Files are automatically encrypted on upload and decrypted on download.

Security Features:
- AES-256 encryption (CBC mode) for file storage
- Password hashing with Werkzeug (bcrypt)
- Path validation to prevent directory traversal
- Filename sanitization
- Session-based authentication
"""
"""
Flask Secure File Portal
=========================
一个安全的Web应用，提供用户认证和AES-256加密文件存储。
文件在上传时自动加密，下载时自动解密。

安全特性：
- AES-256加密（CBC模式）存储文件
- Werkzeug（bcrypt）密码哈希
- 路径验证防止目录遍历
- 文件名清理
- 基于会话的认证
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

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'protected_files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)  # For JWT tokens

# Enable CORS for API endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)

# Simple user storage (in production, use a database)
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
    """获取加密密钥 - 没有密钥无法解密"""
    """Get or generate encryption key for file encryption"""
    key_file = Path('keys/encryption_key.key')
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()  # 返回32字节AES-256密钥
    else:
        key = get_random_bytes(32)  # AES-256 requires 32 bytes
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

def encrypt_file(file_data):
    """
    Encrypt file data using AES-256 in CBC mode.
    
    Process:
    1. Get encryption key (32 bytes for AES-256)
    2. Create AES cipher in CBC mode (generates random IV)
    3. Pad data to AES block size (16 bytes)
    4. Encrypt padded data
    5. Return IV + encrypted data (IV needed for decryption)
    """
    # ✅ 模式分析（唯一的IVs）
    """加密文件 - 每次使用随机IV"""
    key = get_encryption_key()
    cipher = AES.new(key, AES.MODE_CBC)# 自动生成随机IV
    iv = cipher.iv  # 16-byte Initialization Vector# 获取16字节随机IV（每次不同）
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    # 即使同一文件，IV不同 → 密文完全不同
    return iv + encrypted_data  # Format: [IV][Encrypted Data]# IV前置存储

def decrypt_file(encrypted_data):
    """
    Decrypt file data using AES-256 in CBC mode.
    
    Process:
    1. Get encryption key
    2. Extract IV (first 16 bytes) and ciphertext (remaining bytes)
    3. Create AES cipher with same key and IV
    4. Decrypt ciphertext
    5. Remove padding to get original data
    """
    """解密文件 - 任何篡改都会导致解密失败"""
    # ✅ 文件篡改（加密确保完整性）
    key = get_encryption_key()
    iv = encrypted_data[:16]  # Extract IV# 提取IV
    ciphertext = encrypted_data[16:]  # Extract encrypted data# 提取密文
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)  # Remove PKCS7 padding# 移除填充
    # 如果密文被篡改：1. 解密出乱码 2. PKCS7填充验证失败抛出异常
def is_safe_path(basedir, path):
    """Validate file path to prevent directory traversal attacks"""
    # 4. ✅ 目录遍历攻击
    # 防护机制：路径安全验证 + 文件名清理
    """防止目录遍历攻击"""
    try:
        # Resolve the path to ensure it's absolute
        resolved_path = Path(basedir).resolve() / path
        # 确保解析后的路径在基目录内
        # Ensure the resolved path is within the base directory
        return Path(basedir).resolve() in resolved_path.parents or Path(basedir).resolve() == resolved_path.parent
    except (OSError, ValueError):
        return False

@app.route('/')
def index():
    return jsonify({'message': 'Secure File Portal API', 'version': '1.0'})

def token_required(f):
    """Decorator to require JWT token for API endpoints"""
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
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

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    if username in users and check_password_hash(users[username]['password'], password):
        # Generate JWT token
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

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(current_user):
    # For JWT, logout is handled on the client side by deleting the token
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/files', methods=['GET'])
@token_required
def api_list_files(current_user):
    # List available files
    files = []
    files_dir = Path(app.config['UPLOAD_FOLDER'])
    if files_dir.exists():
        for file_path in files_dir.glob('*.enc'):
            files.append({
                'name': file_path.stem,  # filename without .enc extension
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
    
    # Secure filename
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    # Read file data
    file_data = file.read()
    
    # Encrypt the file
    encrypted_data = encrypt_file(file_data)
    
    # Save encrypted file
    encrypted_filename = filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # Validate path to prevent directory traversal
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return jsonify({
        'message': f'File {filename} uploaded and encrypted successfully!',
        'success': True
    })

@app.route('/api/download/<filename>', methods=['GET'])
@token_required
def api_download_file(current_user, filename):
    # Secure filename to prevent directory traversal
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    encrypted_filename = safe_filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # Validate path to prevent directory traversal
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    if not file_path.exists():
        return jsonify({'message': 'File not found'}), 404
    
    try:
        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data)
        
        # Create a temporary file-like object
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
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1', help='Host to run the server on')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    
    # WARNING: debug=True should be False in production
    # Use a production WSGI server (Gunicorn, uWSGI) for production deployment
    app.run(debug=True, host=args.host, port=args.port)

