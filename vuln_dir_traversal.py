"""
漏洞版本2：目录遍历漏洞
移除路径验证和文件名清理，可以尝试访问系统文件
端口：5002
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
jwt_secret_file = Path('keys/jwt_secret_dir_traversal.key')
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
    key_file = Path('keys/encryption_key_dir_traversal.key')
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

def encrypt_file(file_data):
    key = get_encryption_key()
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def decrypt_file(encrypted_data):
    try:
        key = get_encryption_key()
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, AES.block_size)
    except ValueError as e:
        if "Padding" in str(e):
            # 这通常意味着密钥不匹配
            raise ValueError("Decryption failed - possibly due to key mismatch. The file was likely encrypted with a different key.")
        else:
            raise
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise

# ========== 这里是漏洞：总是返回True，不验证路径 ==========
def is_safe_path(basedir, path):
    """漏洞版本：总是允许任何路径"""
    return True  # 危险！允许任何路径访问

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
    return jsonify({'message': '漏洞版本：目录遍历漏洞，端口5002'})

# 为目录遍历攻击提供一个不需要认证的登录端点
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
            try:
                # 尝试解密文件以验证密钥是否有效
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # 只获取基本信息，不解密整个文件
                file_info = {
                    'name': file_path.stem,  # 文件名（不含.enc扩展名）
                    'size': file_path.stat().st_size,
                    'modified': file_path.stat().st_mtime
                }
                files.append(file_info)
            except Exception as e:
                # 如果某个文件访问失败，跳过它但记录错误
                print(f"Warning: Could not access file {file_path}: {str(e)}")
                continue
    
    return jsonify({
        'success': True,
        'files': files
    })

# ========== 漏洞修复：移除上传端点的认证要求 ==========
@app.route('/api/upload', methods=['POST'])
def api_upload_file():  # 移除了token_required装饰器和current_user参数
    if 'file' not in request.files:
        return jsonify({'message': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    # ========== 这里是漏洞：不使用secure_filename ==========
    # filename = secure_filename(file.filename)  # 注释掉这行
    filename = file.filename  # 使用原始文件名，可能包含../等危险字符
    
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    file_data = file.read()
    # 不进行加密，直接保存原始文件内容以增加漏洞效果
    # encrypted_data = encrypt_file(file_data)
    
    # 不添加.enc扩展名，直接使用原始文件名
    # encrypted_filename = filename + '.enc'
    file_path = Path(filename)  # 直接使用原始文件名创建路径
    
    # 不进行路径检查，直接尝试保存文件
    # 漏洞：即使路径检查失败也应该允许上传，以展示漏洞
    # is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename)  # 仅调用但忽略结果
    
    try:
        # 确保目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        return jsonify({
            'message': f'File {filename} uploaded!',
            'success': True
        })
    except Exception as e:
        return jsonify({
            'message': f'Upload failed: {str(e)}',
            'success': False
        }), 500

# ========== 漏洞修复：移除下载端点的认证要求 ==========
@app.route('/api/download/<path:filename>', methods=['GET'])
def api_download_file(filename):  # 移除了token_required装饰器和current_user参数
    # 漏洞：完全信任用户输入的路径，支持任意层级遍历
    print(f"收到下载请求，文件名: {filename}")
    
    # 构建完整的文件路径
    file_path = Path(filename).resolve()
    print(f"解析后的文件路径: {file_path}")
    print(f"当前工作目录: {Path.cwd()}")
    
    try:
        print(f"检查文件是否存在: {file_path.exists()}")
        if not file_path.exists():
            print(f"文件不存在: {file_path}")
            # 尝试一些常见的系统文件路径
            common_paths = [
                Path("C:/windows/win.ini"),
                Path("/etc/passwd"),
                Path("D:/etc/passwd"),  # 我们创建的测试文件
                Path("../../../../windows/win.ini").resolve(),
                Path("../../../etc/passwd").resolve()
            ]
            
            for path in common_paths:
                print(f"尝试备用路径: {path} (存在: {path.exists()})")
                if path.exists():
                    file_path = path
                    break
            else:
                return jsonify({'message': f'File not found: {filename}'}), 404

        # 直接尝试打开文件，不进行任何安全检查
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        print(f"成功读取文件，大小: {len(file_data)} 字节")

        from io import BytesIO
        file_obj = BytesIO(file_data)
        file_obj.seek(0)

        # 直接返回原始文件内容
        response = send_file(
            file_obj,
            as_attachment=True,
            download_name=file_path.name,
            mimetype='application/octet-stream'
        )
        print("文件发送成功")
        return response
    except FileNotFoundError as e:
        print(f"文件未找到错误: {str(e)}")
        return jsonify({'message': f'File not found: {str(e)}'}), 404
    except PermissionError as e:
        print(f"权限错误: {str(e)}")
        return jsonify({'message': f'Permission denied: {str(e)}'}), 403
    except Exception as e:
        print(f"其他错误: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Error reading file: {str(e)}'}), 500

if __name__ == '__main__':
    # 从环境变量获取主机和端口配置，如果没有则使用默认值
    import os
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5002))
    
    app.run(debug=True, host=host, port=port)