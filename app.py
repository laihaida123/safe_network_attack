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

# 导入所需的Python标准库和第三方库
import os                           # 用于操作系统相关功能，如创建目录
import secrets                      # 用于生成加密安全的随机数
from pathlib import Path           # 用于面向对象的文件系统路径操作
from flask import Flask, request, jsonify, send_file  # Flask web框架核心模块
from flask_cors import CORS        # 处理跨域资源共享(CORS)的Flask扩展
from flask_login import LoginManager, UserMixin, current_user  # Flask用户会话管理扩展
from werkzeug.security import generate_password_hash, check_password_hash  # Werkzeug安全工具函数
from werkzeug.utils import secure_filename  # 用于清理文件名，防止目录遍历攻击
from Crypto.Cipher import AES      # pycryptodome库中的AES加密模块
from Crypto.Util.Padding import pad, unpad  # AES加密需要的填充功能
from Crypto.Random import get_random_bytes  # 生成加密安全的随机字节
import jwt                         # JSON Web Token处理库
import datetime                    # 日期时间处理模块

# 初始化Flask应用程序
# Flask是一个轻量级的Python web框架，用于快速构建web应用
app = Flask(__name__)
# 使用持久化的密钥文件而不是每次生成新密钥
# 这样可以确保应用重启后JWT token仍然有效

# 检查是否存在JWT密钥文件，如果不存在则创建
jwt_secret_file = Path('keys/jwt_secret.key')
if jwt_secret_file.exists():
    with open(jwt_secret_file, 'r') as f:
        app.config['JWT_SECRET_KEY'] = f.read()
else:
    # 生成新的JWT密钥并保存到文件
    jwt_secret = secrets.token_hex(32)
    with open(jwt_secret_file, 'w') as f:
        f.write(jwt_secret)
    app.config['JWT_SECRET_KEY'] = jwt_secret

# 检查是否存在应用密钥文件，如果不存在则创建
secret_key_file = Path('keys/secret.key')
if secret_key_file.exists():
    with open(secret_key_file, 'r') as f:
        app.config['SECRET_KEY'] = f.read()
else:
    # 生成新的应用密钥并保存到文件
    secret_key = secrets.token_hex(32)
    with open(secret_key_file, 'w') as f:
        f.write(secret_key)
    app.config['SECRET_KEY'] = secret_key

# 设置文件上传的存储目录
app.config['UPLOAD_FOLDER'] = 'protected_files'
# 设置最大文件上传大小为16MB，防止大文件上传导致服务器资源耗尽
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# 启用CORS（跨域资源共享），允许来自任何源(*)对/api/*路径的访问
# 这在开发阶段非常有用，但在生产环境中应该更严格地限制来源
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 初始化Flask-Login扩展，用于管理用户登录状态
# Flask-Login提供了用户会话管理功能，可以轻松处理用户登录、登出等操作
login_manager = LoginManager()
login_manager.init_app(app)
# 设置登录视图的端点名称，当未登录用户尝试访问受保护页面时重定向到这里
login_manager.login_view = 'login'
# 设置未登录用户访问受保护页面时显示的消息
login_manager.login_message = 'Please log in to access this page.'

# 创建应用所需的目录
# exist_ok=True参数表示如果目录已存在不会抛出异常
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # 存储加密文件的目录
os.makedirs('keys', exist_ok=True)                       # 存储加密密钥的目录

# 简单的用户存储字典（在生产环境中应使用数据库）
# 这里为了演示方便，将用户信息存储在内存字典中
# 实际项目中应该使用数据库存储用户信息
users = {
    # admin用户，密码经过hash处理存储，ID为1
    'admin': {
        'password': generate_password_hash('admin123'),  # 使用Werkzeug生成密码hash值
        'id': 1
    },
    # user1用户，密码经过hash处理存储，ID为2
    'user1': {
        'password': generate_password_hash('password123'),  # 使用Werkzeug生成密码hash值
        'id': 2
    }
}

# 定义User类，继承自UserMixin
# UserMixin提供了默认的用户身份验证和会话管理方法实现
class User(UserMixin):
    # 构造函数，初始化用户对象
    def __init__(self, username, user_id):
        self.id = user_id          # 用户ID
        self.username = username   # 用户名

# 用户加载回调函数，Flask-Login使用它根据用户ID加载用户对象
# 当用户已经登录时，每次请求都会调用此函数来获取用户对象
@login_manager.user_loader
def load_user(user_id):
    # 遍历用户字典查找匹配的用户ID
    for username, user_data in users.items():
        if user_data['id'] == int(user_id):  # 比较ID是否匹配
            # 如果找到匹配的用户，返回User对象
            return User(username, user_data['id'])
    # 如果没找到匹配的用户，返回None
    return None

# 获取或生成加密密钥的函数
def get_encryption_key():
    """获取加密密钥 - 没有密钥无法解密"""
    """Get or generate encryption key for file encryption"""
    # 定义密钥文件路径
    key_file = Path('keys/encryption_key_secure.app.key')
    # 检查密钥文件是否存在
    if key_file.exists():
        try:
            # 如果密钥文件存在，则读取并返回密钥
            with open(key_file, 'rb') as f:
                key = f.read()
                # 验证密钥长度是否正确（32字节用于AES-256）
                if len(key) == 32:
                    print(f"Loaded existing encryption key from {key_file}")
                    return key
                else:
                    # 如果密钥长度不正确，生成新的密钥
                    print(f"Warning: Encryption key file corrupted or incomplete (length: {len(key)}), generating new key")
        except Exception as e:
            print(f"Warning: Failed to read encryption key file: {e}, generating new key")
    
    # 如果密钥文件不存在或密钥无效，则生成新的AES-256密钥（32字节）
    print("Generating new encryption key...")
    key = get_random_bytes(32)  # AES-256 requires 32 bytes
    # 确保keys目录存在
    os.makedirs('keys', exist_ok=True)
    # 将新生成的密钥写入文件保存
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"New encryption key saved to {key_file}")
    # 返回新生成的密钥
    return key

# 文件加密函数，使用AES-256 CBC模式加密文件数据
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
    # 获取加密密钥
    key = get_encryption_key()
    # 创建AES加密器对象，使用CBC模式（自动产生随机IV）
    cipher = AES.new(key, AES.MODE_CBC)# 自动生成随机IV
    # 获取初始化向量(IV)，长度为16字节
    iv = cipher.iv  # 16-byte Initialization Vector# 获取16字节随机IV（每次不同）
    # 对数据进行PKCS7填充，使其长度成为AES块大小(16字节)的整数倍
    padded_data = pad(file_data, AES.block_size)
    # 加密填充后的数据
    encrypted_data = cipher.encrypt(padded_data)
    # 即使同一文件，IV不同 → 密文完全不同
    # 返回IV和加密数据的组合，格式为：[IV][加密数据]
    # IV需要存储在加密数据前面，因为解密时需要用到相同的IV
    return iv + encrypted_data  # Format: [IV][Encrypted Data]# IV前置存储

# 文件解密函数，使用AES-256 CBC模式解密文件数据
def decrypt_file(encrypted_data):
    """
    Decrypt file data using AES-256 in CBC mode.
    
    Args:
        encrypted_data: Encrypted data with IV prefix
        
    Returns:
        Decrypted file data
        
    Raises:
        ValueError: If decryption fails due to incorrect padding or key
        Exception: Other decryption errors
    """
    try:
        # 1. 获取加密密钥
        key = get_encryption_key()
        
        # 2. 检查数据长度是否足够（至少包含16字节IV和16字节数据）
        if len(encrypted_data) < 32:  # 16 bytes IV + 16 bytes minimum data
            raise ValueError("加密数据太短")
        
        # 3. 提取IV（前16字节）和密文（剩余字节）
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # 4. 验证密文长度是否为16字节的倍数（AES块大小）
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度无效")
        
        # 5. 使用相同密钥和IV创建AES密码
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        
        # 6. 解密密文
        decrypted_data = cipher.decrypt(ciphertext)
        
        # 7. 移除PKCS7填充以获取原始数据
        return unpad(decrypted_data, AES.block_size)
    except ValueError as ve:
        # 特别处理与密钥或数据相关的ValueError
        if "Padding" in str(ve) or "padding" in str(ve):
            raise ValueError("解密失败：密钥可能不正确或数据已损坏") from ve
        else:
            raise ve
    except Exception as e:
        # 重新抛出其他异常，但添加更多上下文信息
        raise Exception(f"解密过程中发生错误: {str(e)}") from e

# 路径安全验证函数，防止目录遍历攻击
def is_safe_path(basedir, path):
    """Validate file path to prevent directory traversal attacks"""
    # 4. ✅ 目录遍历攻击
    # 防护机制：路径安全验证 + 文件名清理
    """防止目录遍历攻击"""
    try:
        # 解析基础目录和目标路径，确保获得绝对路径
        resolved_path = Path(basedir).resolve() / path
        # 确保解析后的路径在基目录内，防止目录遍历攻击
        # Ensure the resolved path is within the base directory
        return Path(basedir).resolve() in resolved_path.parents \
            or Path(basedir).resolve() == resolved_path.parent
    except (OSError, ValueError):
        # 如果解析过程中出现异常，认为路径不安全
        return False

# 根路径路由，返回API的基本信息
@app.route('/')
def index():
    # 使用jsonify函数返回JSON格式的响应
    return jsonify({'message': 'Secure File Portal API', 'version': '1.0'})

# JWT token验证装饰器，用于保护需要认证的API端点
def token_required(f):
    """Decorator to require JWT token for API endpoints"""
    # 定义包装函数
    def decorated(*args, **kwargs):
        # 从HTTP请求头中获取Authorization字段
        token = request.headers.get('Authorization')
        
        # 检查是否提供了token
        if not token:
            # 如果没有提供token，返回401未授权错误
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # 移除'Bearer '前缀（如果存在）
            if token.startswith('Bearer '):
                token = token[7:]
                
            # 使用JWT库解码和验证token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            # 根据token中的数据创建当前用户对象
            current_user = User(data['username'], data['id'])
        except jwt.ExpiredSignatureError:
            # 如果token过期，返回401错误
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            # 如果token无效，返回401错误
            return jsonify({'message': 'Token is invalid'}), 401
            
        # 如果token有效，调用被装饰的函数，并传入current_user等参数
        return f(current_user, *args, **kwargs)
    
    # 保持被装饰函数的名称不变（重要！）
    decorated.__name__ = f.__name__
    # 返回包装函数
    return decorated

# 登录API端点，处理用户登录请求
@app.route('/api/login', methods=['POST'])
def api_login():
    # 获取请求中的JSON数据
    data = request.get_json()
    
    # 验证请求数据是否完整
    if not data or not data.get('username') or not data.get('password'):
        # 如果缺少用户名或密码，返回400错误
        return jsonify({'message': 'Username and password required'}), 400
    
    # 从请求数据中提取用户名和密码
    username = data['username']
    password = data['password']
    
    # 验证用户名和密码
    if username in users and check_password_hash(users[username]['password'], password):
        # 如果用户名存在且密码正确，生成JWT token
        token = jwt.encode({
            'username': username,                 # 用户名
            'id': users[username]['id'],          # 用户ID
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # token 24小时后过期
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        # 返回成功响应和token
        return jsonify({
            'success': True,
            'token': token,
            'message': 'Login successful'
        })
    else:
        # 如果用户名或密码错误，返回401未授权错误
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401

# 登出API端点，处理用户登出请求
@app.route('/api/logout', methods=['POST'])
@token_required  # 使用token_required装饰器保护此端点
def api_logout(current_user):
    # 对于JWT，登出操作在客户端通过删除token来完成
    # 服务器端不需要特殊处理
    return jsonify({'message': 'Logged out successfully'})

# 列出文件API端点，返回已上传文件列表
@app.route('/api/files', methods=['GET'])
@token_required  # 使用token_required装饰器保护此端点
def api_list_files(current_user):
    try:
        # 创建空列表存储文件信息
        files = []
        # 获取文件存储目录的Path对象
        files_dir = Path(app.config['UPLOAD_FOLDER'])
        # 检查目录是否存在
        if files_dir.exists():
            # 遍历目录中所有.enc扩展名的文件（加密文件）
            for file_path in files_dir.glob('*.enc'):
                try:
                    # 尝试获取文件信息
                    stat = file_path.stat()
                    # 将文件信息添加到列表中
                    files.append({
                        'name': file_path.stem,  # 不带.enc扩展名的文件名
                        'size': stat.st_size,    # 文件大小（字节）
                        'encrypted_name': file_path.name   # 加密后的文件名
                    })
                except OSError as e:
                    # 如果无法获取文件信息，记录日志并跳过该文件
                    print(f"Warning: Could not access file {file_path}: {e}")
                    continue
        
        # 返回JSON格式的文件列表
        return jsonify({'files': files})
    except Exception as e:
        # 记录详细的错误信息
        print(f"Error in api_list_files: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        # 返回错误信息
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500

# 文件上传API端点，处理文件上传和加密
@app.route('/api/upload', methods=['POST'])
@token_required  # 使用token_required装饰器保护此端点
def api_upload_file(current_user):
    # 检查请求中是否包含文件
    if 'file' not in request.files:
        # 如果没有文件，返回400错误
        return jsonify({'message': 'No file selected'}), 400
    
    # 获取上传的文件对象
    file = request.files['file']
    # 检查文件名是否为空
    if file.filename == '':
        # 如果文件名为空，返回400错误
        return jsonify({'message': 'No file selected'}), 400
    
    # 清理文件名，防止目录遍历攻击
    filename = secure_filename(file.filename)
    # 检查清理后的文件名是否有效
    if not filename:
        # 如果文件名无效，返回400错误
        return jsonify({'message': 'Invalid filename'}), 400
    
    # 读取文件数据
    file_data = file.read()
    
    # 加密文件数据
    encrypted_data = encrypt_file(file_data)
    
    # 构造加密文件的文件名（原文件名+.enc扩展名）
    encrypted_filename = filename + '.enc'
    # 构造文件存储路径
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # 验证文件路径安全性，防止目录遍历攻击
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        # 如果路径不安全，返回400错误
        return jsonify({'message': 'Invalid file path'}), 400
    
    # 将加密后的数据写入文件
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    # 返回成功响应
    return jsonify({
        'message': f'File {filename} uploaded and encrypted successfully!',
        'success': True
    })

# 文件下载API端点，处理文件下载和解密
@app.route('/api/download/<filename>', methods=['GET'])
@token_required
def api_download_file(current_user, filename):
    # 清理文件名，防止目录遍历攻击
    safe_filename = secure_filename(filename)
    # 检查清理后的文件名是否有效
    if not safe_filename or safe_filename != filename:
        # 如果文件名无效，返回400错误
        return jsonify({'message': 'Invalid filename'}), 400
    
    # 构造加密文件的文件名
    encrypted_filename = safe_filename + '.enc'
    # 构造文件路径
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # 验证文件路径安全性，防止目录遍历攻击
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        # 如果路径不安全，返回400错误
        return jsonify({'message': 'Invalid file path'}), 400
    
    # 检查文件是否存在
    if not file_path.exists():
        # 如果文件不存在，返回404错误
        return jsonify({'message': 'File not found'}), 404
    
    try:
        # 读取加密文件
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密文件数据
        decrypted_data = decrypt_file(encrypted_data)
        
        # 创建BytesIO对象作为临时文件对象
        from io import BytesIO
        file_obj = BytesIO(decrypted_data)
        file_obj.seek(0)  # 将文件指针移到开始位置
        
        # 发送文件给客户端下载
        return send_file(
            file_obj,
            as_attachment=True,           # 作为附件下载
            download_name=safe_filename,  # 下载时使用的文件名
            mimetype='application/octet-stream'  # 通用二进制流MIME类型
        )
    except ValueError as ve:
        # 处理解密相关的ValueError（如密钥错误）
        return jsonify({'message': f'解密失败: {str(ve)}'}), 400
    except FileNotFoundError:
        # 处理文件未找到的情况
        return jsonify({'message': '文件未找到'}), 404
    except PermissionError:
        # 处理权限不足的情况
        return jsonify({'message': '权限不足，无法访问文件'}), 403
    except Exception as e:
        # 如果解密过程中发生其他错误，返回500服务器内部错误
        return jsonify({'message': f'服务器内部错误: {str(e)}'}), 500

# 应用程序入口点
if __name__ == '__main__':
    # 解析命令行参数，允许自定义主机和端口
    import argparse
    parser = argparse.ArgumentParser()
    # 添加--host参数，默认为127.0.0.1（本地回环地址）
    parser.add_argument('--host', default='127.0.0.1', help='Host to run the server on')
    # 添加--port参数，默认为5000
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    # 解析命令行参数
    args = parser.parse_args()
    
    # 警告：生产环境中debug应设为False
    # 生产部署应使用专业的WSGI服务器（如Gunicorn、uWSGI）
    app.run(debug=True, host=args.host, port=args.port)