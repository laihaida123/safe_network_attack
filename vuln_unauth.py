"""
漏洞版本1：未授权访问漏洞
移除所有JWT和登录验证，任何人都可以访问所有文件
端口：5001
"""

import os
import secrets
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import datetime
import logging

# 设置日志记录
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 初始化Flask应用程序
# 配置应用密钥和上传文件夹
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # 生成随机密钥，但未用于认证
app.config['UPLOAD_FOLDER'] = 'protected_files'   # 存储加密文件的目录
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制最大上传文件大小为16MB

# 启用CORS支持，允许所有来源访问/api/*端点
# 安全风险：过于宽松的CORS策略可能导致跨站请求伪造攻击
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 创建必要的目录
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('keys', exist_ok=True)

def get_encryption_key():
    """获取加密密钥 - 用于AES加密/解密操作
    如果密钥文件存在则读取，否则生成新的密钥并保存
    """
    # 使用独立的密钥文件，避免与其他服务冲突
    key_file = Path('keys/encryption_key_unauth.key')
    if key_file.exists():
        try:
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
    
    # 生成新的32字节AES密钥并保存到文件
    print("Generating new encryption key...")
    key = get_random_bytes(32)
    # 确保keys目录存在
    os.makedirs('keys', exist_ok=True)
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"New encryption key saved to {key_file}")
    return key

def encrypt_file(file_data):
    """使用AES-CBC模式加密文件数据
    参数:
        file_data: 要加密的原始文件数据（bytes）
    返回:
        包含IV和加密数据的组合字节串
    """
    key = get_encryption_key()
    # 使用AES-CBC模式加密，每次都会生成新的随机IV
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # 获取初始化向量
    # 对数据进行PKCS7填充以满足AES块大小要求
    padded_data = pad(file_data, AES.block_size)
    # 执行加密操作
    encrypted_data = cipher.encrypt(padded_data)
    # 将IV和加密数据组合返回（IV不需要保密）
    return iv + encrypted_data

def decrypt_file(encrypted_data):
    """使用AES-CBC模式解密文件数据
    参数:
        encrypted_data: 包含IV和加密数据的字节串
    返回:
        解密后的原始文件数据
    """
    try:
        key = get_encryption_key()
        # 检查数据长度是否足够（至少包含16字节IV和16字节数据）
        if len(encrypted_data) < 32:  # 16 bytes IV + 16 bytes minimum data
            raise ValueError("加密数据太短")
        
        # 提取前16字节作为IV，剩余部分为密文
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # 验证密文长度是否为16字节的倍数（AES块大小）
        if len(ciphertext) % 16 != 0:
            raise ValueError("密文长度无效")
            
        # 使用相同密钥和提取的IV创建解密器
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        # 执行解密操作
        decrypted_data = cipher.decrypt(ciphertext)
        # 移除填充数据恢复原始内容
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

def is_safe_path(basedir, path):
    """验证文件路径是否安全，防止路径遍历攻击
    参数:
        basedir: 基准目录
        path: 要检查的相对路径
    返回:
        如果路径安全返回True，否则返回False
    """
    try:
        # 构造完整路径并解析符号链接等
        resolved_path = Path(basedir).resolve() / path
        # 检查解析后的路径是否在基准目录内或其子目录中
        return Path(basedir).resolve() in resolved_path.parents or Path(basedir).resolve() == resolved_path.parent
    except (OSError, ValueError):
        # 处理无效路径情况
        return False

@app.route('/')
def index():
    """根路径端点 - 显示服务器身份信息"""
    return jsonify({'message': '漏洞版本：未授权访问，端口5001'})

# ========== 这里是漏洞：移除了所有认证 ==========
# 注意：没有token_required装饰器，也没有login端点
# 任何人都可以直接访问所有API

@app.route('/api/files', methods=['GET'])
def api_list_files():
    """列出所有加密文件的元数据信息
    安全漏洞：无需认证即可访问文件列表，泄露了系统中的文件信息
    """
    print("Received request to /api/files - no authentication required")
    print(f"Request headers: {dict(request.headers)}")
    
    try:
        files = []
        files_dir = Path(app.config['UPLOAD_FOLDER'])
        if files_dir.exists():
            # 遍历所有.enc文件并收集基本信息
            for file_path in files_dir.glob('*.enc'):
                try:
                    # 尝试获取文件信息
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.stem,           # 文件名（不含扩展名）
                        'size': stat.st_size,             # 文件大小
                        'encrypted_name': file_path.name  # 加密后的文件名
                    })
                except OSError as e:
                    # 如果无法获取文件信息，记录日志并跳过该文件
                    print(f"Warning: Could not access file {file_path}: {e}")
                    continue
        
        print(f"Returning file list with {len(files)} files")
        return jsonify({'files': files})
    except Exception as e:
        # 记录错误信息
        print(f"Error in api_list_files: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        # 返回错误信息
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    """上传并加密文件
    安全漏洞：无需认证即可上传文件，任何人都可以向服务器上传文件
    """
    # 检查请求中是否包含文件
    if 'file' not in request.files:
        return jsonify({'message': 'No file selected'}), 400
    
    file = request.files['file']
    # 检查文件名是否为空
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    # 清理文件名以防止特殊字符攻击
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    # 读取文件内容
    file_data = file.read()
    # 对文件内容进行加密
    encrypted_data = encrypt_file(file_data)
    
    # 添加.enc扩展名表示这是一个加密文件
    encrypted_filename = filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # 验证文件路径安全性，防止路径遍历攻击
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    # 将加密后的数据写入文件
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    return jsonify({
        'message': f'File {filename} uploaded and encrypted successfully!',
        'success': True
    })

@app.route('/api/download/<filename>', methods=['GET'])
def api_download_file(filename):
    """下载并解密指定文件
    安全漏洞：无需认证即可下载任意文件，攻击者可以获得服务器上的所有文件
    参数:
        filename: 请求下载的文件名（不含.enc扩展名）
    """
    # 清理文件名以防止特殊字符攻击
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    # 构造加密文件名
    encrypted_filename = safe_filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    # 验证文件路径安全性
    if not is_safe_path(app.config['UPLOAD_FOLDER'], encrypted_filename):
        return jsonify({'message': 'Invalid file path'}), 400
    
    # 检查文件是否存在
    if not file_path.exists():
        return jsonify({'message': 'File not found'}), 404
    
    try:
        # 读取加密文件内容
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密文件内容
        decrypted_data = decrypt_file(encrypted_data)
        
        # 创建内存文件对象用于传输
        from io import BytesIO
        file_obj = BytesIO(decrypted_data)
        file_obj.seek(0)
        
        # 发送文件给客户端下载
        return send_file(
            file_obj,
            as_attachment=True,
            download_name=safe_filename,
            mimetype='application/octet-stream'
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
        # 错误处理
        return jsonify({'message': f'服务器内部错误: {str(e)}'}), 500

if __name__ == '__main__':
    # 从环境变量获取主机和端口配置，如果没有则使用默认值
    import os
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5001))
    
    # 在本地回环地址上运行，仅限本地访问
    # 但因为没有认证机制，所以仍然是一个严重的安全漏洞
    app.run(debug=True, host=host, port=port)