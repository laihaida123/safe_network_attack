# vuln_sql_injection.py
import os
import secrets
import sqlite3
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import jwt
import datetime
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'protected_files'
app.config['DATABASE'] = 'test.db'

# 使用持久化的JWT密钥而不是每次都生成新的
jwt_secret_file = Path('keys/jwt_secret_sql.key')
if jwt_secret_file.exists():
    with open(jwt_secret_file, 'r') as f:
        app.config['JWT_SECRET_KEY'] = f.read()
else:
    jwt_secret = secrets.token_hex(32)
    with open(jwt_secret_file, 'w') as f:
        f.write(jwt_secret)
    app.config['JWT_SECRET_KEY'] = jwt_secret

CORS(app, resources={r"/api/*": {"origins": "*"}})

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 创建测试数据库（模拟用户数据）
def init_database():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # 创建用户表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # 检查表是否为空
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        # 插入测试数据 - 修复列数问题
        cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                      ('admin', 'admin123', 'admin@test.com', 1))
        cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                      ('user1', 'password123', 'user1@test.com', 0))
        cursor.execute("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                      ('test', 'test123', 'test@test.com', 0))
        
        print("数据库初始化完成，插入3条测试数据")
    
    conn.commit()
    conn.close()

init_database()

# 用户数据（与数据库同步）
users = {
    'admin': {
        'password': 'admin123',
        'id': 1
    },
    'user1': {
        'password': 'password123',
        'id': 2
    },
    'test': {
        'password': 'test123',
        'id': 3
    }
}

def get_encryption_key():
    # 使用独立的密钥文件，避免与其他服务冲突
    key_file = Path('keys/encryption_key_sql.key')
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# ========== SQL注入漏洞点 ==========
@app.route('/api/vulnerable/search', methods=['GET'])
def vulnerable_search():
    """存在SQL注入漏洞的搜索接口"""
    search_term = request.args.get('q', '')
    
    if not search_term:
        return jsonify({'error': '搜索词不能为空'}), 400
    
    # 漏洞：直接拼接SQL查询
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    try:
        # 危险！SQL注入漏洞
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
        print(f"[危险] 执行SQL查询: {query}")
        cursor.execute(query)
        
        users_list = []
        for row in cursor.fetchall():
            users_list.append({
                'id': row[0],
                'username': row[1],
                'email': row[3],
                'is_admin': bool(row[4])
            })
        
        conn.close()
        
        # 故意泄露SQL信息（方便演示）
        if 'union' in search_term.lower() or 'select' in search_term:
            return jsonify({
                'users': users_list,
                'debug_info': {
                    'query': query,
                    'vulnerable': True,
                    'message': '检测到可能的SQL注入尝试'
                }
            })
        
        return jsonify({'users': users_list})
        
    except Exception as e:
        # 返回错误信息（实际中不应该这样做）
        return jsonify({
            'error': str(e),
            'vulnerable': True,
            'message': 'SQL执行错误，可能存在SQL注入'
        }), 500

@app.route('/api/vulnerable/login', methods=['POST'])
def vulnerable_login():
    """存在SQL注入的登录接口"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': '用户名和密码不能为空'}), 400
    
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # 漏洞：直接拼接SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[危险] 执行登录查询: {query}")
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # 生成JWT令牌
            token = jwt.encode({
                'username': user[1],
                'id': user[0],
                'is_admin': bool(user[4]),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            
            # 返回额外信息用于演示
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user[0],
                    'username': user[1],
                    'email': user[3],
                    'is_admin': bool(user[4])
                },
                'debug': {
                    'query': query,
                    'vulnerable': True
                }
            })
        else:
            return jsonify({
                'success': False,
                'message': '登录失败',
                'debug': {'query': query}
            }), 401
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'query': query,
            'vulnerable': True
        }), 500

# 安全的版本（对比用）
@app.route('/api/secure/search', methods=['GET'])
def secure_search():
    """安全的搜索接口（使用参数化查询）"""
    search_term = request.args.get('q', '')
    
    if not search_term:
        return jsonify({'error': '搜索词不能为空'}), 400
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    try:
        # 安全：使用参数化查询
        query = "SELECT id, username, email, is_admin FROM users WHERE username LIKE ? OR email LIKE ?"
        cursor.execute(query, (f'%{search_term}%', f'%{search_term}%'))
        
        users_list = []
        for row in cursor.fetchall():
            users_list.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'is_admin': bool(row[3])
            })
        
        conn.close()
        return jsonify({'users': users_list})
        
    except Exception as e:
        return jsonify({'error': '查询失败'}), 500

# 标准登录（用于其他测试）
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    # 检查用户是否存在
    if username in users and users[username]['password'] == password:
        # 生成JWT token
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

# 文件上传接口（为了测试其他攻击）
@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    filename = file.filename
    file_data = file.read()
    
    # 简单保存文件
    encrypted_filename = filename + '.enc'
    file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    return jsonify({
        'message': f'File {filename} uploaded!',
        'success': True
    })

@app.route('/')
def index():
    return jsonify({'message': 'SQL注入漏洞演示版本', 'port': 5005})

if __name__ == '__main__':
    # 从环境变量获取主机和端口配置，如果没有则使用默认值
    import os
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RUN_PORT', 5005))
    
    app.run(debug=True, host=host, port=port)