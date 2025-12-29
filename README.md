# 🔐 Flask安全文件门户 - 完整攻防实验平台

一个集成了多版本漏洞与安全防御的Flask Web应用程序，用于**Web安全教学与攻防实验**。该项目包含一个安全版本和五个典型漏洞版本，配合Vue.js前端攻击测试界面，帮助学习者直观理解常见Web安全漏洞的原理、危害及防护方法。

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![Vue.js](https://img.shields.io/badge/Vue.js-3.0-brightgreen.svg)

## ✨ 核心特性

### 🎯 实验教学导向
- **多版本对比**：安全版本 + 5个独立漏洞版本（未授权访问、目录遍历、ECB加密漏洞等）
- **实时攻击测试**：集成Vue.js前端攻击界面，支持对各个后端服务进行安全测试
- **完整攻防演练**：从漏洞发现、利用到安全防护的完整实验流程

### 🔐 安全机制实现
- **JWT认证授权**：基于令牌的无状态身份验证
- **AES-256-CBC加密**：文件上传自动加密，下载自动解密
- **防御层**：路径验证、输入净化、参数化查询、安全头部等
- **安全配置**：HttpOnly Cookie、CSP策略、会话管理

### 🕷️ 典型漏洞复现
- **未授权访问 (A01:2021)**：缺失访问控制的API端点
- **目录遍历 (CWE-22)**：不安全的文件路径处理
- **SQL注入 (A03:2021)**：用户输入直接拼接SQL语句
- **加密漏洞**：ECB模式导致相同明文相同密文
- **JWT安全**：令牌验证与篡改风险

### 🖥️ 现代技术栈
- **后端**：Python Flask + PyCryptodome + JWT
- **前端**：Vue.js 3 + 轮询负载均衡代理
- **数据库**：SQLite（用于SQL注入实验）
- **安全工具**：模拟Burp Suite攻击测试功能

## 🚀 快速开始

### 系统架构
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Vue前端       │    │   Vue代理       │    │   Flask后端     │
│   (8080)        │───▶│   轮询负载均衡  │───▶│   多版本        │
│  攻击测试界面   │    │                 │    │   (5000-5005)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 环境准备

1. **克隆项目**
```bash
git clone https://github.com/yourusername/flask-security-lab.git
cd flask-security-lab
```

2. **安装Python依赖**
```bash
pip install -r requirements.txt
```

3. **安装前端依赖**
```bash
cd frontend
npm install
```

### 启动所有服务

#### 方法一：分别启动后端服务（推荐用于调试）
需要打开6个终端分别运行以下命令：

```bash
# 终端1 - 安全版本 (参考实现)
python secure_app.py

# 终端2 - 未授权访问漏洞
python vuln_unauth.py

# 终端3 - 目录遍历漏洞
python vuln_dir_traversal.py

# 终端4 - ECB加密模式漏洞
python vuln_ecb_mode.py

# 终端5 - 完全漏洞版本
python vuln_no_validation.py

# 终端6 - SQL注入漏洞
python vuln_sql_injection.py
```

#### 方法二：一键启动所有后端服务
```bash
# 使用启动脚本一次性启动所有服务
python start_multiple_servers.py
```

注意：如果使用方法二，可能需要在任务管理器或htop中手动结束进程来停止服务。

#### 启动前端服务
```bash
cd frontend
npm run serve
```

### 访问应用
- **攻击测试界面**：http://localhost:8080/attack-test
- **安全版本**：http://localhost:5000
- **漏洞版本**：http://localhost:5001-5005（分别对应不同漏洞）

### 默认测试账户
- **用户名**：`admin`
- **密码**：`admin123`

## 📁 项目结构

```
flask-security-lab/
├── backend/                      # 后端代码
│   ├── secure_app.py            # 安全版本（参考实现）
│   ├── vuln_unauth.py           # 未授权访问漏洞
│   ├── vuln_dir_traversal.py    # 目录遍历漏洞
│   ├── vuln_ecb_mode.py         # ECB加密漏洞
│   ├── vuln_no_validation.py    # 完全漏洞版本
│   ├── vuln_sql_injection.py    # SQL注入漏洞
│   ├── common/                  # 公共模块
│   │   ├── auth.py             # JWT认证
│   │   ├── crypto.py           # 加密函数
│   │   └── utils.py            # 工具函数
│   ├── protected_files/         # 加密文件存储
│   └── keys/                    # 加密密钥
│
├── frontend/                    # Vue.js前端
│   ├── public/
│   ├── src/
│   │   ├── views/AttackTest.vue # 攻击测试界面
│   │   ├── components/          # 攻击测试组件
│   │   ├── router/             # 路由配置
│   │   └── App.vue
│   ├── vue.config.js           # 轮询代理配置
│   └── package.json
│
├── docs/                        # 文档
│   ├── SECURITY_OVERVIEW.md     # 安全概述
│   ├── LAB_GUIDE.md            # 实验手册
│   └── VIDEO_SCRIPT.md         # 视频脚本
│
├── requirements.txt            # Python依赖
├── README.md                   # 本文件
└── .gitignore
```

## 🔬 实验指南

### 前端攻击测试界面使用说明

本项目提供了一个集成的Vue.js前端攻击测试界面（位于 http://localhost:8080/attack-test），用于方便地测试各种安全漏洞。界面分为以下几个主要模块：

1. **目标选择区域**：选择要测试的目标服务（安全版本或各漏洞版本）
2. **未授权访问攻击模块**：测试无需认证即可访问的API端点
3. **目录遍历攻击模块**：测试文件上传/下载功能中的路径遍历漏洞
4. **SQL注入攻击模块**：测试各种类型的SQL注入漏洞
5. **ECB加密模式漏洞模块**：测试加密算法的安全性
6. **JWT分析模块**：分析和测试JWT令牌的安全性
7. **请求拦截模拟模块**：模拟Burp Suite等代理工具的功能

#### SQL注入攻击模块详解

SQL注入攻击模块允许您测试多种类型的SQL注入攻击：

- **布尔盲注**：通过真假条件判断获取信息
- **UNION注入**：通过UNION语句合并查询结果
- **报错注入**：通过数据库错误信息获取数据
- **时间盲注**：通过响应时间差异判断条件真假
- **文件名注入**：通过文件名参数进行注入攻击

**使用步骤**：
1. 在顶部选择"SQL注入漏洞 (端口5005)"目标
2. 从下拉菜单中选择注入类型
3. 使用预设的注入语句或手动输入
4. 点击"执行注入攻击"按钮
5. 查看攻击结果和日志信息

**结果解读**：
- 状态码500并不一定代表攻击失败，而是可能暴露了数据库错误信息，这本身就是一种漏洞
- 返回结果中的`"vulnerable": true`字段明确表示存在SQL注入漏洞
- 错误信息可以帮助攻击者进一步优化注入语句

### 实验1：未授权访问漏洞
**目标端口**：5001
**漏洞描述**：API端点缺少身份验证，攻击者无需登录即可访问敏感数据。

**测试步骤**：
1. 访问 http://localhost:8080/attack-test
2. 选择"未授权漏洞 (端口5001)"
3. 点击"直接获取文件列表"（无需登录）
4. 观察能够获取到文件列表
5. 对比安全版本(端口5000)的相同操作

**漏洞代码示例**：
``python
# vuln_unauth.py - 漏洞版本（缺失@token_required装饰器）
@app.route('/api/files', methods=['GET'])
def api_list_files():  # 缺少认证装饰器
    files = os.listdir(UPLOAD_FOLDER)
    return jsonify(files)

# secure_app.py - 安全版本（有认证装饰器）
@app.route('/api/files', methods=['GET'])
@token_required  # JWT认证装饰器
def api_list_files(current_user):
    files = os.listdir(UPLOAD_FOLDER)
    return jsonify(files)
```

### 实验2：目录遍历漏洞
**目标端口**：5002
**漏洞描述**：未对用户输入的文件名进行路径净化，允许攻击者访问系统文件。

**测试步骤**：
1. 登录系统（用户名：admin，密码：admin123）
2. 在目录遍历测试模块，输入文件名：`../../../etc/passwd`
3. 尝试上传或下载该文件
4. 观察系统响应

**防御机制对比**：
```
# 漏洞版本 - 无路径验证
def is_safe_path(basedir, path):
    return True  # 总是返回True，危险！

# 安全版本 - 严格路径验证
def is_safe_path(basedir, path):
    basedir_path = Path(basedir).resolve()
    target_path = Path(path).resolve()
    return basedir_path in target_path.parents
```

### 实验3：ECB加密模式漏洞
**目标端口**：5003
**漏洞描述**：使用ECB加密模式，相同明文块产生相同密文块，泄露数据模式。

**测试步骤**：
1. 登录系统
2. 上传两个内容完全相同的文件
3. 使用"比较加密结果"功能
4. 观察相似度分析（ECB模式应为100%相似）
5. 对比CBC模式（安全版本，应为0%相似）

**加密模式对比**：
```
# ECB漏洞版本
def encrypt_file(file_data):
    cipher = AES.new(key, AES.MODE_ECB)  # 使用ECB模式
    return cipher.encrypt(padded_data)   # 无IV，相同输入相同输出

# CBC安全版本
def encrypt_file(file_data):
    cipher = AES.new(key, AES.MODE_CBC)  # 使用CBC模式
    iv = cipher.iv                       # 随机IV
    return iv + cipher.encrypt(padded_data)  # 不同IV导致不同输出
```

### 实验4：SQL注入漏洞
**目标端口**：5005
**漏洞描述**：用户输入直接拼接到SQL查询语句中，允许执行恶意SQL代码。

**测试步骤**：
1. 访问 http://localhost:8080/attack-test
2. 选择"SQL注入漏洞 (端口5005)"
3. 在注入类型中选择合适的类型（如UNION注入）
4. 使用预设的注入语句或手动输入
5. 点击"执行注入攻击"
6. 观察能否绕过身份验证或获取敏感数据

**常见的注入测试语句**：
- 布尔盲注：`' OR '1'='1`
- 登录绕过：`admin'--`
- UNION查询：`' UNION SELECT username, password FROM users --`
- 报错注入：`' AND 1=CONVERT(int, (SELECT @@version))--`

**重要说明**：
当您看到类似下面的结果时，表示攻击成功发现了SQL注入漏洞：
``json
{
  "error": "SELECTs to the left and right of UNION do not have the same number of result columns",
  "message": "SQL执行错误，可能存在SQL注入",
  "vulnerable": true
}
```
其中`"vulnerable": true`明确指出存在漏洞，错误信息提供了进一步攻击的线索。

**SQL查询对比**：
```
# 漏洞版本 - 字符串拼接
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)  # 直接执行，危险！

# 安全版本 - 参数化查询
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))  # 参数化，安全
```

## 🛡️ 安全实现详情

### JWT认证系统
```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token.split()[1], SECRET_KEY, algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated
```

### 前端轮询负载均衡
```javascript
// vue.config.js - 轮询代理配置
let currentPort = 5000
const ports = [5000, 5001, 5002, 5003, 5004, 5005]

module.exports = {
  devServer: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        router: () => `http://localhost:${ports[currentPort++ % ports.length]}`
      }
    }
  }
}
```

## 📊 实验报告模板

### 实验报告结构
1. **封面**：实验名称、个人信息、日期
2. **实验目的**：简述学习目标
3. **环境配置**：软件版本、系统环境
4. **实验过程**：按漏洞类型详细记录
5. **结果分析**：攻击成功率、防御效果
6. **漏洞分析**：原理、危害、修复方案
7. **心得体会**：学习收获与思考
8. **参考文献**

### 关键截图要求
1. 攻击测试界面整体布局
2. 每个漏洞攻击成功截图
3. 安全版本防御成功截图
4. 攻击日志记录截图
5. 前后端控制台输出

## ⚠️ 安全注意事项

### 实验环境安全
- 仅在隔离的本地环境或实验网络中运行
- 不要使用真实密码或敏感数据
- 实验结束后关闭所有服务

### 生产环境建议
- 使用HTTPS加密传输
- 将加密密钥存储在环境变量或密钥管理服务中
- 实现完整的日志记录和监控
- 定期进行安全审计和渗透测试
- 配置Web应用防火墙（WAF）

## 🆘 故障排除

### 常见问题
1. **端口冲突**：确保5000-5005端口未被占用
2. **依赖安装失败**：检查Python和Node.js版本
3. **前端代理问题**：检查vue.config.js配置
4. **数据库连接失败**：检查SQLite文件权限
5. **SQL注入测试无反应**：确认已选择正确的"SQL注入漏洞 (端口5005)"目标

### SQL注入测试常见问题

**Q: 为什么我点击执行注入攻击后，所有测试都会运行？**
A: 这是由于前端代码逻辑问题导致的。我们已经修复了这个问题，确保每次只执行选定的攻击。

**Q: 为什么我看到的状态码是500，这是攻击失败了吗？**
A: 不是的。在安全测试中，500状态码以及返回的错误信息本身就暴露了系统漏洞。特别是当返回结果包含`"vulnerable": true`时，明确表明存在SQL注入漏洞。

**Q: 如何确定SQL注入攻击成功了？**
A: 成功的标志包括：
   - 返回结果中包含`"vulnerable": true`
   - 返回详细的数据库错误信息
   - 成功绕过身份验证获取敏感数据
   - 能够操纵查询结果

**Q: 我应该如何优化UNION注入语句？**
A: 当您看到类似"SELECTs to the left and right of UNION do not have the same number of result columns"的错误时，说明UNION左右两侧的列数不匹配。您需要调整注入语句中的列数以匹配原始查询。

### 服务状态检查
```bash
# 检查端口占用
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # Linux/Mac

# 测试API端点
curl http://localhost:5000/api/status
```

## 🤝 贡献指南

欢迎提交漏洞修复、新实验案例或文档改进！

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/new-vulnerability`)
3. 提交更改 (`git commit -m 'Add new vulnerability type'`)
4. 推送到分支 (`git push origin feature/new-vulnerability`)
5. 创建Pull Request

## 📚 学习资源

- OWASP Top 10 (2021)：https://owasp.org/www-project-top-ten/
- Web安全测试指南：https://owasp.org/www-project-web-security-testing-guide/
- Flask安全文档：https://flask.palletsprojects.com/en/stable/security/
- JWT安全最佳实践：https://jwt.io/introduction


## 📧 联系与支持

如有问题或建议：
- 提交GitHub Issue
- 查看项目Wiki页面
- 参考详细实验手册

---

