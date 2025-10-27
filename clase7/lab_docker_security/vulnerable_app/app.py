#!/usr/bin/env python3
"""
Aplicación web vulnerable para demostración educativa
NO USAR EN PRODUCCIÓN

UTN FRVM - Laboratorio de Ciberseguridad
"""

from flask import Flask, request, render_template_string, send_file
import os
import subprocess
import sqlite3
import pickle
import base64

app = Flask(__name__)

# VULNERABILIDAD 1: Secret hardcodeado
SECRET_KEY = 'supersecretkey123'
DATABASE_PASSWORD = 'admin123'
API_KEY = 'sk-1234567890abcdef'

# VULNERABILIDAD 2: Debug mode en producción
app.config['DEBUG'] = True

# VULNERABILIDAD 3: Base de datos insegura
def init_db():
    conn = sqlite3.connect('/tmp/users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT, password TEXT, role TEXT)''')
    c.execute("INSERT INTO users VALUES ('admin', 'admin123', 'admin')")
    c.execute("INSERT INTO users VALUES ('user', 'user123', 'user')")
    conn.commit()
    conn.close()

init_db()

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App - UTN FRVM Lab</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #d9534f; }
        .vuln-demo { margin: 20px 0; padding: 15px; border-left: 4px solid #d9534f; }
        input, button { padding: 8px; margin: 5px; }
        button { background: #d9534f; color: white; border: none; cursor: pointer; }
        .warning { background: #fff3cd; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Vulnerable Web Application</h1>
        <div class="warning">
            <strong>⚠️ ADVERTENCIA:</strong> Esta aplicación contiene vulnerabilidades intencionales
            con fines educativos. NO usar en producción.
        </div>

        <div class="vuln-demo">
            <h2>1. SQL Injection</h2>
            <form action="/login" method="post">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
            <p><small>Hint: Try ' OR '1'='1</small></p>
        </div>

        <div class="vuln-demo">
            <h2>2. Command Injection</h2>
            <form action="/ping" method="post">
                <input name="host" placeholder="IP or hostname">
                <button type="submit">Ping</button>
            </form>
            <p><small>Hint: Try 127.0.0.1; cat /etc/passwd</small></p>
        </div>

        <div class="vuln-demo">
            <h2>3. Path Traversal</h2>
            <form action="/file" method="get">
                <input name="name" placeholder="Filename">
                <button type="submit">Read File</button>
            </form>
            <p><small>Hint: Try ../../etc/passwd</small></p>
        </div>

        <div class="vuln-demo">
            <h2>4. Server-Side Template Injection (SSTI)</h2>
            <form action="/render" method="post">
                <input name="template" placeholder="Template string">
                <button type="submit">Render</button>
            </form>
            <p><small>Hint: Try {{ 7*7 }} or {{ ''.__class__.__mro__[1].__subclasses__() }}</small></p>
        </div>

        <div class="vuln-demo">
            <h2>5. Insecure Deserialization</h2>
            <form action="/deserialize" method="post">
                <input name="data" placeholder="Base64 encoded pickle">
                <button type="submit">Deserialize</button>
            </form>
            <p><small>Hint: Upload malicious pickle object</small></p>
        </div>

        <div class="vuln-demo">
            <h2>6. Environment Variables Leak</h2>
            <a href="/debug">View Environment Variables</a>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return HOME_TEMPLATE

# VULNERABILIDAD 4: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL Injection vulnerable query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    conn = sqlite3.connect('/tmp/users.db')
    c = conn.cursor()
    c.execute(query)
    user = c.fetchone()
    conn.close()

    if user:
        return f'''
        <h1>✅ Login Successful!</h1>
        <p>Welcome {user[0]}!</p>
        <p>Role: {user[2]}</p>
        <p><strong>Query ejecutado:</strong> <code>{query}</code></p>
        <a href="/">Volver</a>
        '''
    else:
        return f'''
        <h1>❌ Login Failed</h1>
        <p><strong>Query ejecutado:</strong> <code>{query}</code></p>
        <a href="/">Volver</a>
        '''

# VULNERABILIDAD 5: Command Injection
@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host')

    # Command injection vulnerable
    command = f'ping -c 3 {host}'
    try:
        output = subprocess.check_output(command, shell=True, timeout=5, stderr=subprocess.STDOUT)
        return f'''
        <h1>Ping Results</h1>
        <pre>{output.decode()}</pre>
        <p><strong>Command ejecutado:</strong> <code>{command}</code></p>
        <a href="/">Volver</a>
        '''
    except subprocess.TimeoutExpired:
        return '<h1>Timeout!</h1><a href="/">Volver</a>'
    except Exception as e:
        return f'''
        <h1>Error</h1>
        <pre>{str(e)}</pre>
        <a href="/">Volver</a>
        '''

# VULNERABILIDAD 6: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name')

    # Path traversal vulnerable
    try:
        with open(f'/app/files/{filename}', 'r') as f:
            content = f.read()
        return f'''
        <h1>File Content</h1>
        <pre>{content}</pre>
        <a href="/">Volver</a>
        '''
    except Exception as e:
        return f'''
        <h1>Error reading file</h1>
        <p>{str(e)}</p>
        <a href="/">Volver</a>
        '''

# VULNERABILIDAD 7: Server-Side Template Injection
@app.route('/render', methods=['POST'])
def render_template():
    template_string = request.form.get('template')

    # SSTI vulnerable
    try:
        result = render_template_string(template_string)
        return f'''
        <h1>Rendered Template</h1>
        <div>{result}</div>
        <a href="/">Volver</a>
        '''
    except Exception as e:
        return f'''
        <h1>Template Error</h1>
        <p>{str(e)}</p>
        <a href="/">Volver</a>
        '''

# VULNERABILIDAD 8: Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.form.get('data')

    # Insecure deserialization
    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return f'''
        <h1>Deserialization Result</h1>
        <p>{str(obj)}</p>
        <a href="/">Volver</a>
        '''
    except Exception as e:
        return f'''
        <h1>Deserialization Error</h1>
        <p>{str(e)}</p>
        <a href="/">Volver</a>
        '''

# VULNERABILIDAD 9: Information Disclosure
@app.route('/debug')
def debug_info():
    env_vars = '<br>'.join([f'{k}: {v}' for k, v in os.environ.items()])
    return f'''
    <h1>Debug Information</h1>
    <h2>Environment Variables:</h2>
    <pre>{env_vars}</pre>
    <h2>Application Secrets:</h2>
    <pre>
    SECRET_KEY: {SECRET_KEY}
    DATABASE_PASSWORD: {DATABASE_PASSWORD}
    API_KEY: {API_KEY}
    </pre>
    <a href="/">Volver</a>
    '''

# VULNERABILIDAD 10: No input validation
@app.route('/eval', methods=['POST'])
def eval_code():
    code = request.form.get('code')
    try:
        result = eval(code)
        return f'Result: {result}'
    except Exception as e:
        return f'Error: {str(e)}'

if __name__ == '__main__':
    # VULNERABILIDAD 11: Bind to 0.0.0.0
    os.makedirs('/app/files', exist_ok=True)
    with open('/app/files/test.txt', 'w') as f:
        f.write('Test file content')

    app.run(host='0.0.0.0', port=5000)
