#!/usr/bin/env python3
"""
Aplicación web SEGURA - Versión corregida
UTN FRVM - Laboratorio de Ciberseguridad
"""

from flask import Flask, request, escape
import os

app = Flask(__name__)

# Secrets desde archivos (no hardcodeados)
try:
    with open('/run/secrets/db_password', 'r') as f:
        DB_PASSWORD = f.read().strip()
    with open('/run/secrets/api_key', 'r') as f:
        API_KEY = f.read().strip()
except FileNotFoundError:
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'changeme')
    API_KEY = os.environ.get('API_KEY', 'changeme')

app.config['DEBUG'] = False  # NUNCA debug en producción

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure App - UTN FRVM Lab</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #5cb85c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Secure Web Application</h1>
        <p>Esta aplicación implementa mejores prácticas de seguridad.</p>
        <p>UTN FRVM - Laboratorio de Ciberseguridad</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return HOME_TEMPLATE

@app.route('/health')
def health():
    return {'status': 'healthy'}, 200

if __name__ == '__main__':
    os.makedirs('/app/files', exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
