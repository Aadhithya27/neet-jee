from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT UNIQUE,
                 password_hash TEXT
                 )""")
    c.execute("""CREATE TABLE IF NOT EXISTS contacts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT,
                 message TEXT
                 )""")
    conn.commit()
    conn.close()

app = Flask(__name__, static_folder='../', static_url_path='/')
CORS(app)
init_db()

@app.route('/api/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not (name and email and password):
        return jsonify({'error':'name, email and password required'}), 400
    password_hash = generate_password_hash(password)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)",
                  (name,email,password_hash))
        conn.commit()
        conn.close()
        return jsonify({'message':'user registered'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error':'email already registered'}), 409

@app.route('/api/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not (email and password):
        return jsonify({'error':'email and password required'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,name,password_hash FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row[2], password):
        user = {'id': row[0], 'name': row[1], 'email': email}
        return jsonify({'message':'login successful', 'user': user})
    return jsonify({'error':'invalid credentials'}), 401

@app.route('/api/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    if not (name and email and message):
        return jsonify({'error':'name, email and message required'}), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO contacts (name,email,message) VALUES (?,?,?)",
              (name,email,message))
    conn.commit()
    conn.close()
    return jsonify({'message':'contact saved'}), 201

@app.route('/api/users', methods=['GET'])
def list_users():
    # Simple admin-list endpoint (no auth) to show data locally
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id,name,email FROM users")
    rows = c.fetchall()
    conn.close()
    users = [{'id':r[0],'name':r[1],'email':r[2]} for r in rows]
    return jsonify(users)

# Serve frontend index if requested
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    # try to serve file from parent folder (the unpacked frontend)
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if path != "" and os.path.exists(os.path.join(root, path)):
        return send_from_directory(root, path)
    else:
        index_path = os.path.join(root, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(root, 'index.html')
        return jsonify({'status':'backend running'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
