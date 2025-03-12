from flask import Flask, render_template, request, send_file, jsonify, session, redirect, url_for
import os
from datetime import datetime
import base64
import mysql.connector
import json
import io
import ctypes
import asyncio
import logging
import zlib
from kademlia.network import Server
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Set up logging
logging.basicConfig(level=logging.INFO, filename='blockchain.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load the Falcon shared library
falcon_lib = ctypes.CDLL("/usr/local/lib/libfalcon.so")

# Define Falcon-512 function signatures
falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair.restype = ctypes.c_int

falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign.restype = ctypes.c_int

falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open.restype = ctypes.c_int

# Constants for Falcon-512
CRYPTO_PUBLICKEYBYTES = 897   # Falcon-512 public key size
CRYPTO_SECRETKEYBYTES = 1281  # Falcon-512 secret key size
CRYPTO_BYTES = 666            # Falcon-512 signature size (average)

# Node configuration
NODE_ID = os.getenv("NODE_ID", "node1")
BOOTSTRAP_IP = os.getenv("BOOTSTRAP_IP", "127.0.0.1")
BOOTSTRAP_PORT = int(os.getenv("BOOTSTRAP_PORT", 8468))
LOCAL_DHT_PORT = int(os.getenv("LOCAL_DHT_PORT", 8468))

# MySQL database configuration
DB_CONFIG = {
    'user': 'blockchain_user',
    'password': 'your_password',  # Replace with your actual password
    'host': 'localhost',
    'database': f'rcschain_db_{NODE_ID}',
    'raise_on_warnings': True
}

# Pre-shared AES key for DHT encryption (32 bytes for AES-256)
DHT_ENCRYPTION_KEY = b'SecretKeyForRCSChain1234567890AB'

class Block:
    def __init__(self, index, previous_hash, timestamp, data, signature):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.signature = signature

class PrivateBlockchain:
    def __init__(self):
        self.node_id = NODE_ID
        self.local_ip = self.get_local_ip()
        
        # Load or generate Falcon keys for blockchain and authentication
        key_file = f"falcon_keys_{self.node_id}.bin"
        auth_key_file = f"falcon_auth_keys_{self.node_id}.bin"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                pk_data = f.read(CRYPTO_PUBLICKEYBYTES)
                sk_data = f.read(CRYPTO_SECRETKEYBYTES)
            self.pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES).from_buffer_copy(pk_data)
            self.sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES).from_buffer_copy(sk_data)
        else:
            self.pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
            self.sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
            if falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(self.pk, self.sk) != 0:
                raise RuntimeError("Failed to generate Falcon key pair")
            with open(key_file, "wb") as f:
                f.write(bytes(self.pk))
                f.write(bytes(self.sk))
        
        if os.path.exists(auth_key_file):
            with open(auth_key_file, "rb") as f:
                auth_pk_data = f.read(CRYPTO_PUBLICKEYBYTES)
                auth_sk_data = f.read(CRYPTO_SECRETKEYBYTES)
            self.auth_pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES).from_buffer_copy(auth_pk_data)
            self.auth_sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES).from_buffer_copy(auth_sk_data)
        else:
            self.auth_pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
            self.auth_sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
            if falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(self.auth_pk, self.auth_sk) != 0:
                raise RuntimeError("Failed to generate Falcon auth key pair")
            with open(auth_key_file, "wb") as f:
                f.write(bytes(self.auth_pk))
                f.write(bytes(self.sk))
        
        self.trusted_peers = {}
        self.file_system = {}
        self.init_storage()
        self.dht_server = Server()
        asyncio.run(self.start_dht())
        if not self.load_chain():
            self.create_genesis_block()

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def init_storage(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        
        # Create blocks table
        try:
            c.execute('''CREATE TABLE IF NOT EXISTS blocks (
                         `index` INT PRIMARY KEY,
                         previous_hash TEXT NOT NULL,
                         timestamp TEXT NOT NULL,
                         data TEXT NOT NULL,
                         signature TEXT NOT NULL
                         )''')
        except mysql.connector.Error as e:
            if e.errno != 1050:
                raise
        
        # Create users table
        try:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                         id INT AUTO_INCREMENT PRIMARY KEY,
                         username VARCHAR(255) UNIQUE NOT NULL,
                         password_hash BLOB NOT NULL
                         )''')
        except mysql.connector.Error as e:
            if e.errno != 1050:
                raise
        
        # Add default user (admin:password) if not exists
        default_user = 'admin'
        default_password = 'password'
        password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
        c.execute('INSERT IGNORE INTO users (username, password_hash) VALUES (%s, %s)',
                 (default_user, password_hash))
        
        # Create indexes for blocks table
        for index_name, column in [
            ('idx_signature', 'signature(255)'),
            ('idx_timestamp', 'timestamp(255)'),
            ('idx_prev_hash', 'previous_hash(255)')
        ]:
            try:
                c.execute(f'CREATE INDEX {index_name} ON blocks ({column})')
            except mysql.connector.Error as e:
                if e.errno != 1061:
                    raise
        
        conn.commit()
        conn.close()

    def encrypt_dht_data(self, data):
        aesgcm = AESGCM(DHT_ENCRYPTION_KEY)
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt_dht_data(self, encrypted_data):
        aesgcm = AESGCM(DHT_ENCRYPTION_KEY)
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to decrypt DHT data: {e}")
            return None

    async def start_dht(self):
        await self.dht_server.listen(LOCAL_DHT_PORT)
        if self.node_id != "leader":
            await self.dht_server.bootstrap([(BOOTSTRAP_IP, BOOTSTRAP_PORT)])
        node_data = {
            "ip": self.local_ip,
            "port": 5001,
            "pubkey": base64.b64encode(bytes(self.auth_pk)).decode('utf-8')
        }
        encrypted_data = self.encrypt_dht_data(node_data)
        await self.dht_server.set(f"node_{self.node_id}", encrypted_data)
        asyncio.create_task(self.discover_peers())

    async def discover_peers(self):
        while True:
            for peer_id in ["leader", "node1", "node2"]:  # Adjust as needed
                if peer_id != self.node_id:
                    encrypted_data = await self.dht_server.get(f"node_{peer_id}")
                    if encrypted_data:
                        peer_info = self.decrypt_dht_data(encrypted_data)
                        if peer_info:
                            self.trusted_peers[peer_id] = {
                                "ip": peer_info["ip"],
                                "port": peer_info["port"],
                                "pubkey": (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES).from_buffer_copy(base64.b64decode(peer_info["pubkey"]))
                            }
            await asyncio.sleep(60)

    def sign_block(self, index, previous_hash, timestamp, data):
        message = str(index) + previous_hash + timestamp + str(data)
        msg_bytes = message.encode('utf-8')
        msg_len = len(msg_bytes)
        
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + msg_len))()
        smlen = ctypes.c_size_t(0)
        
        falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign(
            sm, ctypes.byref(smlen), 
            msg_bytes, msg_len, 
            self.sk
        )
        signature = bytes(sm[:CRYPTO_BYTES])
        return base64.b64encode(zlib.compress(signature)).decode('utf-8')

    def verify_block(self, index, previous_hash, timestamp, data, signature):
        message = str(index) + previous_hash + timestamp + str(data)
        msg_bytes = message.encode('utf-8')
        msg_len = ctypes.c_size_t(len(msg_bytes))
        
        signature_bytes = zlib.decompress(base64.b64decode(signature))
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + len(msg_bytes)))()
        for i, byte in enumerate(signature_bytes + msg_bytes):
            sm[i] = byte
        smlen = ctypes.c_size_t(len(signature_bytes) + len(msg_bytes))
        
        m = (ctypes.c_ubyte * len(msg_bytes))()
        mlen = ctypes.c_size_t(0)
        
        result = falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
            m, ctypes.byref(mlen), 
            sm, smlen, 
            self.pk
        )
        return result == 0 and bytes(m[:mlen.value]) == msg_bytes

    def sign_message(self, message):
        msg_bytes = message.encode('utf-8')
        msg_len = len(msg_bytes)
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + msg_len))()
        smlen = ctypes.c_size_t(0)
        
        falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign(
            sm, ctypes.byref(smlen), 
            msg_bytes, msg_len, 
            self.auth_sk
        )
        signature = bytes(sm[:CRYPTO_BYTES])
        return base64.b64encode(zlib.compress(signature)).decode('utf-8')

    def verify_message(self, message, signature, peer_id):
        if peer_id not in self.trusted_peers:
            return False
        msg_bytes = message.encode('utf-8')
        msg_len = ctypes.c_size_t(len(msg_bytes))
        signature_bytes = zlib.decompress(base64.b64decode(signature))
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + len(msg_bytes)))()
        for i, byte in enumerate(signature_bytes + msg_bytes):
            sm[i] = byte
        smlen = ctypes.c_size_t(len(signature_bytes) + len(msg_bytes))
        m = (ctypes.c_ubyte * len(msg_bytes))()
        mlen = ctypes.c_size_t(0)
        
        result = falcon_lib.PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
            m, ctypes.byref(mlen), 
            sm, smlen, 
            self.trusted_peers[peer_id]["pubkey"]
        )
        return result == 0 and bytes(m[:mlen.value]) == msg_bytes

    def create_genesis_block(self):
        genesis_data = {"root": {"type": "directory", "contents": {}}}
        timestamp = datetime.now().isoformat()
        signature = self.sign_block(0, "0", timestamp, genesis_data)
        
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute('INSERT IGNORE INTO blocks (`index`, previous_hash, timestamp, data, signature) VALUES (%s, %s, %s, %s, %s)',
                 (0, "0", timestamp, json.dumps(genesis_data), signature))
        conn.commit()
        conn.close()
        
        self.file_system = genesis_data
        asyncio.run(self.broadcast_block(0, "0", timestamp, genesis_data, signature))

    def load_chain(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor(dictionary=True)
        c.execute('SELECT * FROM blocks ORDER BY `index`')
        blocks = c.fetchall()
        conn.close()

        if not blocks:
            if self.node_id != "leader":
                asyncio.run(self.sync_from_leader())
            return False

        self.file_system = {"root": {"type": "directory", "contents": {}}}
        for block in blocks:
            data = json.loads(block['data'])
            if not self.verify_block(block['index'], block['previous_hash'], 
                                    block['timestamp'], data, block['signature']):
                logging.error(f"Invalid signature in block {block['index']}. Skipping.")
                continue
            if block['index'] == 0:
                self.file_system = data
            else:
                self.apply_operation(data)
        return True

    def apply_operation(self, data):
        operation = data["operation"]
        path = data["path"]
        current, target = get_path_dict(path)
        
        if operation == "create_folder":
            current[target] = {"type": "directory", "contents": {}}
        elif operation == "upload_file":
            current[target] = {"type": "file", "content": data["content"]}
        elif operation == "delete_file":
            if target in current and current[target]["type"] == "file":
                del current[target]
        elif operation == "delete_folder":
            if target in current and current[target]["type"] == "directory":
                del current[target]
        elif operation == "move" or operation == "copy":
            source_path = data["source"]
            src_current, src_target = get_path_dict(source_path)
            if src_target in src_current:
                item = src_current[src_target]
                if operation == "move":
                    del src_current[src_target]
                current[target] = item.copy()

    async def broadcast_block(self, index, previous_hash, timestamp, data, signature):
        block = {
            "index": index,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "data": json.dumps(data),
            "signature": signature
        }
        message = json.dumps({"type": "block", "block": block, "node_id": self.node_id})
        signature = self.sign_message(message)
        payload = json.dumps({"message": message, "signature": signature}).encode('utf-8')
        
        for peer_id, peer_info in self.trusted_peers.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_info["ip"], peer_info["port"]))
                sock.sendall(payload)
                sock.close()
            except Exception as e:
                logging.error(f"Failed to broadcast to {peer_id} at {peer_info['ip']}:{peer_info['port']}: {e}")

    async def sync_from_leader(self):
        leader_info = self.trusted_peers.get("leader")
        if not leader_info:
            logging.error("Leader not found in trusted peers for sync")
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((leader_info["ip"], leader_info["port"]))
            message = json.dumps({"type": "sync_request", "node_id": self.node_id})
            signature = self.sign_message(message)
            sock.sendall(json.dumps({"message": message, "signature": signature}).encode('utf-8'))
            data = sock.recv(4096)
            payload = json.loads(data.decode('utf-8'))
            message = json.loads(payload["message"])
            if not self.verify_message(payload["message"], payload["signature"], message["node_id"]):
                logging.error("Sync response signature verification failed")
                return
            blocks = message["blocks"]
            conn = mysql.connector.connect(**DB_CONFIG)
            c = conn.cursor()
            for block in blocks:
                c.execute('INSERT IGNORE INTO blocks (`index`, previous_hash, timestamp, data, signature) VALUES (%s, %s, %s, %s, %s)',
                         (block['index'], block['previous_hash'], block['timestamp'], block['data'], block['signature']))
                data = json.loads(block['data'])
                if block['index'] == 0:
                    self.file_system = data
                else:
                    self.apply_operation(data)
            conn.commit()
            conn.close()
            sock.close()
        except Exception as e:
            logging.error(f"Failed to sync from leader: {e}")

    async def listen_for_blocks(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 5001))
        server.listen(5)
        logging.info(f"Node {self.node_id} listening on port 5001")
        while True:
            client, addr = server.accept()
            data = client.recv(4096).decode('utf-8')
            payload = json.loads(data)
            message = json.loads(payload["message"])
            if not self.verify_message(payload["message"], payload["signature"], message["node_id"]):
                logging.error(f"Invalid signature from {addr}")
                client.close()
                continue
            
            if message["type"] == "block":
                block = message["block"]
                if self.verify_block(block['index'], block['previous_hash'], 
                                    block['timestamp'], json.loads(block['data']), block['signature']):
                    conn = mysql.connector.connect(**DB_CONFIG)
                    c = conn.cursor()
                    c.execute('INSERT IGNORE INTO blocks (`index`, previous_hash, timestamp, data, signature) VALUES (%s, %s, %s, %s, %s)',
                             (block['index'], block['previous_hash'], block['timestamp'], block['data'], block['signature']))
                    conn.commit()
                    conn.close()
                    self.apply_operation(json.loads(block['data']))
                    await self.broadcast_block(block['index'], block['previous_hash'], block['timestamp'], 
                                              json.loads(block['data']), block['signature'])
            elif message["type"] == "sync_request":
                conn = mysql.connector.connect(**DB_CONFIG)
                c = conn.cursor(dictionary=True)
                c.execute('SELECT * FROM blocks ORDER BY `index`')
                blocks = c.fetchall()
                response = json.dumps({"type": "sync_response", "blocks": blocks, "node_id": self.node_id})
                signature = self.sign_message(response)
                client.sendall(json.dumps({"message": response, "signature": signature}).encode('utf-8'))
                conn.close()
            client.close()

# Initialize private blockchain
blockchain = PrivateBlockchain()

# Helper functions
def get_path_dict(path):
    parts = path.strip("/").split("/")
    current = blockchain.file_system["root"]["contents"]
    for part in parts[:-1]:
        if part and part in current and current[part]["type"] == "directory":
            current = current[part]["contents"]
    return current, parts[-1] if parts else ""

def update_file_system(operation, path, data=None):
    current, target = get_path_dict(path)
    block_data = {"operation": operation, "path": path}
    
    if operation == "create_folder":
        current[target] = {"type": "directory", "contents": {}}
        block_data["type"] = "directory"
    elif operation == "upload_file":
        current[target] = {"type": "file", "content": data}
        block_data["content"] = data
    elif operation == "delete_file":
        if target in current and current[target]["type"] == "file":
            del current[target]
    elif operation == "delete_folder":
        if target in current and current[target]["type"] == "directory":
            del current[target]
    elif operation == "move" or operation == "copy":
        source_path = data["source"]
        src_current, src_target = get_path_dict(source_path)
        if src_target in src_current:
            item = src_current[src_target]
            if operation == "move":
                del src_current[src_target]
            current[target] = item.copy()
        block_data["source"] = source_path
    
    conn = mysql.connector.connect(**DB_CONFIG)
    c = conn.cursor(dictionary=True)
    c.execute('SELECT * FROM blocks ORDER BY `index` DESC LIMIT 1')
    previous_block = c.fetchone() or {"index": -1, "signature": "0"}
    index = previous_block['index'] + 1
    timestamp = datetime.now().isoformat()
    signature = blockchain.sign_block(index, previous_block['signature'], timestamp, block_data)
    c.execute('INSERT INTO blocks (`index`, previous_hash, timestamp, data, signature) VALUES (%s, %s, %s, %s, %s)',
             (index, previous_block['signature'], timestamp, json.dumps(block_data), signature))
    conn.commit()
    conn.close()
    
    asyncio.run(blockchain.broadcast_block(index, previous_block['signature'], timestamp, block_data, signature))

# Authentication helper
def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__  # Preserve the original function name
    return wrap

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor(dictionary=True)
        c.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
@login_required
def list_files():
    path = request.args.get('path', '')
    current, _ = get_path_dict(path)
    return jsonify(current)

@app.route('/api/create_folder', methods=['POST'])
@login_required
def create_folder():
    path = request.json.get('path')
    if not path:
        return jsonify({"error": "Path required"}), 400
    update_file_system("create_folder", path)
    return jsonify({"success": True})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    path = request.form.get('path')
    if not file or not path:
        return jsonify({"error": "File and path required"}), 400
    
    content = base64.b64encode(file.read()).decode('utf-8')
    update_file_system("upload_file", path, content)
    return jsonify({"success": True})

@app.route('/api/download', methods=['GET'])
@login_required
def download_file():
    path = request.args.get('path')
    current, target = get_path_dict(path)
    if target in current and current[target]["type"] == "file":
        content = base64.b64decode(current[target]["content"])
        return send_file(
            io.BytesIO(content),
            download_name=target,
            as_attachment=True
        )
    return jsonify({"error": "File not found"}), 404

@app.route('/api/delete_file', methods=['POST'])
@login_required
def delete_file():
    path = request.json.get('path')
    if not path:
        return jsonify({"error": "Path required"}), 400
    current, target = get_path_dict(path)
    if target in current and current[target]["type"] == "file":
        update_file_system("delete_file", path)
        return jsonify({"success": True})
    return jsonify({"error": "Not a file or does not exist"}), 404

@app.route('/api/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    path = request.json.get('path')
    if not path:
        return jsonify({"error": "Path required"}), 400
    current, target = get_path_dict(path)
    if target in current and current[target]["type"] == "directory":
        update_file_system("delete_folder", path)
        return jsonify({"success": True})
    return jsonify({"error": "Not a folder or does not exist"}), 404

@app.route('/api/move', methods=['POST'])
@login_required
def move_item():
    source = request.json.get('source')
    dest = request.json.get('dest')
    if not source or not dest:
        return jsonify({"error": "Source and destination required"}), 400
    update_file_system("move", dest, {"source": source})
    return jsonify({"success": True})

@app.route('/api/copy', methods=['POST'])
@login_required
def copy_item():
    source = request.json.get('source')
    dest = request.json.get('dest')
    if not source or not dest:
        return jsonify({"error": "Source and destination required"}), 400
    update_file_system("copy", dest, {"source": source})
    return jsonify({"success": True})

# HTML Templates
login_template = """
<!DOCTYPE html>
<html>
<head>
    <title>RCS Login</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Ryan's Cool Storage - Login</h1>
    <form method="post">
        <label>Username: <input type="text" name="username" required></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <input type="submit" value="Login">
    </form>
    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

index_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Ryan's Cool Storage (RCS)</title>
    <style>
        .folder { color: blue; cursor: pointer; }
        .file { color: black; cursor: pointer; }
        #path { margin-bottom: 10px; }
    </style>
</head>
<body>
    <div id="path">/</div>
    <p>Logged in as: {{ session['username'] }} | <a href="{{ url_for('logout') }}">Logout</a></p>
    <input type="file" id="fileInput">
    <button onclick="uploadFile()">Upload</button>
    <button onclick="createFolder()">New Folder</button>
    <div id="fileList"></div>

    <script>
        let currentPath = '';

        function updateFileList() {
            fetch('/api/files?path=' + currentPath)
                .then(res => res.json())
                .then(data => {
                    let html = '<ul>';
                    for (let [name, item] of Object.entries(data)) {
                        if (item.type === 'directory') {
                            html += `<li class="folder" onclick="navigate('${name}')">${name}/ <button onclick="deleteFolder('${name}')">Delete</button></li>`;
                        } else {
                            html += `<li class="file" onclick="download('${name}')">${name} <button onclick="deleteFile('${name}')">Delete</button></li>`;
                        }
                    }
                    html += '</ul>';
                    document.getElementById('fileList').innerHTML = html;
                    document.getElementById('path').textContent = '/' + currentPath;
                });
        }

        function navigate(folder) {
            currentPath = currentPath ? currentPath + '/' + folder : folder;
            updateFileList();
        }

        function createFolder() {
            let name = prompt('Folder name:');
            if (name) {
                fetch('/api/create_folder', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: currentPath + '/' + name})
                }).then(() => updateFileList());
            }
        }

        function uploadFile() {
            let file = document.getElementById('fileInput').files[0];
            if (file) {
                let formData = new FormData();
                formData.append('file', file);
                formData.append('path', currentPath + '/' + file.name);
                fetch('/api/upload', {method: 'POST', body: formData})
                    .then(() => updateFileList());
            }
        }

        function download(filename) {
            window.location = '/api/download?path=' + currentPath + '/' + filename;
        }

        function deleteFile(filename) {
            if (confirm('Are you sure you want to delete ' + filename + '?')) {
                fetch('/api/delete_file', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: currentPath + '/' + filename})
                }).then(() => updateFileList());
            }
        }

        function deleteFolder(foldername) {
            if (confirm('Are you sure you want to delete ' + foldername + ' and all its contents?')) {
                fetch('/api/delete_folder', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: currentPath + '/' + foldername})
                }).then(response => {
                    if (!response.ok) {
                        response.json().then(data => alert(data.error));
                    } else {
                        updateFileList();
                    }
                });
            }
        }

        updateFileList();
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    with open('templates/login.html', 'w') as f:
        f.write(login_template)
    with open('templates/index.html', 'w') as f:
        f.write(index_template)
    
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, lambda: asyncio.run(blockchain.listen_for_blocks()))
    app.run(host='0.0.0.0', port=5000, debug=True)
