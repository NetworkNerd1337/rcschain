from flask import Flask, render_template, request, send_file, jsonify
import os
from datetime import datetime
import base64
import mysql.connector
import json
import io
import ctypes
import socket
import threading
import queue
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO, filename='blockchain.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load the Falcon shared library for blockchain signatures
falcon_lib = ctypes.CDLL("/usr/local/lib/libfalcon.so")

# Define Falcon function signatures
falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair.restype = ctypes.c_int

falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign.restype = ctypes.c_int

falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte)
]
falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open.restype = ctypes.c_int

# Constants
CRYPTO_PUBLICKEYBYTES = 1793
CRYPTO_SECRETKEYBYTES = 2305
CRYPTO_BYTES = 1330

# Node configuration
NODE_ID = os.getenv("NODE_ID", "node1")
LEADER_IP = os.getenv("LEADER_IP", "127.0.0.1")
LEADER_PORT = int(os.getenv("LEADER_PORT", 5001))
LOCAL_PORT = int(os.getenv("LOCAL_PORT", 5001))

# MySQL database configuration
DB_CONFIG = {
    'user': 'blockchain_user',
    'password': 'your_password',  # Replace with your actual password
    'host': 'localhost',
    'database': f'rschain_db_{NODE_ID}',
    'raise_on_warnings': True
}

# Queue for incoming blocks
block_queue = queue.Queue()

# Authentication keys
def generate_auth_keys(node_id):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    with open(f"auth_private_{node_id}.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"auth_public_{node_id}.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def load_auth_keys(node_id):
    try:
        with open(f"auth_private_{node_id}.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(f"auth_public_{node_id}.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        return private_key, public_key
    except FileNotFoundError:
        return generate_auth_keys(node_id)

# Database setup
def init_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    c = conn.cursor()
    
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
    
    try:
        c.execute('CREATE INDEX idx_signature ON blocks (signature(255))')
    except mysql.connector.Error as e:
        if e.errno != 1061:
            raise
    
    try:
        c.execute('CREATE INDEX idx_timestamp ON blocks (timestamp(255))')
    except mysql.connector.Error as e:
        if e.errno != 1061:
            raise
    
    try:
        c.execute('CREATE INDEX idx_prev_hash ON blocks (previous_hash(255))')
    except mysql.connector.Error as e:
        if e.errno != 1061:
            raise
    
    conn.commit()
    conn.close()

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
        # Load or generate Falcon keys for blockchain
        key_file = f"falcon_keys_{self.node_id}.bin"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                pk_data = f.read(CRYPTO_PUBLICKEYBYTES)
                sk_data = f.read(CRYPTO_SECRETKEYBYTES)
            self.pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES).from_buffer_copy(pk_data)
            self.sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES).from_buffer_copy(sk_data)
        else:
            self.pk = (ctypes.c_ubyte * CRYPTO_PUBLICKEYBYTES)()
            self.sk = (ctypes.c_ubyte * CRYPTO_SECRETKEYBYTES)()
            if falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(self.pk, self.sk) != 0:
                raise RuntimeError("Failed to generate Falcon key pair")
            with open(key_file, "wb") as f:
                f.write(bytes(self.pk))
                f.write(bytes(self.sk))
        
        # Load or generate RSA keys for authentication
        self.auth_private_key, self.auth_public_key = load_auth_keys(self.node_id)
        
        # Trusted peers (public keys of authorized nodes)
        self.trusted_peers = {}
        for peer_id in ["leader", "node1", "node2"]:  # Add your node IDs
            with open(f"auth_public_{peer_id}.pem", "rb") as f:
                self.trusted_peers[peer_id] = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        self.file_system = {}
        self.init_storage()
        self.start_networking()
        if not self.load_chain():
            self.create_genesis_block()

    def init_storage(self):
        init_db()

    def sign_block(self, index, previous_hash, timestamp, data):
        message = str(index) + previous_hash + timestamp + str(data)
        msg_bytes = message.encode('utf-8')
        msg_len = len(msg_bytes)
        
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + msg_len))()
        smlen = ctypes.c_size_t(0)
        
        falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign(
            sm, ctypes.byref(smlen), 
            msg_bytes, msg_len, 
            self.sk
        )
        signature = bytes(sm[:CRYPTO_BYTES])
        return base64.b64encode(signature).decode('utf-8')

    def verify_block(self, index, previous_hash, timestamp, data, signature):
        message = str(index) + previous_hash + timestamp + str(data)
        msg_bytes = message.encode('utf-8')
        msg_len = ctypes.c_size_t(len(msg_bytes))
        
        signature_bytes = base64.b64decode(signature)
        sm = (ctypes.c_ubyte * (CRYPTO_BYTES + len(msg_bytes)))()
        for i, byte in enumerate(signature_bytes + msg_bytes):
            sm[i] = byte
        smlen = ctypes.c_size_t(len(signature_bytes) + len(msg_bytes))
        
        m = (ctypes.c_ubyte * len(msg_bytes))()
        mlen = ctypes.c_size_t(0)
        
        result = falcon_lib.PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open(
            m, ctypes.byref(mlen), 
            sm, smlen, 
            self.pk
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
        self.broadcast_block(0, "0", timestamp, genesis_data, signature)

    def load_chain(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        c = conn.cursor(dictionary=True)
        c.execute('SELECT * FROM blocks ORDER BY `index`')
        blocks = c.fetchall()
        conn.close()

        if not blocks:
            if self.node_id != "leader":
                self.sync_from_leader()
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
        elif operation in ["delete_file", "delete_folder"]:
            if target in current:
                if (operation == "delete_file" and current[target]["type"] == "file") or \
                   (operation == "delete_folder" and current[target]["type"] == "directory" and not current[target]["contents"]):
                    del current[target]
        elif operation == "move" or operation == "copy":
            source_path = data["source"]
            src_current, src_target = get_path_dict(source_path)
            if src_target in src_current:
                item = src_current[src_target]
                if operation == "move":
                    del src_current[src_target]
                current[target] = item.copy()

    def sign_message(self, message):
        return self.auth_private_key.sign(
            message.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def verify_message(self, message, signature, peer_id):
        if peer_id not in self.trusted_peers:
            return False
        try:
            self.trusted_peers[peer_id].verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def broadcast_block(self, index, previous_hash, timestamp, data, signature):
        block = {
            "index": index,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "data": json.dumps(data),
            "signature": signature
        }
        message = json.dumps({"type": "block", "block": block, "node_id": self.node_id})
        signature = base64.b64encode(self.sign_message(message)).decode('utf-8')
        payload = json.dumps({"message": message, "signature": signature}).encode('utf-8')
        
        if self.node_id == "leader":
            for peer in self.peers:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((peer[0], peer[1]))
                    sock.sendall(payload)
                    sock.close()
                except Exception as e:
                    logging.error(f"Failed to broadcast to {peer}: {e}")
        else:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((LEADER_IP, LEADER_PORT))
                sock.sendall(payload)
                sock.close()
            except Exception as e:
                logging.error(f"Failed to send to leader {LEADER_IP}:{LEADER_PORT}: {e}")

    def sync_from_leader(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((LEADER_IP, LEADER_PORT))
            message = json.dumps({"type": "sync_request", "node_id": self.node_id})
            signature = base64.b64encode(self.sign_message(message)).decode('utf-8')
            sock.sendall(json.dumps({"message": message, "signature": signature}).encode('utf-8'))
            data = sock.recv(4096)
            payload = json.loads(data.decode('utf-8'))
            message = json.loads(payload["message"])
            if not self.verify_message(payload["message"], base64.b64decode(payload["signature"]), message["node_id"]):
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

    def start_networking(self):
        self.peers = [("192.168.1.101", 5001), ("192.168.1.102", 5001)] if self.node_id == "leader" else []
        threading.Thread(target=self.listen_for_blocks, daemon=True).start()

    def listen_for_blocks(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', LOCAL_PORT))
        server.listen(5)
        logging.info(f"Node {self.node_id} listening on port {LOCAL_PORT}")
        while True:
            client, addr = server.accept()
            data = client.recv(4096).decode('utf-8')
            payload = json.loads(data)
            message = json.loads(payload["message"])
            if not self.verify_message(payload["message"], base64.b64decode(payload["signature"]), message["node_id"]):
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
                    if self.node_id == "leader":
                        self.broadcast_block(block['index'], block['previous_hash'], block['timestamp'], 
                                            json.loads(block['data']), block['signature'])
            elif message["type"] == "sync_request" and self.node_id == "leader":
                conn = mysql.connector.connect(**DB_CONFIG)
                c = conn.cursor(dictionary=True)
                c.execute('SELECT * FROM blocks ORDER BY `index`')
                blocks = c.fetchall()
                response = json.dumps({"type": "sync_response", "blocks": blocks, "node_id": self.node_id})
                signature = base64.b64encode(self.sign_message(response)).decode('utf-8')
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
        if target in current and current[target]["type"] == "directory" and not current[target]["contents"]:
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
    
    blockchain.broadcast_block(index, previous_block['signature'], timestamp, block_data, signature)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def list_files():
    path = request.args.get('path', '')
    current, _ = get_path_dict(path)
    return jsonify(current)

@app.route('/api/create_folder', methods=['POST'])
def create_folder():
    path = request.json.get('path')
    if not path:
        return jsonify({"error": "Path required"}), 400
    update_file_system("create_folder", path)
    return jsonify({"success": True})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    path = request.form.get('path')
    if not file or not path:
        return jsonify({"error": "File and path required"}), 400
    
    content = base64.b64encode(file.read()).decode('utf-8')
    update_file_system("upload_file", path, content)
    return jsonify({"success": True})

@app.route('/api/download', methods=['GET'])
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
def delete_folder():
    path = request.json.get('path')
    if not path:
        return jsonify({"error": "Path required"}), 400
    current, target = get_path_dict(path)
    if target in current and current[target]["type"] == "directory":
        if current[target]["contents"]:
            return jsonify({"error": "Folder is not empty"}), 400
        update_file_system("delete_folder", path)
        return jsonify({"success": True})
    return jsonify({"error": "Not a folder or does not exist"}), 404

@app.route('/api/move', methods=['POST'])
def move_item():
    source = request.json.get('source')
    dest = request.json.get('dest')
    if not source or not dest:
        return jsonify({"error": "Source and destination required"}), 400
    update_file_system("move", dest, {"source": source})
    return jsonify({"success": True})

@app.route('/api/copy', methods=['POST'])
def copy_item():
    source = request.json.get('source')
    dest = request.json.get('dest')
    if not source or not dest:
        return jsonify({"error": "Source and destination required"}), 400
    update_file_system("copy", dest, {"source": source})
    return jsonify({"success": True})

# HTML Template
html_template = """
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
            if (confirm('Are you sure you want to delete ' + foldername + '?')) {
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
    with open('templates/index.html', 'w') as f:
        f.write(html_template)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
