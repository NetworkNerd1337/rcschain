# Ryan's Cool Storage (RCS) Blockchain

This project implements a multi-node, quantum-resistant blockchain-based file storage system named **Ryan's Cool Storage (RCS)**, utilizing the Falcon-512 signature scheme from PQClean for both blockchain integrity and peer authentication. It features a Flask-based web interface with comprehensive user management, MySQL for persistent storage, and a secure peer-to-peer network with dynamic discovery via an encrypted Distributed Hash Table (DHT).

## Features
- **Quantum Resistance**: Uses Falcon-512 for post-quantum cryptographic signatures and authentication.
- **Optimized Signatures**: Falcon-512 signatures (~666 bytes) are compressed with zlib (~400-500 bytes) for network efficiency.
- **Multi-Node Support**: Nodes synchronize blocks via a DHT-based network with dynamic peer discovery.
- **Encrypted DHT**: Peer data (IP, port, public key) is encrypted with AES-GCM for privacy.
- **User Authentication**: Requires login to access the web UI, with usernames and bcrypt-hashed passwords stored in MySQL.
- **Full User Management**: Users can register, delete other users (except themselves), and change their passwords via the UI.
- **Web Interface**: Authenticated users can upload, download, create folders, delete files/folders (recursively), move, and copy files/folders via a browser.
- **Persistence**: Stores blockchain data in MySQL with node-specific databases (e.g., `rcschain_db_node1`), with in-memory file system reconstruction on startup.
- **Security**: Only trusted nodes with the shared DHT encryption key can join and decipher peer data; UI access is restricted to authenticated users.

## Prerequisites
- **Operating System**: Ubuntu 20.04+ or another Debian-based distribution.
- **Hardware**: Minimum 2GB RAM, multi-core CPU recommended for multiple nodes.
- **Dependencies**:
  - Python 3.8+
  - MySQL Server 8.0+
  - GCC (for compiling PQClean Falcon library)
  - Required Python packages (listed below)

### Required Packages
Install the following system packages:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev mysql-server mysql-client libmysqlclient-dev build-essential libssl-dev git
```
TIP: You'll need to decide if you'll install into a virtual Python environment, or install system-wide using 
```--break-system-packages```. The proper way to do this would be through a virtual environment. However, for this guide, we assume the installation is on a purpose-built system not shared with anything else so we will use system-wide dependencies.

# Installation

## Step 1: Clone the Repository
```bash
git clone https://github.com/NetworkNerd1337/rcschain.git
cd rcschain
```
## Step 2: Install PQClean and Compile Falcon Library

### 1. Clone PQClean:
```bash
git clone https://github.com/PQClean/PQClean.git
cd PQClean
```
### 2. Compile Falcon-512 into a shared library:
```bash
gcc -shared -fPIC -o libfalcon.so \
    crypto_sign/falcon-512/clean/*.c \
    common/*.c \
    -I common -I crypto_sign/falcon-512
```
### 3. Move the library to a system path:
```bash
sudo mv libfalcon.so /usr/local/lib/
sudo ldconfig
cd ..
```
## Step 3: Set Up MySQL

### 1. Secure MySQL installation:
```bash
sudo mysql_secure_installation
```
TIP: This will run a script to set up MySQL more securely for you. Often, these particular settings (like allowing remote root login) are left open/misconfigured, resulting in an unexpectedly vulnerable and less-than-secure installation of MySQL. Please consider using the default answers to this script, and at least medium password complexity.

### 2. Log in to MySQL as root:
```bash
sudo mysql -u root -p
```
### 3. Create a user and database prefix:
```bash
CREATE USER 'blockchain_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON rcschain_db_.* TO 'blockchain_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
TIP: The script uses databases like rcschain_db_leader, rcschain_db_node1, etc., based on the NODE_ID. The wildcard (rcschain_db_*) ensures access to all such databases.

## Step 4: Configure the Script

### 1. Make a backup copy of the script in the project directory:
```bash
cp rcschain.py rcschain_original.py
```
### 2. Edit rcschain.py to set your MySQL password and (optionally) DHT encryption key:
```bash
DB_CONFIG = {
    'user': 'blockchain_user',
    'password': 'your_secure_password',  # Replace with your password
    'host': 'localhost',
    'database': f'rcschain_db_{NODE_ID}',
    'raise_on_warnings': True
}
DHT_ENCRYPTION_KEY = b'SecretKeyForRCSChain1234567890AB'  # Replace with a secure 32-byte key
```
TIP: The default DHT Key key is for demonstration. Replace it with a unique, secure 32-byte key shared among trusted nodes.

# Usage

## Single Node (Bootstrap Node)

### 1. Run the script as the bootstrap node (e.g., leader):
```bash
export NODE_ID="leader"
export BOOTSTRAP_IP="192.168.1.100"  # Replace with this node’s IP
export BOOTSTRAP_PORT=8468
export LOCAL_DHT_PORT=8468
python3 rcschain.py
```
### 2. Access the web interface:
- Open http://192.168.1.100:5000 in a browser.
- Log in with default credentials: admin:password.
- Use the UI to manage files/folders or users:
	- Register: Click "Register" on the login page to create a new user.
	- Manage Users: From the main UI, click "Manage Users" to list and delete users.
	- Change Password: Click "Change Password" to update your password.
	- File Operations: Upload files, create folders, delete files/folders recursively, etc.
- Log out via the link in the UI.

## Multi-Node Setup

### Prerequisites
- Multiple machines or ports on one machine.
- A bootstrap node (e.g., the leader) must be running first.
- All nodes must share the same DHT_ENCRYPTION_KEY.

### Start the Bootstrap Node
- See "Single Node" above.

### Start Follower Nodes
- Node 1:
```bash
export NODE_ID="node1"
export BOOTSTRAP_IP="192.168.1.100"  # Leader’s IP
export BOOTSTRAP_PORT=8468
export LOCAL_DHT_PORT=8469
python3 rcschain.py
```
- Node 2:
```bash
export NODE_ID="node2"
export BOOTSTRAP_IP="192.168.1.100"
export BOOTSTRAP_PORT=8468
export LOCAL_DHT_PORT=8470
python3 rcschain.py
```
## Verify Multi-Node Operation
- Access any node’s UI (e.g., http://192.168.1.100:5000).
- Log in with admin:password.
- Upload a file, create a folder with subcontents, or delete a folder recursively.
- Check other nodes (e.g., http://<node1-ip>:5000) after logging in to ensure actions sync.

## User Management
- Default User: admin:password is created on first run.
- Register New Users:
	- From the login page, click "Register".
	- Enter a username, password (min 8 characters), and confirm password.
	- Submit to create the account and return to login.
- Delete Users:
	- Log in, click "Manage Users" from the main UI.
	- Select a user (except yourself) and click "Delete".
- Change Password:
	- Log in, click "Change Password".
	- Enter current password, new password (min 8 characters), and confirm.
	- Submit to update your password.
- Manual Database Management (optional):
```bash
mysql -u blockchain_user -p rcschain_db_<NODE_ID>
```
```sql
-- Add user manually
INSERT INTO users (username, password_hash)
VALUES ('newuser', '$2b$12$...'); -- Replace with bcrypt hash
-- Generate hash
python3 -c "import bcrypt; print(bcrypt.hashpw('your_password'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))"
```
# Peer Exchange Mechanism
- Dynamic Discovery: Nodes use a Kademlia DHT for peer discovery. The bootstrap node (e.g., leader) initializes the DHT network.
- Encrypted DHT: Peer data (IP, port, Falcon public key) is encrypted with AES-GCM using a shared key, ensuring privacy.
- Authentication: Nodes verify messages with Falcon-512 signatures.
- Adding a New Node:
	- Ensure the new node has the same DHT_ENCRYPTION_KEY as existing nodes.
	- Start the new node with a unique NODE_ID and connect to the bootstrap node:
	```bash
	export NODE_ID="node3"
	export BOOTSTRAP_IP="192.168.1.100"
	export BOOTSTRAP_PORT=8468
	export LOCAL_DHT_PORT=8471
	python3 rcschain.py
	```
	- The node auto-registers in the DHT; existing nodes discover it within 60 seconds if they have the key.
- Removing a Node: Stop the node. It will no longer respond to DHT queries, and peers will eventually timeout.

# Troubleshooting
- Database Errors: Ensure MySQL is running (sudo systemctl status mysql) and credentials match DB_CONFIG. Each node uses a unique database (e.g., rcschain_db_node1).
- Networking Issues: Check firewall (sudo ufw allow 5000/tcp; sudo ufw allow 5001/tcp; sudo ufw allow 8468-8471/tcp).
- DHT Failures: Ensure the bootstrap node is running and reachable, and all nodes use the same DHT_ENCRYPTION_KEY. Check blockchain.log for decryption errors:
```bash
cat blockchain.log
```
- Authentication Issues: Verify username/password with MySQL data. Reset by dropping the users table and restarting:
```bash
mysql -u blockchain_user -p rcschain_db_<NODE_ID> -e "DROP TABLE users;"
```
- Reset Chain: To start fresh:
```bash
rm falcon_keys_*.bin falcon_auth_keys_*.bin
mysql -u blockchain_user -p -e "DROP DATABASE rcschain_db_$NODE_ID;"
```
# Security Notes
- Debug Mode: debug=True is for development only. Use a WSGI server (e.g., Gunicorn) for production:
```bash
pip3 install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 rcschain:app
```
- Key Protection: Secure falcon_keys_*.bin and falcon_auth_keys_*.bin:
```bash
chmod 600 falcon_keys_*.bin falcon_auth_keys_*.bin
```
- DHT Encryption: The DHT_ENCRYPTION_KEY must be shared securely among trusted nodes. Hardcoding is for demo only; use a key management system in production.
- Session Security: The Flask secret key is randomly generated per run. For production, set a fixed, secure value via an environment variable:
```bash
export FLASK_SECRET_KEY="your_secure_key_here"
```
Then update rcschain.py: app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

# Future Enhancements
- Implement dynamic key derivation for DHT encryption (e.g., via key exchange).
- Add a full consensus algorithm (e.g., Raft) for decentralized operation.
- Enhance user management with roles (e.g., admin vs. regular users).
- Batch operations to further reduce signature overhead.
- Refactoring into a distributed OO application rather than a single procedural file

Contributing
Pull requests are welcome! Please test changes on a multi-node setup with authentication before submitting.
