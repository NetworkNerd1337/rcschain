# Quantum-Resistant Blockchain File Storage

This project implements a multi-node, quantum-resistant blockchain-based file storage system using the Falcon-Padded-1024 signature scheme from PQClean. It features a Flask-based web interface for file and folder management, MySQL for persistent storage, and a secure peer-to-peer authentication mechanism to ensure only trusted nodes can join the network.

## Features
- **Quantum Resistance**: Uses Falcon-Padded-1024 for post-quantum cryptographic signatures.
- **Multi-Node Support**: Nodes synchronize blocks via a leader-based network, with RSA-based authentication.
- **Web Interface**: Upload, download, create folders, move, copy, and delete files/folders via a browser.
- **Persistence**: Stores blockchain data in MySQL, with in-memory file system reconstruction on startup.
- **Security**: Only authorized nodes can join via pre-shared RSA public keys.

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
Install python packages:
```bash
pip3 install flask mysql-connector-python cryptography
```
# Installation

## Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/quantum-blockchain-storage.git
cd quantum-blockchain-storage
```
## Step 2: Install PQClean and Compile Falcon Library

### 1. Clone PQClean:
```bash
git clone https://github.com/PQClean/PQClean.git
cd PQClean
```
### 2. Compile Falcon-Padded-1024 into a shared library:
```bash
gcc -shared -fPIC -o libfalcon.so \
    crypto_sign/falcon-padded-1024/*.c \
    common/*.c \
    -I common -I crypto_sign/falcon-padded-1024
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
### 2. Log in to MySQL as root:
```bash
sudo mysql -u root -p
```
### 3. Create a user and database prefix:
```bash
CREATE USER 'blockchain_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON blockchain_db_*.* TO 'blockchain_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
## Step 4: Configure the Script

### 1. Copy the script to your project directory:
```bash
cp rcschain.py .
```
### 2. Edit rcschain.py to set your MySQL password:
```bash
DB_CONFIG = {
    'user': 'blockchain_user',
    'password': 'your_secure_password',  # Replace with your password
    'host': 'localhost',
    'database': f'blockchain_db_{NODE_ID}',
    'raise_on_warnings': True
}
```
### 3. Update the peers list in start_networking with your node IPs/ports (e.g., ("192.168.1.101", 5002)).

# Usage

## Single Node

### 1. Run the script:
```bash
export NODE_ID="leader"
export LEADER_IP="127.0.0.1"
export LEADER_PORT=5001
export LOCAL_PORT=5001
python3 blockchain_storage.py
```
### 2. Access the web interface:
- Open HTTP://127.0.0.1:5000 in a browser.
- Use the UI to upload files, create folders, etc.

## Multi-Node Setup

### Prerequisites
- Multiple machines or ports on one machine.
- Each node needs the public keys of all trusted peers.

### Generate Authentication Keys

### 1. Generate keys for each node:
```bash
export NODE_ID="leader"
python3 blockchain_storage.py  # Creates auth_private_leader.pem, auth_public_leader.pem
export NODE_ID="node1"
python3 blockchain_storage.py  # Creates auth_private_node1.pem, auth_public_node1.pem
export NODE_ID="node2"
python3 blockchain_storage.py  # Creates auth_private_node2.pem, auth_public_node2.pem
```
### 2. Distribute public keys:
- Copy auth_public_leader.pem, auth_public_node1.pem, and auth_public_node2.pem to each node’s directory.

## Start the Leader Node
```bash
export NODE_ID="leader"
export LEADER_IP="192.168.1.100"  # Replace with leader’s IP
export LEADER_PORT=5001
export LOCAL_PORT=5001
python3 blockchain_storage.py
```
## Start Follower Nodes
- Node 1:
```bash
export NODE_ID="node1"
export LEADER_IP="192.168.1.100"
export LEADER_PORT=5001
export LOCAL_PORT=5002
python3 blockchain_storage.py
```
- Node 2:
```bash
export NODE_ID="node2"
export LEADER_IP="192.168.1.100"
export LEADER_PORT=5001
export LOCAL_PORT=5003
python3 blockchain_storage.py
```

## Verify Multi-Node Operation
- Access any node’s UI (e.g., http://192.168.1.100:5000).
- Upload a file or create a folder.
- Check other nodes (e.g., http://192.168.1.101:5002) to ensure the action syncs.

# Peer Exchange Mechanism
- **Trusted Peers:** The leader node maintains a list of authorized peers in self.trusted_peers. Only nodes with matching public keys can join.
- **Adding a New Node:**
  - Generate keys for the new node (e.g., node3):
  ```bash
  export NODE_ID="node3"
  python3 blockchain_storage.py
  ```
  - Copy auth_public_node3.pem to all existing nodes.
  - Update self.trusted_peers in the script on all nodes to include node3.
  - Update self.peers in start_networking on the leader with the new node’s IP/port (e.g., ("192.168.1.103", 5004)).
  - Start the new node:
  ```bash
  export NODE_ID="node3"
  export LEADER_IP="192.168.1.100"
  export LEADER_PORT=5001
  export LOCAL_PORT=5004
  python3 blockchain_storage.py
  ```
  - **Removing a Node:** Remove its public key from self.trusted_peers and its IP/port from self.peers on all nodes.

# Troubleshooting

- **Database Errors:** Ensure MySQL is running (sudo systemctl status mysql) and credentials match DB_CONFIG.
- **Networking Issues:** Check firewall (sudo ufw allow 5000/tcp; sudo ufw allow 5001/tcp).
- **Authentication Failures:** Verify public keys are correctly distributed and match self.trusted_peers. Check blockchain.log:
```bash
cat blockchain.log
```
- **Reset Chain:** To start fresh:
```bash
rm falcon_keys_*.bin auth_private_*.pem auth_public_*.pem
mysql -u blockchain_user -p -e "DROP DATABASE blockchain_db_$NODE_ID;"
```

# Security Notes
- **Debug Mode:** debug=True is for development only. Use a WSGI server (e.g., Gunicorn) for production:
```bash
pip3 install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 blockchain_storage:app
```
- **Key Protection:** Secure auth_private_*.pem and falcon_keys_*.bin:
```bash
chmod 600 auth_private_*.pem falcon_keys_*.bin
```

# Future Enhancements
- Replace RSA with Falcon for post-quantum peer authentication in Multi-Node deployments.
- Implement dynamic peer discovery (e.g., via a DHT).
- Add a consensus algorithm (e.g., Raft) for decentralized operation.
- Much more UI development

# Contributing
Pull requests are welcome! Please test changes on a multi-node setup before submitting.
