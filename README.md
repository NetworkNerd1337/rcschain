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
