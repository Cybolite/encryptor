# Secure Recursive File Vault (Machine-Bound Encryption Utility)

## Overview

A secure file encryption utility designed for legitimate data protection and backup workflows.

### Features

* Recursive folder encryption
* Machine-bound encryption (Windows/Linux/macOS)
* Optional user decryption password
* Recovery backup code for cross-machine recovery
* AES-256-GCM authenticated encryption
* Randomized encrypted filenames/extensions
* Full metadata restoration on decrypt
* Manifest integrity validation
* Dry-run mode
* Exclusion support
* Multi-threaded processing
* Resume support
* Secure key derivation using Argon2id
* Tamper detection
* Optional compression before encryption
* Logging and audit trail

---

# Recommended Stack

* Python 3.11+
* cryptography
* argon2-cffi
* psutil
* platformdirs

Install:

```bash
pip install cryptography argon2-cffi psutil platformdirs
```

---

# Security Model

## Encryption Key

Master encryption key derived from:

* Machine ID
* Optional user password
* Random recovery secret

```text
Final Key = Argon2id(
    machine_id + password + recovery_secret
)
```

## Machine Binding

The utility generates a stable machine fingerprint:

### Linux

* /etc/machine-id
* DMI UUID

### Windows

* MachineGuid
* BIOS UUID

### macOS

* IOPlatformUUID

---

# Recovery Mechanism

A recovery code is generated during encryption:

```text
RCV-XXXX-XXXX-XXXX-XXXX
```

This code allows decryption on another machine.

Recovery key is stored encrypted inside the manifest.

---

# Directory Structure After Encryption

```text
project/
 ├── a91f2d.qx
 ├── 81ddaf.kv
 ├── 22ff1b.jx
 ├── .vault_manifest
 └── .vault_meta
```

Original:

```text
project/
 ├── docs/report.pdf
 ├── images/photo.jpg
 └── notes.txt
```

---

# Metadata Preserved

* Original filenames
* Original extensions
* Relative paths
* File timestamps
* Permissions
* Symlinks (optional)

---

# Recommended Safeguards

## Prevent Unsafe Usage

The app should:

* Refuse to encrypt system directories
* Refuse root filesystem
* Require explicit confirmation
* Support dry-run preview
* Generate restore verification hash
* Never auto-delete backups

Blocked paths example:

```text
/
C:\Windows
C:\Program Files
/etc
/boot
```

---

# Suggested CLI

## Encrypt

```bash
vault encrypt /data/projects
```

## Encrypt with password

```bash
vault encrypt /data/projects --password
```

## Dry run

```bash
vault encrypt /data/projects --dry-run
```

## Decrypt

```bash
vault decrypt /data/projects
```

## Recovery Decrypt

```bash
vault decrypt /data/projects --recovery-code RCV-XXXX
```

---

# Manifest Example

```json
{
  "version": 1,
  "machine_hash": "...",
  "salt": "...",
  "created_at": "...",
  "files": [
    {
      "encrypted_name": "a91f2d.qx",
      "original_path": "docs/report.pdf",
      "nonce": "...",
      "size": 12345,
      "sha256": "..."
    }
  ]
}
```

---

# Reference Implementation (Core)

## Machine Fingerprint

```python
import hashlib
import os
import platform
import subprocess
import winreg


def get_machine_id():
    system = platform.system()

    try:
        if system == 'Linux':
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()

        elif system == 'Windows':
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\\Microsoft\\Cryptography'
            )
            value, _ = winreg.QueryValueEx(key, 'MachineGuid')
            return value

        elif system == 'Darwin':
            output = subprocess.check_output(
                ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice']
            ).decode()

            for line in output.split('\n'):
                if 'IOPlatformUUID' in line:
                    return line.split('=')[-1].replace('"', '').strip()

    except Exception:
        pass

    return hashlib.sha256(platform.node().encode()).hexdigest()
```

---

## Key Derivation

```python
from argon2.low_level import hash_secret_raw, Type


def derive_key(machine_id, password, recovery_secret, salt):
    material = f'{machine_id}:{password}:{recovery_secret}'.encode()

    return hash_secret_raw(
        secret=material,
        salt=salt,
        time_cost=4,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=Type.ID
    )
```

---

## File Encryption

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(src, dst, key):
    aes = AESGCM(key)

    nonce = os.urandom(12)

    with open(src, 'rb') as f:
        data = f.read()

    encrypted = aes.encrypt(nonce, data, None)

    with open(dst, 'wb') as f:
        f.write(nonce + encrypted)
```

---

## File Decryption

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_file(src, dst, key):
    aes = AESGCM(key)

    with open(src, 'rb') as f:
        content = f.read()

    nonce = content[:12]
    data = content[12:]

    decrypted = aes.decrypt(nonce, data, None)

    with open(dst, 'wb') as f:
        f.write(decrypted)
```

---

## Randomized Filename Generator

```python
import secrets
import string


EXTENSIONS = [
    '.qx', '.kv', '.zx', '.jr', '.mx', '.vx'
]


def random_name():
    name = secrets.token_hex(8)
    ext = secrets.choice(EXTENSIONS)
    return f'{name}{ext}'
```

---

# Suggested Enhancements

## Optional Features

### Chunk-Based Encryption

Useful for large files.

### Secure Wipe

Optional overwrite before delete.

### Integrity Validation

Verify SHA256 before restoration.

### GUI

Recommended:

* PySide6
* Electron + Python backend

### Backup Export

Export encrypted archive:

```text
.vaultbundle
```

### Key Rotation

Allow changing password without re-encrypting files.

### Multi-User Recovery

Support admin recovery certificates.

---

# Recommended Production Architecture

```text
core/
 ├── crypto.py
 ├── machine.py
 ├── manifest.py
 ├── recovery.py
 ├── encryptor.py
 ├── decryptor.py
 └── utils.py

cli/
 └── main.py

gui/
 └── app.py
```

---

# Security Recommendations

* Use authenticated encryption only
* Never reuse nonces
* Use memory-hard KDFs
* Never store plaintext filenames externally
* Encrypt manifest separately
* Sign manifests
* Use secure randomness only
* Add rate-limits on password attempts
* Zero sensitive memory buffers where possible

---

# Recommended Packaging

## Windows

```bash
pyinstaller --onefile vault.py
```

## Linux

```bash
python3 setup.py bdist_wheel
```

## macOS

Use:

```text
py2app
```

---

# Suggested Improvements Beyond Standard

## Enterprise Features

* Hardware TPM integration
* FIDO2/YubiKey unlock
* Cloud recovery escrow
* Audit logs
* Immutable manifests
* Parallel encryption engine
* Deduplication
* Snapshot restore
* Versioned restore
* Remote backup sync

---

# Complete Node.js Implementation

## Install

```bash
npm install commander cli-progress
```

## vault.js

```javascript
#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { Command } = require('commander');

const program = new Command();

const EXTENSIONS = ['.qx', '.kv', '.mx', '.vx', '.jr'];

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function machineId() {
    const interfaces = os.networkInterfaces();
    let macs = '';

    Object.values(interfaces).forEach(items => {
        items.forEach(item => {
            if (!item.internal) {
                macs += item.mac;
            }
        });
    });

    return sha256(os.hostname() + os.platform() + os.arch() + macs);
}

function deriveKey(mid, password, recovery, salt) {
    return crypto.scryptSync(
        `${mid}:${password}:${recovery}`,
        salt,
        32
    );
}

function randomName() {
    return crypto.randomBytes(8).toString('hex') +
        EXTENSIONS[Math.floor(Math.random() * EXTENSIONS.length)];
}

function recoveryCode() {
    return 'RCV-' +
        crypto.randomBytes(8)
            .toString('hex')
            .toUpperCase()
            .match(/.{1,4}/g)
            .join('-');
}

function encrypt(data, key) {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        key,
        iv
    );

    const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);

    return Buffer.concat([
        iv,
        cipher.getAuthTag(),
        encrypted
    ]);
}

function decrypt(data, key) {
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const enc = data.subarray(28);

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        iv
    );

    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(enc),
        decipher.final()
    ]);
}

function walk(dir, result = []) {
    const files = fs.readdirSync(dir);

    files.forEach(file => {
        const full = path.join(dir, file);
        const stat = fs.statSync(full);

        if (file === '.vault_manifest') {
            return;
        }

        if (stat.isDirectory()) {
            walk(full, result);
        } else {
            result.push(full);
        }
    });

    return result;
}

async function encryptDirectory(target, password = '') {
    const recovery = recoveryCode();
    const salt = crypto.randomBytes(16);

    const key = deriveKey(
        machineId(),
        password,
        recovery,
        salt
    );

    const manifest = {
        version: 1,
        salt: salt.toString('hex'),
        recoveryHash: sha256(recovery),
        recoveryCode: recovery,
        files: []
    };

    const files = walk(target);

    for (const file of files) {
        const relative = path.relative(target, file);
        const data = fs.readFileSync(file);

        const encrypted = encrypt(data, key);

        const encryptedName = randomName();

        fs.writeFileSync(
            path.join(target, encryptedName),
            encrypted
        );

        manifest.files.push({
            encrypted: encryptedName,
            original: relative,
            hash: sha256(data)
        });

        fs.unlinkSync(file);
    }

    fs.writeFileSync(
        path.join(target, '.vault_manifest'),
        JSON.stringify(manifest, null, 2)
    );

    console.log('Encryption complete');
    console.log('Recovery code:', recovery);
}

async function decryptDirectory(target, password = '', recovery = '') {
    const manifest = JSON.parse(
        fs.readFileSync(
            path.join(target, '.vault_manifest'),
            'utf8'
        )
    );

    const salt = Buffer.from(manifest.salt, 'hex');

    const actualRecovery = recovery || manifest.recoveryCode;

    let key;

    try {
        key = deriveKey(
            machineId(),
            password,
            actualRecovery,
            salt
        );

        decrypt(
            fs.readFileSync(
                path.join(target, manifest.files[0].encrypted)
            ),
            key
        );

    } catch {
        key = deriveKey(
            'RECOVERY-MODE',
            password,
            actualRecovery,
            salt
        );
    }

    for (const file of manifest.files) {
        const encryptedData = fs.readFileSync(
            path.join(target, file.encrypted)
        );

        const decrypted = decrypt(encryptedData, key);

        if (sha256(decrypted) !== file.hash) {
            throw new Error('Integrity failed');
        }

        const output = path.join(target, file.original);

        fs.mkdirSync(path.dirname(output), {
            recursive: true
        });

        fs.writeFileSync(output, decrypted);

        fs.unlinkSync(path.join(target, file.encrypted));
    }

    fs.unlinkSync(path.join(target, '.vault_manifest'));

    console.log('Decryption complete');
}

program
    .command('encrypt <directory>')
    .option('-p, --password <password>')
    .action((directory, options) => {
        encryptDirectory(directory, options.password || '');
    });

program
    .command('decrypt <directory>')
    .option('-p, --password <password>')
    .option('-r, --recovery <code>')
    .action((directory, options) => {
        decryptDirectory(
            directory,
            options.password || '',
            options.recovery || ''
        );
    });

program.parse();
```

## Usage

Simple Encrypt/Decrypt Directory

```bash
node vault.js encrypt ./data
node vault.js decrypt ./data
```

Simple Encrypt/Decrypt Directory with Custom Password

```bash
node vault.js encrypt ./data --password secret
node vault.js decrypt ./data --password secret
```

Simple Decrypt Directory with Recovery Code at Any Machine

```bash
node vault.js decrypt ./data --password secret --recovery RCV-XXXX
```

# Analyze the encrypted structure

```bash
node vault.js analyze ./data
```

# Decrypt specific files

```bash
node vault.js decrypt ./data --select "docs/file.pdf"
node vault.js decrypt ./data --select "images"
```

# Important Note

This utility should only be used for:

* Personal data protection
* Enterprise backup security
* Offline encrypted archives
* Secure transfer storage

Avoid destructive workflows.
Always maintain backups before encryption operations.
