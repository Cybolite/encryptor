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