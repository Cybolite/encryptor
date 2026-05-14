#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { Command } = require('commander');

const program = new Command();

const MANIFEST_FILE = 'vault.manifest.json';

const EXTENSIONS = [
    '.qx',
    '.kv',
    '.mx',
    '.vx',
    '.jr'
];

function sha256File(file) {

    return new Promise((resolve, reject) => {

        const hash = crypto.createHash('sha256');

        const stream = fs.createReadStream(file);

        stream.on('data', chunk => hash.update(chunk));

        stream.on('end', () => {
            resolve(hash.digest('hex'));
        });

        stream.on('error', reject);
    });
}

function sha256(data) {
    return crypto.createHash('sha256')
        .update(data)
        .digest('hex');
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

    return sha256(
        os.hostname() +
        os.platform() +
        os.arch() +
        macs
    );
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

function walk(dir, result = []) {

    const files = fs.readdirSync(dir);

    files.forEach(file => {

        const full = path.join(dir, file);

        const stat = fs.statSync(full);

        if (file === MANIFEST_FILE) {
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

function encryptFile(input, output, key) {

    return new Promise((resolve, reject) => {

        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        const inputStream = fs.createReadStream(input);

        const outputStream = fs.createWriteStream(output);

        outputStream.write(iv);

        inputStream
            .pipe(cipher)
            .pipe(outputStream);

        outputStream.on('finish', () => {

            const tag = cipher.getAuthTag();

            fs.appendFileSync(output, tag);

            resolve();
        });

        inputStream.on('error', reject);

        outputStream.on('error', reject);
    });
}

function decryptFile(input, output, key) {

    return new Promise((resolve, reject) => {

        const stat = fs.statSync(input);

        const fd = fs.openSync(input, 'r');

        const iv = Buffer.alloc(12);

        const tag = Buffer.alloc(16);

        fs.readSync(fd, iv, 0, 12, 0);

        fs.readSync(
            fd,
            tag,
            0,
            16,
            stat.size - 16
        );

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        decipher.setAuthTag(tag);

        const inputStream = fs.createReadStream(input, {
            start: 12,
            end: stat.size - 17
        });

        const outputStream = fs.createWriteStream(output);

        inputStream
            .pipe(decipher)
            .pipe(outputStream);

        outputStream.on('finish', resolve);

        inputStream.on('error', reject);

        outputStream.on('error', reject);
    });
}

function filterManifestFiles(manifest, targetPath) {

    return manifest.files.filter(file => {

        return (
            file.original === targetPath ||
            file.original.startsWith(
                targetPath + path.sep
            )
        );
    });
}

function showManifestTree(manifest) {

    const tree = {};

    for (const file of manifest.files) {

        const parts = file.original.split(path.sep);

        let current = tree;

        parts.forEach((part, index) => {

            if (!current[part]) {

                current[part] = index === parts.length - 1
                    ? '__FILE__'
                    : {};
            }

            current = current[part];
        });
    }

    function printTree(obj, prefix = '') {

        for (const key in obj) {

            console.log(prefix + '├── ' + key);

            if (obj[key] !== '__FILE__') {

                printTree(
                    obj[key],
                    prefix + '│   '
                );
            }
        }
    }

    printTree(tree);
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
        recoveryCode: recovery,
        files: []
    };

    const files = walk(target);

    for (const file of files) {

        const relative = path.relative(target, file);

        const encryptedName = randomName();

        const encryptedPath = path.join(
            target,
            encryptedName
        );

        await encryptFile(
            file,
            encryptedPath,
            key
        );

        const hash = await sha256File(file);

        manifest.files.push({
            encrypted: encryptedName,
            original: relative,
            hash
        });

        fs.unlinkSync(file);

        console.log('Encrypted:', relative);
    }

    fs.writeFileSync(
        path.join(target, MANIFEST_FILE),
        JSON.stringify(manifest, null, 2)
    );

    console.log('\nEncryption complete');
    console.log('Recovery Code:', recovery);
}

async function decryptDirectory(
    target,
    password = '',
    recovery = '',
    targetSelection = ''
) {

    const manifestPath = path.join(
        target,
        MANIFEST_FILE
    );

    if (!fs.existsSync(manifestPath)) {

        throw new Error(
            'Manifest not found'
        );
    }

    const manifest = JSON.parse(
        fs.readFileSync(
            manifestPath,
            'utf8'
        )
    );

    const actualRecovery =
        recovery || manifest.recoveryCode;

    const salt = Buffer.from(
        manifest.salt,
        'hex'
    );

    let key;

    try {

        key = deriveKey(
            machineId(),
            password,
            actualRecovery,
            salt
        );

        const testFile = manifest.files[0];

        const tmp = path.join(
            os.tmpdir(),
            'vault_test.tmp'
        );

        await decryptFile(
            path.join(
                target,
                testFile.encrypted
            ),
            tmp,
            key
        );

        fs.unlinkSync(tmp);

    } catch {

        key = deriveKey(
            'RECOVERY-MODE',
            password,
            actualRecovery,
            salt
        );
    }

    const selectedFiles = targetSelection
    ? filterManifestFiles(
        manifest,
        targetSelection
    )
    : manifest.files;

    for (const file of selectedFiles) {
    // for (const file of manifest.files) {

        const encryptedPath = path.join(
            target,
            file.encrypted
        );

        const output = path.join(
            target,
            file.original
        );

        fs.mkdirSync(
            path.dirname(output),
            {
                recursive: true
            }
        );

        await decryptFile(
            encryptedPath,
            output,
            key
        );

        const hash = await sha256File(output);

        if (hash !== file.hash) {

            throw new Error(
                `Integrity failed: ${file.original}`
            );
        }

        fs.unlinkSync(encryptedPath);

        console.log('Decrypted:', file.original);
    }

    fs.unlinkSync(manifestPath);

    console.log('\nDecryption complete');
}

program
    .command('encrypt <directory>')
    .option(
        '-p, --password <password>'
    )
    .action(async (
        directory,
        options
    ) => {

        try {

            await encryptDirectory(
                directory,
                options.password || ''
            );

        } catch (err) {

            console.error(
                'Error:',
                err.message
            );
        }
    });

program
    .command('analyze <directory>')
    .action((directory) => {

        const manifestPath = path.join(
            directory,
            MANIFEST_FILE
        );

        if (!fs.existsSync(manifestPath)) {

            console.log('Manifest not found');

            return;
        }

        const manifest = JSON.parse(
            fs.readFileSync(
                manifestPath,
                'utf8'
            )
        );

        console.log('\nEncrypted Structure:\n');

        showManifestTree(manifest);
    });

program
    .command('decrypt <directory>')
    .option(
        '-p, --password <password>'
    )
    .option(
        '-r, --recovery <code>'
    )
    .option(
        '-s, --select <path>'
    )
    .action(async (
        directory,
        options
    ) => {

        try {

            await decryptDirectory(
                directory,
                options.password || '',
                options.recovery || '',
                options.select || ''
            );

        } catch (err) {

            console.error(
                'Error:',
                err.message
            );
        }
    });

program.parse();