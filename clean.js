const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const TARGET_DIR = process.argv[2] || '.';
const TEMP_FILE = path.join(TARGET_DIR, '.wipe.tmp');

const CHUNK_SIZE = 1024 * 1024 * 10; // 10MB

async function wipeFreeSpace() {
    console.log(`Wiping free space in: ${TARGET_DIR}`);

    const stream = fs.createWriteStream(TEMP_FILE, {
        flags: 'w'
    });

    return new Promise((resolve, reject) => {
        stream.on('error', (err) => {
            if (err.code === 'ENOSPC') {
                console.log('Disk full reached.');
                cleanup();
            } else {
                reject(err);
            }
        });

        function writeChunk() {
            let ok = true;

            while (ok) {
                const buffer = crypto.randomBytes(CHUNK_SIZE);
                ok = stream.write(buffer);
            }

            if (!ok) {
                stream.once('drain', writeChunk);
            }
        }

        function cleanup() {
            stream.end(() => {
                fs.unlink(TEMP_FILE, (err) => {
                    if (err) return reject(err);

                    console.log('Free space wiped successfully.');
                    resolve();
                });
            });
        }

        writeChunk();
    });
}

wipeFreeSpace().catch(err => {
    console.error('Error:', err.message);
});