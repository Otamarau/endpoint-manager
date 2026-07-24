const crypto = require('node:crypto');

const cost = 16384;
const blockSize = 8;
const parallelization = 1;
const keyLength = 64;

function readHiddenPasscode() {
    if (!process.stdin.isTTY) {
        return new Promise((resolve, reject) => {
            let input = '';
            process.stdin.setEncoding('utf8');
            process.stdin.on('data', (chunk) => {
                input += chunk;
            });
            process.stdin.on('end', () => resolve(input.replace(/\r?\n$/, '')));
            process.stdin.on('error', reject);
        });
    }

    return new Promise((resolve) => {
        let input = '';
        process.stdout.write('Enter the new site passcode: ');
        process.stdin.setRawMode(true);
        process.stdin.setEncoding('utf8');
        process.stdin.resume();

        const finish = (passcode) => {
            process.stdin.setRawMode(false);
            process.stdin.pause();
            process.stdout.write('\n');
            resolve(passcode);
        };

        process.stdin.on('data', (character) => {
            if (character === '\u0003') {
                process.stdout.write('\n');
                process.exit(130);
            }
            if (character === '\r' || character === '\n') {
                return finish(input);
            }
            if (character === '\u007f' || character === '\b') {
                input = input.slice(0, -1);
                return;
            }
            input += character;
        });
    });
}

async function main() {
    const passcode = await readHiddenPasscode();
    if (!passcode) {
        throw new Error('The passcode cannot be empty.');
    }

    const salt = crypto.randomBytes(16);
    const derivedKey = await new Promise((resolve, reject) => {
        crypto.scrypt(
            passcode,
            salt,
            keyLength,
            {
                N: cost,
                r: blockSize,
                p: parallelization,
                maxmem: 64 * 1024 * 1024
            },
            (error, key) => error ? reject(error) : resolve(key)
        );
    });

    console.log([
        'scrypt',
        cost,
        blockSize,
        parallelization,
        salt.toString('base64url'),
        derivedKey.toString('base64url')
    ].join('$'));
}

main().catch((error) => {
    console.error(error.message);
    process.exit(1);
});
