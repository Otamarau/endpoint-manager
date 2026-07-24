require('dotenv').config({ quiet: true });

const express = require('express');
const Database = require('better-sqlite3');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const app = express();
app.set('trust proxy', 'loopback');
const port = Number(process.env.PORT) || 3000;
const certificatePath = path.resolve(
    process.env.HTTPS_CERT_PATH || path.join(__dirname, 'certs', 'localhost-cert.pem')
);
const privateKeyPath = path.resolve(
    process.env.HTTPS_KEY_PATH || path.join(__dirname, 'certs', 'localhost-key.pem')
);
const publicDirectory = path.join(__dirname, 'public');
const dataDirectory = path.join(__dirname, 'data');
const inventoryPath = path.join(dataDirectory, 'rustdesk_inventory.json');
const databasePath = path.resolve(
    process.env.RUSTDESK_DB_PATH ||
    path.join(os.homedir(), 'rustdesk', 'data', 'db_v2.sqlite3')
);
const threatDownBaseUrl = 'https://api.threatdown.com';
const sitePasscodeHash = process.env.SITE_PASSCODE_HASH;
const authenticatedSessions = new Map();
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const unlockAttempts = new Map();
const unlockMaxAttempts = Math.max(Number(process.env.UNLOCK_MAX_ATTEMPTS) || 5, 1);
const unlockWindowMs = Math.max(Number(process.env.UNLOCK_WINDOW_MINUTES) || 15, 1) * 60 * 1000;
let threatDownToken = null;
let threatDownTokenExpiresAt = 0;

function parsePeerInfo(value) {
    if (!value) return {};

    try {
        const text = Buffer.isBuffer(value) ? value.toString('utf8') : value;
        return typeof text === 'string' ? JSON.parse(text) : text;
    } catch {
        return {};
    }
}

function firstValue(object, keys) {
    for (const key of keys) {
        const value = object?.[key];
        const normalizedValue = String(value ?? '').trim();
        if (normalizedValue && normalizedValue.toLowerCase() !== '<unknown>') {
            return normalizedValue;
        }
    }
    return '';
}

function readInventory() {
    if (!fs.existsSync(databasePath)) {
        throw new Error(`RustDesk database was not found at ${databasePath}`);
    }

    const database = new Database(databasePath, {
        readonly: true,
        fileMustExist: true
    });

    try {
        const peers = database.prepare(`
            SELECT id, guid, uuid, created_at, info, note
            FROM peer
            ORDER BY id
        `).all();

        return peers.map((peer) => {
            const info = parsePeerInfo(peer.info);

            return {
                username: firstValue(info, ['netbios_user', 'username', 'user_name', 'user', 'login_name']),
                deviceName: firstValue(info, ['computer_name', 'hostname', 'device_name', 'deviceName', 'host_name', 'name']),
                ip: firstValue(info, ['ip', 'address', 'ip_address']),
                rustdeskId: String(peer.id ?? ''),
                guid: peer.guid ?? '',
                uuid: peer.uuid ?? '',
                createdAt: peer.created_at ?? '',
                macAddress: firstValue(info, ['mac_address', 'mac', 'macAddress']),
                note: peer.note ?? ''
            };
        });
    } finally {
        database.close();
    }
}

function normalizeDeviceName(value) {
    return String(value || '').trim().split('.')[0].toLowerCase();
}

function normalizeIp(value) {
    return String(value || '').trim().replace(/^::ffff:/, '').toLowerCase();
}

function usableIps(nics = []) {
    const ips = nics.flatMap((nic) => Array.isArray(nic.ips) ? nic.ips : []);
    return [...new Set(ips.map(normalizeIp).filter((ip) =>
        ip && ip !== '127.0.0.1' && ip !== '::1' && !ip.startsWith('169.254.')
    ))];
}

function requireThreatDownConfig() {
    const values = {
        clientId: process.env.THREATDOWN_CLIENT_ID,
        clientSecret: process.env.THREATDOWN_CLIENT_SECRET,
        accountId: process.env.THREATDOWN_ACCOUNT_ID
    };

    const missing = Object.entries(values)
        .filter(([, value]) => !value)
        .map(([key]) => key);

    if (missing.length) {
        throw new Error(`Missing ThreatDown configuration: ${missing.join(', ')}`);
    }

    return values;
}

async function getThreatDownToken() {
    if (threatDownToken && Date.now() < threatDownTokenExpiresAt) {
        return threatDownToken;
    }

    const { clientId, clientSecret } = requireThreatDownConfig();
    const authorization = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const response = await fetch(`${threatDownBaseUrl}/oauth2/token`, {
        method: 'POST',
        headers: {
            Authorization: `Basic ${authorization}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            grant_type: 'client_credentials',
            scope: 'read'
        })
    });
    const payload = await response.json();

    if (!response.ok) {
        throw new Error(`ThreatDown authentication failed (${response.status}): ${payload.message || payload.error || 'Unknown error'}`);
    }

    threatDownToken = payload.access_token;
    threatDownTokenExpiresAt = Date.now() + Math.max(0, Number(payload.expires_in || 3600) - 60) * 1000;
    return threatDownToken;
}

async function readThreatDownInventory() {
    const { accountId } = requireThreatDownConfig();
    const token = await getThreatDownToken();
    const endpoints = [];
    let nextCursor;

    do {
        const requestBody = {
            page_size: 2000,
            sort_field: 'host_name',
            sort_order: 'asc'
        };

        if (nextCursor) requestBody.next_cursor = nextCursor;

        const response = await fetch(`${threatDownBaseUrl}/nebula/v1/endpoints`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                accountid: accountId,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        const payload = await response.json();

        if (!response.ok) {
            throw new Error(`ThreatDown endpoint query failed (${response.status}): ${payload.message || payload.error || 'Unknown error'}`);
        }

        endpoints.push(...(payload.endpoints || []));
        nextCursor = payload.next_cursor || null;
    } while (nextCursor);

    return endpoints.map((record) => {
        const agent = record.agent || {};
        const machine = record.machine || {};
        const ips = usableIps(agent.nics);

        if (ips.length === 0 && agent.machine_ip) ips.push(normalizeIp(agent.machine_ip));

        return {
            username: agent.last_user || '',
            deviceName: agent.host_name || agent.fully_qualified_host_name || record.display_name || '',
            ip: ips.join(', '),
            ips,
            rustdeskId: '',
            threatDownId: machine.id || agent.machine_id || '',
            lastSeenAt: machine.last_seen_at || machine.last_day_seen || '',
            online: Boolean(machine.online),
            source: 'ThreatDown'
        };
    });
}

function mergeInventories(threatDownEndpoints, rustDeskEndpoints) {
    const remainingRustDesk = [...rustDeskEndpoints];

    const merged = threatDownEndpoints.map((threatDownEndpoint) => {
        const deviceName = normalizeDeviceName(threatDownEndpoint.deviceName);
        const threatDownIps = new Set(threatDownEndpoint.ips.map(normalizeIp));
        const matchIndex = remainingRustDesk.findIndex((rustDeskEndpoint) => {
            const rustDeskName = normalizeDeviceName(rustDeskEndpoint.deviceName);
            const rustDeskIp = normalizeIp(rustDeskEndpoint.ip);
            return (deviceName && rustDeskName === deviceName) ||
                (rustDeskIp && threatDownIps.has(rustDeskIp));
        });

        if (matchIndex === -1) return threatDownEndpoint;

        const [rustDeskEndpoint] = remainingRustDesk.splice(matchIndex, 1);
        return {
            ...threatDownEndpoint,
            username: threatDownEndpoint.username || rustDeskEndpoint.username,
            deviceName: threatDownEndpoint.deviceName || rustDeskEndpoint.deviceName,
            ip: threatDownEndpoint.ip || rustDeskEndpoint.ip,
            rustdeskId: rustDeskEndpoint.rustdeskId,
            rustdesk: rustDeskEndpoint,
            source: 'ThreatDown + RustDesk'
        };
    });

    return merged.concat(remainingRustDesk.map((endpoint) => ({
        ...endpoint,
        source: 'RustDesk'
    })));
}

function readCookie(request, name) {
    const cookies = String(request.headers.cookie || '').split(';');
    for (const cookie of cookies) {
        const separator = cookie.indexOf('=');
        if (separator === -1) continue;
        if (cookie.slice(0, separator).trim() === name) {
            return decodeURIComponent(cookie.slice(separator + 1).trim());
        }
    }
    return '';
}

function parsePasscodeHash(value) {
    const [algorithm, costText, blockSizeText, parallelizationText, saltText, hashText] =
        String(value || '').split('$');
    const cost = Number(costText);
    const blockSize = Number(blockSizeText);
    const parallelization = Number(parallelizationText);

    if (
        algorithm !== 'scrypt' ||
        !Number.isInteger(cost) ||
        !Number.isInteger(blockSize) ||
        !Number.isInteger(parallelization) ||
        !saltText ||
        !hashText
    ) {
        return null;
    }

    try {
        return {
            cost,
            blockSize,
            parallelization,
            salt: Buffer.from(saltText, 'base64url'),
            expectedHash: Buffer.from(hashText, 'base64url')
        };
    } catch {
        return null;
    }
}

function passcodesMatch(submittedPasscode) {
    return new Promise((resolve) => {
        const parsedHash = parsePasscodeHash(sitePasscodeHash);
        if (!parsedHash || typeof submittedPasscode !== 'string') {
            return resolve(false);
        }

        crypto.scrypt(
            submittedPasscode,
            parsedHash.salt,
            parsedHash.expectedHash.length,
            {
                N: parsedHash.cost,
                r: parsedHash.blockSize,
                p: parsedHash.parallelization,
                maxmem: 64 * 1024 * 1024
            },
            (error, submittedHash) => {
                resolve(
                    !error &&
                    submittedHash.length === parsedHash.expectedHash.length &&
                    crypto.timingSafeEqual(submittedHash, parsedHash.expectedHash)
                );
            }
        );
    });
}

function activeUnlockAttempt(request) {
    const clientIp = request.ip || request.socket.remoteAddress || 'unknown';
    const attempt = unlockAttempts.get(clientIp);

    if (attempt && attempt.resetAt > Date.now()) {
        return { clientIp, attempt };
    }

    unlockAttempts.delete(clientIp);
    return { clientIp, attempt: null };
}

function rejectRateLimited(response, resetAt) {
    const retryAfterSeconds = Math.max(Math.ceil((resetAt - Date.now()) / 1000), 1);
    response.setHeader('Retry-After', retryAfterSeconds);
    return response.status(429).json({
        error: 'Too many incorrect passcode attempts. Try again later.'
    });
}

function requireAuthentication(request, response, next) {
    const sessionId = readCookie(request, 'endpoint_session');
    const expiresAt = authenticatedSessions.get(sessionId);

    if (!expiresAt || expiresAt <= Date.now()) {
        if (sessionId) authenticatedSessions.delete(sessionId);
        return response.status(401).json({ error: 'Passcode required.' });
    }

    next();
}

async function generateInventory() {
    const sourceErrors = {};
    let threatDownEndpoints = [];
    let rustDeskEndpoints = [];

    try {
        threatDownEndpoints = await readThreatDownInventory();
    } catch (error) {
        sourceErrors.threatDown = error.message;
    }

    try {
        rustDeskEndpoints = readInventory();
    } catch (error) {
        sourceErrors.rustDesk = error.message;
    }

    if (threatDownEndpoints.length === 0 && rustDeskEndpoints.length === 0) {
        throw new Error(Object.values(sourceErrors).join(' | ') || 'No inventory sources returned endpoints.');
    }

    const payload = {
        generatedAt: new Date().toISOString(),
        endpoints: mergeInventories(threatDownEndpoints, rustDeskEndpoints),
        sources: {
            threatDown: threatDownEndpoints.length,
            rustDesk: rustDeskEndpoints.length
        },
        sourceErrors
    };

    fs.mkdirSync(dataDirectory, { recursive: true });
    fs.writeFileSync(inventoryPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    return payload;
}

app.use(express.json({ limit: '2kb' }));

app.post('/api/unlock', async (request, response) => {
    if (!parsePasscodeHash(sitePasscodeHash)) {
        return response.status(503).json({ error: 'SITE_PASSCODE_HASH is not configured correctly.' });
    }

    const { clientIp, attempt } = activeUnlockAttempt(request);
    if (attempt?.failures >= unlockMaxAttempts) {
        return rejectRateLimited(response, attempt.resetAt);
    }

    if (!await passcodesMatch(request.body?.passcode)) {
        const updatedAttempt = {
            failures: (attempt?.failures || 0) + 1,
            resetAt: attempt?.resetAt || Date.now() + unlockWindowMs
        };
        unlockAttempts.set(clientIp, updatedAttempt);

        if (updatedAttempt.failures >= unlockMaxAttempts) {
            return rejectRateLimited(response, updatedAttempt.resetAt);
        }

        return response.status(401).json({ error: 'Incorrect passcode.' });
    }

    unlockAttempts.delete(clientIp);
    const sessionId = crypto.randomBytes(32).toString('hex');
    authenticatedSessions.set(sessionId, Date.now() + sessionLifetimeMs);
    response.setHeader(
        'Set-Cookie',
        `endpoint_session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${sessionLifetimeMs / 1000}`
    );
    response.status(204).end();
});

app.get('/api/endpoints', requireAuthentication, async (request, response) => {
    try {
        response.json(await generateInventory());
    } catch (error) {
        console.error(error.message);
        response.status(500).json({
            error: 'Unable to read the RustDesk inventory.',
            details: error.message
        });
    }
});

app.use(express.static(publicDirectory));

const httpsServer = https.createServer({
    cert: fs.readFileSync(certificatePath),
    key: fs.readFileSync(privateKeyPath)
}, app);

httpsServer.listen(port, () => {
    console.log(`Endpoint Manager is running at https://localhost:${port}`);
    console.log(`HTTPS certificate: ${certificatePath}`);
    console.log(`RustDesk database: ${databasePath}`);
});
