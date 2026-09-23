const fs = require('node:fs');
const dotenv = require('dotenv');

const apiOrigin = 'https://webexapis.com';

function createWebexClient({ envFile, fetchImpl = fetch }) {
    let accessToken;
    let expiresAt = 0;

    function configuration() {
        return dotenv.parse(fs.readFileSync(envFile, 'utf8'));
    }

    async function request(url, options = {}) {
        const response = await fetchImpl(url, {
            ...options,
            redirect: 'error',
            signal: AbortSignal.timeout(30000)
        });
        if (!response.ok) {
            const hint = url.includes('/access_token')
                ? 'Check the Webex Service App credentials and refresh token.'
                : 'Check the Webex Service App people-read permissions.';
            throw new Error(`Webex HTTP ${response.status}. ${hint}`);
        }
        return response;
    }

    async function token() {
        if (accessToken && Date.now() < expiresAt) return accessToken;
        const env = configuration();
        for (const key of ['WEBEX_CLIENT_ID', 'WEBEX_CLIENT_SECRET', 'WEBEX_REFRESH_TOKEN']) {
            if (!env[key]?.trim()) throw new Error(`Set ${key} in the Webex credentials file.`);
        }
        const response = await request(`${apiOrigin}/v1/access_token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                client_id: env.WEBEX_CLIENT_ID,
                client_secret: env.WEBEX_CLIENT_SECRET,
                refresh_token: env.WEBEX_REFRESH_TOKEN
            })
        });
        const tokens = await response.json();
        if (typeof tokens.access_token !== 'string' || !tokens.access_token) {
            throw new Error('Webex did not return an access token.');
        }
        if (tokens.refresh_token) {
            if (typeof tokens.refresh_token !== 'string' || /[\r\n"]/.test(tokens.refresh_token)) {
                throw new Error('Webex returned an invalid refresh token.');
            }
            const text = fs.readFileSync(envFile, 'utf8');
            const updated = text.replace(/^\s*(?:export\s+)?WEBEX_REFRESH_TOKEN\s*=.*$/gm,
                () => `WEBEX_REFRESH_TOKEN="${tokens.refresh_token}"`);
            const temporary = `${envFile}.${process.pid}.tmp`;
            try {
                fs.writeFileSync(temporary, updated, { mode: 0o600, flag: 'wx' });
                fs.renameSync(temporary, envFile);
            } finally {
                if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
            }
        }
        accessToken = tokens.access_token;
        expiresAt = Date.now() + Math.max(0, Number(tokens.expires_in || 3600) - 60) * 1000;
        return accessToken;
    }

    return {
        isConfigured: () => fs.existsSync(envFile) && ['WEBEX_CLIENT_ID', 'WEBEX_CLIENT_SECRET', 'WEBEX_REFRESH_TOKEN'].some(key => configuration()[key]),
        async readPeople() {
            const bearer = await token();
            const people = [];
            const visited = new Set();
            let next = `${apiOrigin}/v1/people?max=1000`;
            while (next) {
                const url = new URL(next);
                if (url.origin !== apiOrigin || url.pathname !== '/v1/people' || url.username || url.password || visited.has(url.href)) {
                    throw new Error('Webex returned an invalid or repeated pagination link.');
                }
                visited.add(url.href);
                const response = await request(url.href, { headers: { Authorization: `Bearer ${bearer}` } });
                const payload = await response.json();
                if (!Array.isArray(payload.items)) throw new Error('Webex returned an invalid people response.');
                people.push(...payload.items);
                next = response.headers.get('link')?.match(/<([^>]+)>\s*;\s*rel="next"/i)?.[1];
            }
            return people;
        }
    };
}

function identity(value) {
    return String(value || '').normalize('NFKC').trim().toLowerCase();
}

function alias(value) {
    return identity(value).replace(/[\s._-]+/g, '');
}

function enrichEndpoints(endpoints, people) {
    const emails = new Map();
    const aliases = new Map();
    function add(index, key, person) {
        if (!key) return;
        if (!index.has(key)) index.set(key, new Set());
        index.get(key).add(person);
    }
    for (const person of people) {
        for (const email of person.emails || []) {
            add(emails, identity(email), person);
            add(aliases, alias(String(email).split('@')[0]), person);
        }
        add(aliases, alias(person.displayName), person);
        add(aliases, alias([person.firstName, person.lastName].filter(Boolean).join(' ')), person);
    }
    return endpoints.map(endpoint => {
        const username = identity(endpoint.username).split('\\').pop();
        // Email identities require the whole email to match; never drop their domain.
        const candidates = username.includes('@') ? emails.get(username) : aliases.get(alias(username));
        const person = candidates?.size === 1 ? [...candidates][0] : null;
        const extensions = person ? [person.extension, ...(person.phoneNumbers || [])
            .filter(number => number.type === 'work_extension').map(number => number.value)] : [];
        return {
            ...endpoint,
            extension: [...new Set(extensions.map(value => String(value ?? '').trim()).filter(Boolean))].join(', ')
        };
    });
}

module.exports = { createWebexClient, enrichEndpoints };
