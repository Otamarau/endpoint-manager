const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWebexClient, enrichEndpoints } = require('../lib/webex');

test('matches Windows names and exact emails, preserves zeroes and existing device fields', () => {
    const people = [{ displayName: 'Jane Smith', emails: ['jane.smith@example.com'], extension: '0012',
        phoneNumbers: [{ type: 'work_extension', value: '0012' }, { type: 'work', value: '+61123456789' }] }];
    const endpoints = [{ username: 'AzureAD\\JaneSmith', rustdeskId: '123' },
        { username: 'JANE.SMITH@example.com' }, { username: 'DOMAIN\\jane.smith' },
        { username: 'jane.smith@different.example' }, { username: '' }];
    const result = enrichEndpoints(endpoints, people);
    assert.deepEqual(result.map(item => item.extension), ['0012', '0012', '0012', '', '']);
    assert.equal(result[0].rustdeskId, '123');
    assert.equal(endpoints[0].extension, undefined);
});

test('ambiguous names stay blank even if only one person has an extension', () => {
    const people = [{ displayName: 'Jane Smith', emails: ['jane@example.com'], extension: '12' },
        { displayName: 'Jane Smith', emails: ['other@example.com'] }];
    const result = enrichEndpoints([{ username: 'AzureAD\\JaneSmith' }, { username: 'jane@example.com' }], people);
    assert.deepEqual(result.map(item => item.extension), ['', '12']);
});

test('accepts extension-only phone entries and clears old extensions when unmatched', () => {
    assert.equal(enrichEndpoints([{ username: 'sam' }], [{ emails: ['sam@example.com'],
        phoneNumbers: [{ type: 'work_extension', value: '0345' }] }])[0].extension, '0345');
    assert.equal(enrichEndpoints([{ username: 'sam', extension: 'old' }], [])[0].extension, '');
});

function fixture(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'endpoint-webex-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const envFile = path.join(directory, '.env');
    fs.writeFileSync(envFile, 'WEBEX_CLIENT_ID=test\nWEBEX_CLIENT_SECRET=secret\nWEBEX_REFRESH_TOKEN=old\nUNRELATED=keep\n');
    return envFile;
}

function json(payload, headers = {}) {
    return new Response(JSON.stringify(payload), { headers });
}

test('rotates tokens safely, follows all pages and reuses the access token', async t => {
    const envFile = fixture(t);
    let tokenCalls = 0;
    let peopleCalls = 0;
    const client = createWebexClient({ envFile, fetchImpl: async (url, options) => {
        assert.equal(options.redirect, 'error');
        if (url.endsWith('/access_token')) {
            tokenCalls++;
            assert.equal(JSON.parse(options.body).refresh_token, 'old');
            return json({ access_token: 'access', refresh_token: 'renewed', expires_in: 3600 });
        }
        peopleCalls++;
        assert.equal(options.headers.Authorization, 'Bearer access');
        assert.match(fs.readFileSync(envFile, 'utf8'), /WEBEX_REFRESH_TOKEN="renewed"/);
        return url.includes('cursor=2') ? json({ items: [{ id: 'second' }] })
            : json({ items: [{ id: 'first' }] }, { link: '<https://webexapis.com/v1/people?cursor=2>; rel="next"' });
    } });
    assert.equal(client.isConfigured(), true);
    assert.deepEqual(await client.readPeople(), [{ id: 'first' }, { id: 'second' }]);
    await client.readPeople();
    assert.equal(tokenCalls, 1);
    assert.equal(peopleCalls, 4);
    assert.match(fs.readFileSync(envFile, 'utf8'), /UNRELATED=keep/);
});

test('rejects untrusted and repeated pagination links before sending credentials', async t => {
    for (const next of ['https://untrusted.example/v1/people', 'https://webexapis.com/v1/people?max=1000']) {
        const envFile = fixture(t);
        let calls = 0;
        const client = createWebexClient({ envFile, fetchImpl: async url => {
            calls++;
            return url.endsWith('/access_token') ? json({ access_token: 'access' })
                : json({ items: [] }, { link: `<${next}>; rel="next"` });
        } });
        await assert.rejects(client.readPeople(), /invalid or repeated pagination/);
        assert.equal(calls, 2);
    }
});

test('reports API failures without including response bodies or credentials', async t => {
    const client = createWebexClient({ envFile: fixture(t), fetchImpl: async () => new Response('sensitive response', { status: 401 }) });
    await assert.rejects(client.readPeople(), error => error.message.includes('Webex HTTP 401') && !error.message.includes('sensitive'));
});
