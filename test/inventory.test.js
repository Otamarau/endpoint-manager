const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { enrichEndpoints } = require('../lib/webex');

function inventoryHarness(webex) {
    const filename = path.resolve(__dirname, '../server.js');
    const localRequire = createRequire(filename);
    let saved;
    const context = vm.createContext({
        require(name) {
            if (name === 'dotenv') return { config() {} };
            if (name === './lib/webex') return { enrichEndpoints, createWebexClient: () => webex };
            if (name === 'node:fs') return {
                existsSync: () => false, readFileSync: () => '', mkdirSync() {},
                writeFileSync(file, contents) { saved = JSON.parse(contents); }
            };
            if (name === 'node:https') return { createServer: () => ({ listen() {} }) };
            return localRequire(name);
        },
        __dirname: path.dirname(filename), process: { env: {} }, console, Buffer,
        URLSearchParams, setInterval
    });
    vm.runInContext(fs.readFileSync(filename, 'utf8'), context);
    vm.runInContext(`
        readThreatDownInventory = async () => [{ username: 'AzureAD\\\\JaneSmith', deviceName: 'PC1', ips: [], rustdeskId: '' }];
        readInventory = () => [{ username: 'Jane', deviceName: 'PC1', rustdeskId: '1234' }];
    `, context);
    return { generate: () => vm.runInContext('generateInventory()', context), saved: () => saved };
}

test('inventory combines device sources, enriches extensions and persists the result', async () => {
    const harness = inventoryHarness({ isConfigured: () => true, readPeople: async () => [
        { displayName: 'Jane Smith', extension: '0012' }
    ] });
    const result = await harness.generate();
    assert.equal(result.endpoints.length, 1);
    assert.equal(result.endpoints[0].rustdeskId, '1234');
    assert.equal(result.endpoints[0].extension, '0012');
    assert.equal(result.sources.webexMatched, 1);
    assert.equal(harness.saved().endpoints[0].extension, '0012');
});

test('Webex API and credential-file failures keep the device inventory available', async () => {
    for (const webex of [
        { isConfigured: () => true, readPeople: async () => { throw new Error('Webex HTTP 403'); } },
        { isConfigured: () => { throw new Error('Credentials file unavailable'); } }
    ]) {
        const harness = inventoryHarness(webex);
        const result = await harness.generate();
        assert.equal(result.endpoints.length, 1);
        assert.equal(result.endpoints[0].rustdeskId, '1234');
        assert.equal(result.endpoints[0].extension, '');
        assert.ok(result.sourceErrors.webex);
        assert.equal(harness.saved().endpoints.length, 1);
    }
});
