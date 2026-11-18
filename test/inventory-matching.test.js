const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mergeInventories } = require('../lib/inventory');

const device = (name, ip, id = name) => ({ deviceName: name, ips: [ip], threatDownId: id, rustdeskId: '' });
const peer = (id, ip, name = '') => ({ rustdeskId: id, ip, deviceName: name });

test('verified A00073 mapping wins over multiple peers and stale devices sharing an IP', () => {
    const devices = [device('A00073', '172.16.1.81', 'kristy'), device('A00210', '172.16.1.81')];
    const peers = [peer('1298578316', '::ffff:172.16.1.81'), peer('138935363', '::ffff:172.16.1.81')];
    for (const records of [devices, [...devices].reverse()]) {
        const result = mergeInventories(records, peers, { kristy: '138935363' });
        assert.equal(result.find(row => row.deviceName === 'A00073').rustdeskId, '138935363');
        assert.equal(result.find(row => row.deviceName === 'A00210').rustdeskId, '');
        assert.equal(result.filter(row => row.rustdeskId === '138935363').length, 1);
        assert.ok(result.some(row => row.source === 'RustDesk' && row.rustdeskId === '1298578316'));
    }
});

test('IP collisions on either side stay unmatched', () => {
    for (const [devices, peers] of [
        [[device('PC1', '10.0.0.1')], [peer('1', '10.0.0.1'), peer('2', '10.0.0.1')]],
        [[device('PC1', '10.0.0.1'), device('PC2', '10.0.0.1')], [peer('1', '10.0.0.1')]]
    ]) {
        assert.equal(mergeInventories(devices, peers).filter(row => row.source === 'ThreatDown + RustDesk').length, 0);
    }
});

test('name matching has priority across the whole inventory regardless of record order', () => {
    const result = mergeInventories(
        [device('OLD', '10.0.0.1'), device('PC1.example.com', '10.0.0.2')],
        [peer('wrong', '10.0.0.2'), peer('right', '10.0.0.1', 'pc1')]
    );
    assert.equal(result[0].rustdeskId, '');
    assert.equal(result[1].rustdeskId, 'right');
});

test('unique IP fallback works but conflicting names and duplicate names do not match', () => {
    assert.equal(mergeInventories([device('PC1', '10.0.0.1')], [peer('1', '::ffff:10.0.0.1')])[0].rustdeskId, '1');
    assert.equal(mergeInventories([device('PC1', '10.0.0.1')], [peer('1', '10.0.0.1', 'PC2')])[0].rustdeskId, '');
    assert.equal(mergeInventories([device('PC1', '')], [peer('1', '', 'PC1'), peer('2', '', 'PC1')])[0].rustdeskId, '');
});

test('missing configured peers do not fall back to a different ID; configured IDs stay reserved', () => {
    assert.equal(mergeInventories([device('PC1', '10.0.0.1')], [peer('wrong', '10.0.0.1')], { PC1: 'right' })[0].rustdeskId, '');
    assert.equal(mergeInventories([device('PC2', '10.0.0.1')], [peer('right', '10.0.0.1')], { PC1: 'right' })[0].rustdeskId, '');
    assert.throws(() => mergeInventories([], [], { PC1: '1', PC2: '1' }), /unique/);
});
