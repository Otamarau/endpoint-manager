function normalizeName(value) {
    return String(value || '').trim().split('.')[0].toLowerCase();
}

function normalizeIp(value) {
    return String(value || '').trim().replace(/^::ffff:/i, '').toLowerCase();
}

function mergeInventories(threatDownEndpoints, rustDeskEndpoints, mappings = {}) {
    if (!mappings || Array.isArray(mappings) || typeof mappings !== 'object' ||
        Object.values(mappings).some(id => typeof id !== 'string' || !id.trim()) ||
        new Set(Object.values(mappings)).size !== Object.values(mappings).length) {
        throw new Error('RustDesk mappings must contain unique RustDesk ID strings keyed by ThreatDown device ID.');
    }

    const matches = new Map();
    const used = new Set();
    const reservedIds = new Set(Object.values(mappings));
    const configured = endpoint => Object.hasOwn(mappings, endpoint.threatDownId);
    const assign = (endpoint, peer) => { matches.set(endpoint, peer); used.add(peer); };

    // Explicit, verified assignments take precedence and reserve both identities.
    for (const endpoint of threatDownEndpoints) {
        if (!configured(endpoint)) continue;
        const peers = rustDeskEndpoints.filter(peer => peer.rustdeskId === mappings[endpoint.threatDownId]);
        const targets = threatDownEndpoints.filter(other => other.threatDownId === endpoint.threatDownId);
        if (peers.length === 1 && targets.length === 1) assign(endpoint, peers[0]);
    }

    const available = peer => !used.has(peer) && !reservedIds.has(peer.rustdeskId);
    // Complete all unique name matches before considering weaker IP evidence.
    for (const endpoint of threatDownEndpoints) {
        if (configured(endpoint)) continue;
        const name = normalizeName(endpoint.deviceName);
        if (!name) continue;
        const peers = rustDeskEndpoints.filter(peer => normalizeName(peer.deviceName) === name);
        const targets = threatDownEndpoints.filter(other => normalizeName(other.deviceName) === name);
        if (peers.length === 1 && targets.length === 1 && available(peers[0])) assign(endpoint, peers[0]);
    }

    const ips = endpoint => (endpoint.ips || []).map(normalizeIp).filter(ip =>
        ip && ip !== '127.0.0.1' && ip !== '::1' && !ip.startsWith('169.254.')
    );
    const sharesIp = (endpoint, peer) => ips(endpoint).includes(normalizeIp(peer.ip));
    for (const endpoint of threatDownEndpoints) {
        if (configured(endpoint) || matches.has(endpoint)) continue;
        // Count all original records: removing an earlier match must not turn
        // an ambiguous shared address into an apparently unique match.
        const peers = rustDeskEndpoints.filter(peer => sharesIp(endpoint, peer));
        if (peers.length !== 1 || !available(peers[0])) continue;
        const peer = peers[0];
        if (threatDownEndpoints.filter(other => sharesIp(other, peer)).length !== 1) continue;
        const name = normalizeName(endpoint.deviceName);
        const peerName = normalizeName(peer.deviceName);
        if (name && peerName && name !== peerName) continue;
        assign(endpoint, peer);
    }

    return threatDownEndpoints.map(endpoint => {
        const peer = matches.get(endpoint);
        if (!peer) return endpoint;
        return {
            ...endpoint,
            username: endpoint.username || peer.username,
            deviceName: endpoint.deviceName || peer.deviceName,
            ip: endpoint.ip || peer.ip,
            rustdeskId: peer.rustdeskId,
            rustdesk: peer,
            source: 'ThreatDown + RustDesk'
        };
    }).concat(rustDeskEndpoints.filter(peer => !used.has(peer)).map(peer => ({ ...peer, source: 'RustDesk' })));
}

module.exports = { mergeInventories };
