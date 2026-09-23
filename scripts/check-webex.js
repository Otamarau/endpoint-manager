const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
require('dotenv').config({ path: path.join(root, '.env'), quiet: true });
const { createWebexClient, enrichEndpoints } = require('../lib/webex');

async function main() {
    const client = createWebexClient({ envFile: path.resolve(root, process.env.WEBEX_ENV_FILE || '.env') });
    const people = await client.readPeople();
    const snapshot = path.join(root, 'data/rustdesk_inventory.json');
    const endpoints = fs.existsSync(snapshot) ? JSON.parse(fs.readFileSync(snapshot, 'utf8')).endpoints : [];
    const enriched = enrichEndpoints(endpoints, people);
    console.log(JSON.stringify({
        webexPeople: people.length,
        peopleWithExtensions: people.filter(person => person.extension || person.phoneNumbers?.some(number => number.type === 'work_extension' && number.value)).length,
        cachedEndpoints: endpoints.length,
        endpointsWithExtensions: enriched.filter(endpoint => endpoint.extension).length
    }, null, 2));
}

main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
});
