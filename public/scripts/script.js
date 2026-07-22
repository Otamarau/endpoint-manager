const tableBody = document.querySelector('#endpoint-table-body');
const searchInput = document.querySelector('#endpoint-search');
let endpoints = [];

function normalizeSearchValue(value) {
    return String(value ?? '').trim().toLowerCase();
}

function editDistance(first, second) {
    const previous = Array.from({ length: second.length + 1 }, (_, index) => index);

    for (let firstIndex = 1; firstIndex <= first.length; firstIndex += 1) {
        const current = [firstIndex];

        for (let secondIndex = 1; secondIndex <= second.length; secondIndex += 1) {
            const substitutionCost = first[firstIndex - 1] === second[secondIndex - 1] ? 0 : 1;
            current[secondIndex] = Math.min(
                current[secondIndex - 1] + 1,
                previous[secondIndex] + 1,
                previous[secondIndex - 1] + substitutionCost
            );
        }

        previous.splice(0, previous.length, ...current);
    }

    return previous[second.length];
}

function fieldMatchScore(value, searchTerm) {
    const field = normalizeSearchValue(value);
    if (!field) return Number.POSITIVE_INFINITY;
    if (field === searchTerm) return 0;
    if (field.startsWith(searchTerm)) return 1 + (field.length - searchTerm.length) / 100;

    const containedAt = field.indexOf(searchTerm);
    if (containedAt !== -1) return 2 + containedAt / 100;

    const candidates = [field, ...field.split(/[\\\s,._-]+/).filter(Boolean)];
    const distance = Math.min(...candidates.map((candidate) => editDistance(candidate, searchTerm)));
    return 10 + distance + Math.abs(field.length - searchTerm.length) / 100;
}

function endpointMatchScore(endpoint, searchTerm) {
    const searchableColumns = [
        endpoint.username,
        endpoint.deviceName,
        endpoint.ip,
        endpoint.rustdeskId
    ];

    return Math.min(...searchableColumns.map((value) => fieldMatchScore(value, searchTerm)));
}

function renderEndpoints(filter = '') {
    const searchTerm = normalizeSearchValue(filter);
    const visibleEndpoints = searchTerm
        ? endpoints
            .map((endpoint, originalIndex) => ({
                endpoint,
                originalIndex,
                score: endpointMatchScore(endpoint, searchTerm)
            }))
            .sort((first, second) =>
                first.score - second.score || first.originalIndex - second.originalIndex
            )
            .map(({ endpoint }) => endpoint)
        : endpoints;

    tableBody.replaceChildren();

    if (visibleEndpoints.length === 0) {
        const row = document.createElement('tr');
        row.className = 'empty-row';
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.textContent = 'No endpoints to display.';
        row.append(cell);
        tableBody.append(row);
        return;
    }

    const columns = [
        ['Username', 'username'],
        ['Device name', 'deviceName'],
        ['IP', 'ip'],
        ['RustDesk ID', 'rustdeskId']
    ];

    for (const endpoint of visibleEndpoints) {
        const row = document.createElement('tr');

        for (const [label, property] of columns) {
            const cell = document.createElement('td');
            cell.dataset.label = label;
            cell.textContent = endpoint[property] || '—';
            row.append(cell);
        }

        tableBody.append(row);
    }
}

async function unlockSite() {
    while (true) {
        const passcode = window.prompt('Enter the Endpoint Manager passcode:');

        if (passcode === null) {
            throw new Error('Access cancelled. Refresh the page to try again.');
        }

        const response = await fetch('/api/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passcode })
        });

        if (response.ok) return;

        const payload = await response.json().catch(() => ({}));
        window.alert(payload.error || 'Incorrect passcode. Please try again.');
    }
}

async function loadEndpoints() {
    try {
        await unlockSite();
        const response = await fetch('/api/endpoints');
        const payload = await response.json();

        if (!response.ok) {
            throw new Error(payload.details || payload.error || 'Request failed');
        }

        endpoints = payload.endpoints;
        renderEndpoints(searchInput.value);
    } catch (error) {
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        row.className = 'empty-row';
        const cell = document.createElement('td');
        cell.colSpan = 4;
        cell.textContent = `Could not load endpoints: ${error.message}`;
        row.append(cell);
        tableBody.append(row);
    }
}

searchInput.addEventListener('input', () => renderEndpoints(searchInput.value));
loadEndpoints();
