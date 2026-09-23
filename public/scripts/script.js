const tableBody = document.querySelector('#endpoint-table-body');
const searchInput = document.querySelector('#endpoint-search');
const sortButtons = document.querySelectorAll('.column-sort');
const sortCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
let endpoints = [];
let sortColumn = null;
let sortDirection = 'ascending';

function compareEndpoints(first, second) {
    const firstValue = String(first[sortColumn] ?? '').trim();
    const secondValue = String(second[sortColumn] ?? '').trim();
    // Keep missing values at the bottom in either direction.
    if (!firstValue || !secondValue) return Number(!firstValue) - Number(!secondValue);
    return sortCollator.compare(firstValue, secondValue) * (sortDirection === 'ascending' ? 1 : -1);
}

function updateSortHeadings() {
    for (const button of sortButtons) {
        const active = button.dataset.sort === sortColumn;
        button.closest('th').setAttribute('aria-sort', active ? sortDirection : 'none');
        button.querySelector('.sort-indicator').textContent = active
            ? (sortDirection === 'ascending' ? '↑' : '↓') : '↕';
        const nextDirection = active && sortDirection === 'ascending' ? 'descending' : 'ascending';
        button.setAttribute('aria-label', `${button.dataset.label}: sort ${nextDirection}`);
        button.title = `Sort ${nextDirection}`;
    }
}

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
        endpoint.rustdeskId,
        endpoint.extension
    ];

    return Math.min(...searchableColumns.map((value) => fieldMatchScore(value, searchTerm)));
}

function appendHighlightedValue(cell, value, searchTerm, useFuzzyMatch = false) {
    const displayValue = String(value || '—');
    if (!searchTerm) {
        cell.textContent = displayValue;
        return;
    }

    const normalizedValue = displayValue.toLowerCase();
    const exactRanges = [];
    let matchIndex = normalizedValue.indexOf(searchTerm);

    while (matchIndex !== -1) {
        exactRanges.push([matchIndex, matchIndex + searchTerm.length]);
        matchIndex = normalizedValue.indexOf(searchTerm, matchIndex + searchTerm.length);
    }

    if (exactRanges.length === 0 && useFuzzyMatch) {
        const candidates = [...displayValue.matchAll(/[^\\\s,._-]+/g)];
        let closestCandidate;

        for (const candidate of candidates) {
            const distance = editDistance(candidate[0].toLowerCase(), searchTerm);
            if (!closestCandidate || distance < closestCandidate.distance) {
                closestCandidate = { index: candidate.index, length: candidate[0].length, distance };
            }
        }

        if (closestCandidate) {
            exactRanges.push([
                closestCandidate.index,
                closestCandidate.index + closestCandidate.length
            ]);
        }
    }

    if (exactRanges.length === 0) {
        cell.textContent = displayValue;
        return;
    }

    let cursor = 0;
    for (const [start, end] of exactRanges) {
        cell.append(document.createTextNode(displayValue.slice(cursor, start)));
        const highlight = document.createElement('mark');
        highlight.className = 'search-highlight';
        highlight.textContent = displayValue.slice(start, end);
        cell.append(highlight);
        cursor = end;
    }
    cell.append(document.createTextNode(displayValue.slice(cursor)));
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
        : [...endpoints];

    if (sortColumn) visibleEndpoints.sort(compareEndpoints);

    tableBody.replaceChildren();

    if (visibleEndpoints.length === 0) {
        const row = document.createElement('tr');
        row.className = 'empty-row';
        const cell = document.createElement('td');
        cell.colSpan = 5;
        cell.textContent = 'No endpoints to display.';
        row.append(cell);
        tableBody.append(row);
        return;
    }

    const columns = [
        ['Username', 'username'],
        ['Device name', 'deviceName'],
        ['IP', 'ip'],
        ['RustDesk ID', 'rustdeskId'],
        ['Extension', 'extension']
    ];

    for (const endpoint of visibleEndpoints) {
        const row = document.createElement('tr');
        const hasExactMatch = searchTerm && columns.some(([, property]) =>
            normalizeSearchValue(endpoint[property]).includes(searchTerm)
        );
        const bestFuzzyScore = searchTerm && !hasExactMatch
            ? Math.min(...columns.map(([, property]) => fieldMatchScore(endpoint[property], searchTerm)))
            : null;

        for (const [label, property] of columns) {
            const cell = document.createElement('td');
            cell.dataset.label = label;
            const useFuzzyMatch = bestFuzzyScore !== null
                && fieldMatchScore(endpoint[property], searchTerm) === bestFuzzyScore;
            appendHighlightedValue(cell, endpoint[property], searchTerm, useFuzzyMatch);
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
        const status = document.querySelector('#inventory-status');
        status.textContent = payload.sourceErrors?.webex
            ? 'Phone extensions are unavailable. The Webex connection needs attention.'
            : '';
        status.hidden = !status.textContent;
        renderEndpoints(searchInput.value);
    } catch (error) {
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        row.className = 'empty-row';
        const cell = document.createElement('td');
        cell.colSpan = 5;
        cell.textContent = `Could not load endpoints: ${error.message}`;
        row.append(cell);
        tableBody.append(row);
    }
}

searchInput.addEventListener('input', () => renderEndpoints(searchInput.value));
for (const button of sortButtons) {
    button.dataset.label = button.firstChild.textContent.trim();
    button.addEventListener('click', () => {
        sortDirection = sortColumn === button.dataset.sort && sortDirection === 'ascending'
            ? 'descending' : 'ascending';
        sortColumn = button.dataset.sort;
        updateSortHeadings();
        renderEndpoints(searchInput.value);
    });
}
updateSortHeadings();
loadEndpoints();
