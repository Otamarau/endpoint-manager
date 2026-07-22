# Endpoint Manager

Endpoint Manager is a small, self-hosted web inventory for viewing RustDesk and
ThreatDown endpoints in one searchable table. It reads RustDesk peer data from a
local SQLite database, retrieves devices from the ThreatDown API, and combines
matching records using their device name or IP address.

## Features

- Combines RustDesk and ThreatDown endpoint inventories
- Matches records by normalized device name or IP address
- Displays usernames, device names, IP addresses, and RustDesk IDs
- Includes typo-tolerant search and responsive mobile styling
- Reads the RustDesk database in read-only mode
- Protects the inventory behind a configurable passcode
- Continues with either inventory source if the other is unavailable

## Requirements

- Node.js 20 or newer
- A RustDesk SQLite database, ThreatDown API credentials, or both
- Network access to `https://api.threatdown.com` when using ThreatDown

## Installation

1. Clone the repository and enter its directory:

   ```sh
   git clone https://github.com/YOUR_USERNAME/endpoint-manager.git
   cd endpoint-manager
   ```

2. Install the dependencies:

   ```sh
   npm install
   ```

3. Copy `.env.example` to `.env` and edit the settings for your environment:

   ```sh
   cp .env.example .env
   ```

   On Windows PowerShell, use:

   ```powershell
   Copy-Item .env.example .env
   ```

4. Start the application:

   ```sh
   npm start
   ```

5. Open `http://localhost:3000` and enter the configured site passcode.

For development with automatic server restarts, run `npm run dev`.

## Configuration

Configuration is loaded from `.env` in the project directory.

| Variable | Required | Description |
| --- | --- | --- |
| `SITE_PASSCODE` | Yes | Passcode required before endpoint data can be viewed. |
| `PORT` | No | HTTP port. Defaults to `3000`. |
| `RUSTDESK_DB_PATH` | For RustDesk | Absolute path to the RustDesk `db_v2.sqlite3` database. |
| `THREATDOWN_CLIENT_ID` | For ThreatDown | ThreatDown OAuth client ID. |
| `THREATDOWN_CLIENT_SECRET` | For ThreatDown | ThreatDown OAuth client secret. |
| `THREATDOWN_ACCOUNT_ID` | For ThreatDown | ThreatDown account ID sent with API requests. |

At least one inventory source must be correctly configured and available. If
`RUSTDESK_DB_PATH` is omitted, the application looks for
`~/rustdesk/data/db_v2.sqlite3`.

The RustDesk database must contain a `peer` table with the fields used by
RustDesk Server Pro: `id`, `guid`, `uuid`, `created_at`, `info`, and `note`.

## How inventory merging works

Endpoint Manager first compares normalized device names (ignoring domains and
letter case). If those do not match, it compares the RustDesk IP address with
the usable IP addresses reported by ThreatDown. Unmatched records from either
source remain visible as separate endpoints.

Every request to `/api/endpoints` refreshes the inventory. A generated snapshot
is written to `data/rustdesk_inventory.json`; this file is ignored by Git.

## Security notes

This project is best suited to an internal network. The built-in passcode is a
small access-control layer, not a replacement for production authentication.
Sessions are stored in memory and are lost when the server restarts. The session
cookie is HTTP-only and same-site, but it is not marked `Secure` because the
development server uses HTTP.

For access outside a trusted network, place the application behind an HTTPS
reverse proxy and add appropriate authentication, firewall rules, and rate
limiting. Never commit `.env`, SQLite databases, or generated inventory files;
the included `.gitignore` excludes them.

## Project structure

```text
public/                 Browser interface
  scripts/script.js     Inventory rendering and search
  styles/styles.css     Responsive styling
server.js               Express server and inventory integrations
.env.example            Configuration template
```

## Troubleshooting

- **`SITE_PASSCODE is not configured`**: Add a non-empty `SITE_PASSCODE` to
  `.env`, then restart the server.
- **RustDesk database not found**: Set `RUSTDESK_DB_PATH` to the absolute path
  of `db_v2.sqlite3` and ensure the server process can read it.
- **Missing ThreatDown configuration**: Set all three `THREATDOWN_*` variables,
  or rely on a valid RustDesk database as the available inventory source.
- **No endpoints load**: Check the server output. The response fails only when
  neither source returns any endpoints.

