# HPE OneView Hardware Inventory Reporter

Read-only Python tool that queries an HPE OneView appliance via its REST API and produces a normalized, one-row-per-component CSV inventory report. Covers all managed and monitored servers (rack, blade, Synergy) with full hardware detail — CPUs, memory, storage controllers, drives, network and FC adapters, firmware, power supplies, fans, BIOS, and PCIe devices.

Designed for HPE OneView 10.0+ (X-API-Version ≥ 5600). Includes an Azure DevOps pipeline template for scheduled reporting.

## Features

- **Automatic API version negotiation** — probes `/rest/version` and uses `currentVersion`; no hard-coded version required
- **53-column stable CSV schema** — server context columns (1–30) + component detail columns (31–53); safe for Power BI / CMDB import without re-mapping
- **Defensive parsing** — all field access via `dig()` helper; unknown or missing fields produce empty cells, never exceptions
- **N+1 avoidance** — enclosure, hardware-type, profile, rack-manager URIs are fetched once and cached per run
- **Read-only** — only GET + login POST + logout DELETE are issued; OneView state is never modified
- **Secret-safe** — password only via env var or interactive prompt; session token masked in logs; raw JSON dumps scrub credential-like keys
- **Azure DevOps ready** — includes pipeline YAML with secret variable handling, Secure File CA bundle support, and artifact publishing

## Quick Start

### Prerequisites

```
Python >= 3.9
pip install -r requirements.txt
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ONEVIEW_URL` | yes | `https://oneview.example.com` |
| `ONEVIEW_USERNAME` | yes | Read-only service account |
| `ONEVIEW_PASSWORD` | yes | Password (never pass as CLI arg) |
| `ONEVIEW_AUTH_DOMAIN` | no | Auth domain, default `LOCAL` |
| `ONEVIEW_API_VERSION` | no | Override API version (fallback only) |

### Run

```bash
# Minimal — timestamped CSV written to ./reports/
export ONEVIEW_URL="https://oneview.example.com"
export ONEVIEW_USERNAME="ov-readonly"
export ONEVIEW_PASSWORD='secret'
python oneview_hw_inventory_report.py

# Enterprise CA bundle
python oneview_hw_inventory_report.py --ca-bundle ./certs/corp-root-ca.pem

# Lab / self-signed (insecure — shows warning)
python oneview_hw_inventory_report.py --verify-tls false

# Dump raw per-server JSON (credentials scrubbed) for debugging
python oneview_hw_inventory_report.py --dump-raw-json-dir ./raw-json

# Strict mode — non-zero exit if any per-server parse failures
python oneview_hw_inventory_report.py --strict
```

## CSV Schema

Every row has all 53 columns. Empty cells indicate a value not present or not applicable for that component type.

**Server context (columns 1–30)** — identical across all rows for a given server:

`report_timestamp`, `oneview_appliance`, `oneview_api_version`, `server_name`, `server_hostname`, `server_uri`, `server_uuid`, `server_serial_number`, `server_model`, `server_generation`, `server_hardware_type`, `server_state`, `server_power_state`, `server_management_state`, `server_licensing_status`, `server_compliance_status`, `server_profile_name`, `server_profile_uri`, `server_profile_template_name`, `server_profile_template_uri`, `enclosure_name`, `enclosure_uri`, `enclosure_bay`, `rack_name`, `rack_uri`, `rack_manager`, `rack_manager_uri`, `ilo_address`, `ilo_hostname`, `ilo_firmware_version`

**Component detail (columns 31–53)**:

`component_category`, `component_type`, `component_name`, `component_location`, `component_slot`, `component_bay`, `component_port`, `component_model`, `component_manufacturer`, `component_part_number`, `component_spare_part_number`, `component_serial_number`, `component_firmware_version`, `component_capacity`, `component_capacity_bytes`, `component_speed`, `component_speed_mbps`, `component_mac_address`, `component_wwpn`, `component_wwnn`, `component_status`, `component_health`, `component_extra_json`

**`component_category` values**: `server-summary`, `cpu`, `memory`, `storage-controller`, `storage-logical-drive`, `storage-physical-drive`, `net-adapter`, `fc-adapter`, `cna-adapter`, `adapter`, `firmware`, `power-supply`, `fan`, `bios`, `security`, `pci`

The first row per server is always `server-summary` — filter on this to get exact server count without deduplication.

## OneView Endpoints Used

| Endpoint | Purpose |
|---|---|
| `GET /rest/version` | Discover supported `X-API-Version` |
| `POST /rest/login-sessions` | Authenticate |
| `DELETE /rest/login-sessions` | Logout |
| `GET /rest/server-hardware?start=&count=` | Paginated server list |
| `GET /rest/server-hardware/{id}` | Per-server inventory |
| `GET /rest/server-hardware/{id}/firmware` | Firmware sub-inventory |
| `GET /rest/server-hardware-types/{id}` | Hardware type details |
| `GET /rest/enclosures/{id}` | Enclosure/bay/rack context |
| `GET /rest/rack-managers/{id}` | Rack-manager context |
| `GET /rest/server-profiles/{id}` | Profile name and compliance |
| `GET /rest/server-profile-templates/{id}` | Template name |

## Azure DevOps Pipeline

See `azure-pipelines.yml`. Configure these pipeline variables (lock icon enabled):

| Variable | Notes |
|---|---|
| `oneviewUrl` | Appliance URL |
| `oneviewUsername` | Service account username |
| `oneviewPassword` | **Secret** — lock icon on |
| `oneviewAuthDomain` | Default: `LOCAL` |
| `caBundleSecureFile` | Secure File name (optional) |

The pipeline publishes the CSV as an artifact named `oneview-inventory` on every run, including on failure (partial results).

## Troubleshooting

**Authentication failed (401/403)** — Check `--auth-domain`; many sites need `LOCAL` rather than an AD domain. Verify the OneView role has at least *Read only* scope on Server Hardware.

**Certificate validation failed** — Supply `--ca-bundle ./corp-root-ca.pem` or use `--verify-tls false` in a lab environment.

**No servers returned** — Validate by browsing to `/rest/server-hardware` in your browser. Confirm servers are in *Managed* or *Monitored* state in the OneView UI.

**Missing component details** — Refresh the server in the OneView UI (*Actions → Refresh*), then re-run. Alternatively, extend with iLO Redfish (see source comments).

**API version mismatch (HTTP 400)** — Let `/rest/version` succeed (it works without authentication), or set `--api-version <currentVersion>` explicitly.

**Strict mode exits non-zero on otherwise-good output** — At least one server had a partial parse failure. Re-run with `--dump-raw-json-dir ./raw-json --log-level DEBUG` to identify which parser warned.

## Extending to iLO Redfish

For data OneView does not expose (per-DIMM detail on monitored-only servers, GPU metrics, NVMe SMART, full RAID metadata), take `server_ctx["ilo_address"]` and walk `/redfish/v1/Systems/1/Memory`, `/Processors`, `/Storage`, etc. Emit rows with the same `server_ctx` dict so they join naturally to OneView rows downstream. Gate behind `--enable-redfish-fallback` since iLO is often firewalled from CI runners.

## License

MIT
