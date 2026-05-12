#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oneview_hw_inventory_report.py
==============================

On-demand HPE OneView hardware inventory CSV reporter.

Reads server hardware (managed + monitored, rack + blade + Synergy) visible
to an HPE OneView appliance via its REST API and produces a normalized,
one-row-per-component CSV inventory report.

Read-only.  Designed for HPE OneView 10.0+.  No state in OneView is changed.

Author: Infrastructure Automation
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import logging
import os
import re
import socket
import sys
import time
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - fallback for very old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

import urllib3


# --------------------------------------------------------------------------- #
# Module-level configuration
# --------------------------------------------------------------------------- #

LOG = logging.getLogger("oneview_hw_inventory")

# Fallback X-API-Version if /rest/version cannot be reached.  OneView 10.x
# typically returns currentVersion >= 5600.  This is intentionally configurable
# via --api-version / ONEVIEW_API_VERSION so operators are never stuck.
DEFAULT_API_VERSION = "5600"

# HTTP timeouts (connect, read)
DEFAULT_TIMEOUT: Tuple[int, int] = (15, 90)

# Pagination page size for collection endpoints.
DEFAULT_PAGE_SIZE = 100

# Retries for transient HTTP failures.
RETRY_STATUSES = (429, 500, 502, 503, 504)
RETRY_TOTAL = 5
RETRY_BACKOFF_FACTOR = 1.5

# Keys we will never write out in raw JSON dumps.
_SECRET_KEY_PATTERNS = re.compile(
    r"(?i)(password|secret|token|sessionid|x-api-key|authorization|auth)"
)


# --------------------------------------------------------------------------- #
# CSV schema
# --------------------------------------------------------------------------- #

SERVER_COLUMNS: List[str] = [
    "report_timestamp",
    "oneview_appliance",
    "oneview_api_version",
    "server_name",
    "server_hostname",
    "server_uri",
    "server_uuid",
    "server_serial_number",
    "server_model",
    "server_generation",
    "server_hardware_type",
    "server_state",
    "server_power_state",
    "server_management_state",
    "server_licensing_status",
    "server_compliance_status",
    "server_profile_name",
    "server_profile_uri",
    "server_profile_template_name",
    "server_profile_template_uri",
    "enclosure_name",
    "enclosure_uri",
    "enclosure_bay",
    "rack_name",
    "rack_uri",
    "rack_manager",
    "rack_manager_uri",
    "ilo_address",
    "ilo_hostname",
    "ilo_firmware_version",
]

COMPONENT_COLUMNS: List[str] = [
    "component_category",
    "component_type",
    "component_name",
    "component_location",
    "component_slot",
    "component_bay",
    "component_port",
    "component_model",
    "component_manufacturer",
    "component_part_number",
    "component_spare_part_number",
    "component_serial_number",
    "component_firmware_version",
    "component_capacity",
    "component_capacity_bytes",
    "component_speed",
    "component_speed_mbps",
    "component_mac_address",
    "component_wwpn",
    "component_wwnn",
    "component_status",
    "component_health",
    "component_extra_json",
]

CSV_COLUMNS: List[str] = SERVER_COLUMNS + COMPONENT_COLUMNS


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #

def dig(obj: Any, *path: Any, default: Any = None) -> Any:
    """Safe nested lookup through dicts and lists.

    dig(d, "a", "b", 0, "c") -> d["a"]["b"][0]["c"] or default if any step fails.
    """
    current = obj
    for key in path:
        if current is None:
            return default
        try:
            if isinstance(key, int):
                if isinstance(current, (list, tuple)) and -len(current) <= key < len(current):
                    current = current[key]
                else:
                    return default
            else:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
        except (TypeError, KeyError, IndexError):
            return default
    return current if current is not None else default


def as_list(value: Any) -> List[Any]:
    """Normalize to a list.  None -> [], scalar -> [scalar], list -> list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def safe_json(value: Any) -> str:
    """Serialize arbitrary structure to compact JSON; never raise."""
    if value is None or value == "" or value == {} or value == []:
        return ""
    try:
        return json.dumps(value, default=str, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return json.dumps(str(value))


def coerce_int(value: Any) -> Optional[int]:
    """Best-effort int conversion.  Returns None on failure."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def gib_to_bytes(gib: Any) -> Optional[int]:
    n = coerce_int(gib)
    return n * 1024 ** 3 if n is not None else None


def mib_to_bytes(mib: Any) -> Optional[int]:
    n = coerce_int(mib)
    return n * 1024 ** 2 if n is not None else None


def gb_to_bytes(gb: Any) -> Optional[int]:
    n = coerce_int(gb)
    return n * 1000 ** 3 if n is not None else None


def timestamp_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def scrub_secrets(obj: Any) -> Any:
    """Deep-copy `obj` removing anything that looks like a credential."""
    if isinstance(obj, dict):
        return {
            k: ("***" if _SECRET_KEY_PATTERNS.search(str(k)) else scrub_secrets(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [scrub_secrets(v) for v in obj]
    return obj


def mask(value: Optional[str]) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "***"
    return value[:2] + "***" + value[-2:]


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "unknown"


# --------------------------------------------------------------------------- #
# OneView REST client
# --------------------------------------------------------------------------- #

class OneViewError(RuntimeError):
    """Raised for fatal OneView client errors."""


class OneViewAuthError(OneViewError):
    """Raised on authentication / authorization failure."""


class OneViewClient:
    """Minimal, read-only HPE OneView REST client.

    - Probes /rest/version for X-API-Version.
    - Authenticates via /rest/login-sessions.
    - Generic GET with retries.
    - Paginated GET.
    """

    def __init__(
        self,
        base_url: str,
        verify: Any = True,
        timeout: Tuple[int, int] = DEFAULT_TIMEOUT,
        api_version_override: Optional[str] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.api_version: Optional[str] = api_version_override
        self.page_size = page_size

        self._session = requests.Session()
        retry = Retry(
            total=RETRY_TOTAL,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUSES,
            allowed_methods=frozenset(["GET", "POST", "DELETE"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

        self._auth_token: Optional[str] = None

    # ----- low-level -----------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.api_version:
            h["X-API-Version"] = str(self.api_version)
        if self._auth_token:
            h["Auth"] = self._auth_token
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        expect_json: bool = True,
        anonymous: bool = False,
    ) -> Any:
        url = self._url(path)
        headers = self._headers()
        if anonymous:
            headers.pop("Auth", None)

        try:
            resp = self._session.request(
                method,
                url,
                params=params,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except requests.exceptions.SSLError as exc:
            raise OneViewError(
                f"TLS verification failed for {self.base_url}: {exc}. "
                "Use --ca-bundle to supply your enterprise CA or --verify-tls false "
                "for lab environments only."
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise OneViewError(
                f"Unable to reach OneView appliance at {self.base_url}: {exc}"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise OneViewError(
                f"Timeout talking to OneView appliance at {self.base_url}: {exc}"
            ) from exc

        if resp.status_code == 401 or resp.status_code == 403:
            raise OneViewAuthError(
                f"OneView returned {resp.status_code} for {method} {path}. "
                "Check credentials, authLoginDomain, and that the user has read access."
            )

        if resp.status_code >= 400:
            # Try to surface OneView's structured error body if present.
            try:
                err_body = resp.json()
            except ValueError:
                err_body = resp.text[:500]
            raise OneViewError(
                f"OneView {method} {path} -> HTTP {resp.status_code}: "
                f"{scrub_secrets(err_body)!r}"
            )

        if not expect_json or resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    # ----- high level ----------------------------------------------------

    def discover_api_version(self, prefer_current: bool = True) -> str:
        """Hit /rest/version and pick an X-API-Version to use for the session.

        Falls back to the configured override / DEFAULT_API_VERSION on failure.
        """
        try:
            # Use a transient minimal API-Version header just to satisfy
            # appliances that require it even on /rest/version.
            headers = {"X-API-Version": str(self.api_version or DEFAULT_API_VERSION)}
            resp = self._session.get(
                self._url("/rest/version"),
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
            )
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:
            LOG.warning(
                "Could not probe /rest/version (%s). Falling back to X-API-Version=%s",
                exc,
                self.api_version or DEFAULT_API_VERSION,
            )
            self.api_version = str(self.api_version or DEFAULT_API_VERSION)
            return self.api_version

        current = body.get("currentVersion")
        minimum = body.get("minimumVersion")
        LOG.info(
            "OneView /rest/version reports currentVersion=%s minimumVersion=%s",
            current,
            minimum,
        )
        chosen = current if prefer_current and current else (current or minimum or DEFAULT_API_VERSION)
        self.api_version = str(chosen)
        return self.api_version

    def login(self, username: str, password: str, auth_domain: Optional[str] = None) -> None:
        body: Dict[str, Any] = {"userName": username, "password": password}
        if auth_domain:
            body["authLoginDomain"] = auth_domain
        result = self._request(
            "POST",
            "/rest/login-sessions",
            json_body=body,
            anonymous=True,
        )
        token = dig(result, "sessionID")
        if not token:
            raise OneViewAuthError(
                "Login succeeded HTTP-wise but no sessionID was returned by OneView."
            )
        self._auth_token = token
        LOG.info("Authenticated to %s as %s (token=%s)", self.base_url, username, mask(token))

    def logout(self) -> None:
        if not self._auth_token:
            return
        try:
            self._request("DELETE", "/rest/login-sessions", expect_json=False)
            LOG.debug("Logged out of OneView.")
        except Exception as exc:
            LOG.debug("Logout failed (non-fatal): %s", exc)
        finally:
            self._auth_token = None

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", path, params=params)

    def get_collection(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        page_size: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Iterate all pages of a OneView collection endpoint.

        Honors `nextPageUri` when present; otherwise advances `start`.
        """
        out: List[Dict[str, Any]] = []
        start = 0
        size = page_size or self.page_size
        current_path: Optional[str] = path
        current_params: Optional[Dict[str, Any]] = dict(params or {})
        current_params.setdefault("start", start)
        current_params.setdefault("count", size)

        while current_path:
            body = self.get(current_path, params=current_params)
            members = dig(body, "members") or []
            out.extend(members)
            next_uri = dig(body, "nextPageUri")
            total = dig(body, "total")
            LOG.debug(
                "Paged %s start=%s count=%s -> got %d/%s",
                current_path,
                current_params.get("start") if current_params else None,
                current_params.get("count") if current_params else None,
                len(members),
                total,
            )
            if next_uri:
                current_path = next_uri
                current_params = None  # nextPageUri already encodes start/count
                continue
            # Manual advance fallback
            if not members:
                break
            start += len(members)
            if total is not None and start >= int(total):
                break
            current_params = {"start": start, "count": size}
            if params:
                for k, v in params.items():
                    current_params.setdefault(k, v)
        return out


# --------------------------------------------------------------------------- #
# Component row builder
# --------------------------------------------------------------------------- #

def _empty_component_dict() -> Dict[str, Any]:
    return {col: "" for col in COMPONENT_COLUMNS}


def make_component_row(
    server_ctx: Dict[str, Any],
    category: str,
    *,
    type_: str = "",
    name: str = "",
    location: str = "",
    slot: Any = "",
    bay: Any = "",
    port: Any = "",
    model: str = "",
    manufacturer: str = "",
    part_number: str = "",
    spare_part_number: str = "",
    serial_number: str = "",
    firmware_version: str = "",
    capacity: str = "",
    capacity_bytes: Any = "",
    speed: str = "",
    speed_mbps: Any = "",
    mac_address: str = "",
    wwpn: str = "",
    wwnn: str = "",
    status: str = "",
    health: str = "",
    extra: Any = None,
) -> Dict[str, Any]:
    row = dict(server_ctx)  # copy server-level columns
    row.update(_empty_component_dict())
    row["component_category"] = category or ""
    row["component_type"] = type_ or ""
    row["component_name"] = name or ""
    row["component_location"] = location or ""
    row["component_slot"] = "" if slot in (None, "") else str(slot)
    row["component_bay"] = "" if bay in (None, "") else str(bay)
    row["component_port"] = "" if port in (None, "") else str(port)
    row["component_model"] = model or ""
    row["component_manufacturer"] = manufacturer or ""
    row["component_part_number"] = part_number or ""
    row["component_spare_part_number"] = spare_part_number or ""
    row["component_serial_number"] = serial_number or ""
    row["component_firmware_version"] = firmware_version or ""
    row["component_capacity"] = capacity or ""
    row["component_capacity_bytes"] = "" if capacity_bytes in (None, "") else str(capacity_bytes)
    row["component_speed"] = speed or ""
    row["component_speed_mbps"] = "" if speed_mbps in (None, "") else str(speed_mbps)
    row["component_mac_address"] = mac_address or ""
    row["component_wwpn"] = wwpn or ""
    row["component_wwnn"] = wwnn or ""
    row["component_status"] = status or ""
    row["component_health"] = health or ""
    row["component_extra_json"] = safe_json(extra) if extra else ""
    return row


# --------------------------------------------------------------------------- #
# Parsers - one per logical hardware category
# --------------------------------------------------------------------------- #
#
# These parsers tolerate missing data.  OneView field names below have been
# observed across OneView 5.x-10.x and HPE iLO Redfish-derived inventory
# sections that OneView surfaces.  When a field is not present, the helper
# returns "".  Anything we discover but don't have a column for is preserved
# in component_extra_json.
#
# Operators integrating new OneView versions or new firmware: validate
# field names against a live /rest/server-hardware/{id} response.

def parse_server_identity(
    server: Dict[str, Any],
    sh_type: Optional[Dict[str, Any]],
    enclosure: Optional[Dict[str, Any]],
    rack_manager: Optional[Dict[str, Any]],
    profile: Optional[Dict[str, Any]],
    template: Optional[Dict[str, Any]],
    appliance_url: str,
    api_version: str,
    report_ts: str,
) -> Dict[str, Any]:
    """Build the server-context column dict that prefixes every row."""

    model = dig(server, "model") or dig(sh_type, "model") or ""
    generation = dig(sh_type, "generation") or _guess_generation(model)
    sh_type_name = dig(sh_type, "name") or dig(server, "serverHardwareTypeName") or ""

    ilo_address = (
        dig(server, "mpHostInfo", "mpIpAddresses", 0, "address")
        or dig(server, "mpIpAddress")
        or ""
    )
    ilo_hostname = (
        dig(server, "mpHostInfo", "mpHostName")
        or dig(server, "mpDnsName")
        or ""
    )
    ilo_fw = dig(server, "mpFirmwareVersion") or ""

    enclosure_name = dig(enclosure, "name") or ""
    enclosure_uri = dig(server, "locationUri") or dig(enclosure, "uri") or ""
    enclosure_bay = dig(server, "position") or ""

    # OneView surfaces rack info either on the server, on the enclosure, or
    # via a rack-manager resource.
    rack_name = (
        dig(server, "rackName")
        or dig(enclosure, "rackName")
        or dig(rack_manager, "rackName")
        or ""
    )
    rack_uri = (
        dig(server, "rackUri")
        or dig(enclosure, "rackUri")
        or ""
    )
    rack_manager_name = dig(rack_manager, "name") or ""
    rack_manager_uri = dig(rack_manager, "uri") or dig(server, "rackManagerUri") or ""

    return {
        "report_timestamp": report_ts,
        "oneview_appliance": appliance_url,
        "oneview_api_version": str(api_version),
        "server_name": dig(server, "name") or dig(server, "serverName") or "",
        "server_hostname": dig(server, "serverName") or dig(server, "shortModel") or "",
        "server_uri": dig(server, "uri") or "",
        "server_uuid": dig(server, "uuid") or "",
        "server_serial_number": dig(server, "serialNumber") or "",
        "server_model": model,
        "server_generation": generation,
        "server_hardware_type": sh_type_name,
        "server_state": dig(server, "state") or "",
        "server_power_state": dig(server, "powerState") or "",
        "server_management_state": dig(server, "stateReason") or dig(server, "refreshState") or "",
        "server_licensing_status": dig(server, "licensingIntent") or "",
        "server_compliance_status": (
            dig(profile, "templateCompliance")
            or dig(server, "profileComplianceStatus")
            or ""
        ),
        "server_profile_name": dig(profile, "name") or "",
        "server_profile_uri": dig(server, "serverProfileUri") or dig(profile, "uri") or "",
        "server_profile_template_name": dig(template, "name") or "",
        "server_profile_template_uri": dig(profile, "serverProfileTemplateUri") or dig(template, "uri") or "",
        "enclosure_name": enclosure_name,
        "enclosure_uri": enclosure_uri,
        "enclosure_bay": str(enclosure_bay) if enclosure_bay not in (None, "") else "",
        "rack_name": rack_name,
        "rack_uri": rack_uri,
        "rack_manager": rack_manager_name,
        "rack_manager_uri": rack_manager_uri,
        "ilo_address": ilo_address,
        "ilo_hostname": ilo_hostname,
        "ilo_firmware_version": ilo_fw,
    }


def _guess_generation(model: str) -> str:
    """Best-effort generation extraction from model string (e.g. 'Gen10', 'Gen11')."""
    if not model:
        return ""
    m = re.search(r"Gen\s?(\d+)", model)
    return f"Gen{m.group(1)}" if m else ""


def parse_server_summary_row(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> Dict[str, Any]:
    """Single roll-up row per server: CPU count/cores, total RAM, etc."""
    cpu_count = dig(server, "processorCount")
    cpu_cores = dig(server, "processorCoreCount")
    cpu_speed = dig(server, "processorSpeedMhz")
    cpu_type = dig(server, "processorType") or ""
    memory_mb = dig(server, "memoryMb")
    memory_bytes = mib_to_bytes(memory_mb)

    summary = {
        "processorCount": cpu_count,
        "processorCoreCount": cpu_cores,
        "processorType": cpu_type,
        "processorSpeedMhz": cpu_speed,
        "memoryMb": memory_mb,
        "formFactor": dig(server, "formFactor"),
        "intelligentProvisioningVersion": dig(server, "intelligentProvisioningVersion"),
        "romVersion": dig(server, "romVersion"),
        "shortModel": dig(server, "shortModel"),
        "assetTag": dig(server, "assetTag"),
        "oneViewVersion": dig(server, "currentVersion") or dig(server, "version"),
    }

    return make_component_row(
        server_ctx,
        category="server-summary",
        type_="summary",
        name=server_ctx.get("server_name", ""),
        model=server_ctx.get("server_model", ""),
        serial_number=server_ctx.get("server_serial_number", ""),
        firmware_version=dig(server, "romVersion") or "",
        capacity=f"{memory_mb} MB" if memory_mb else "",
        capacity_bytes=memory_bytes,
        speed=f"{cpu_speed} MHz" if cpu_speed else "",
        status=server_ctx.get("server_state", ""),
        health=dig(server, "status") or "",
        extra=summary,
    )


def parse_processors(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-socket CPU rows.  If only roll-up counts are available, emit one row."""
    rows: List[Dict[str, Any]] = []

    # Per-socket detail (when OneView surfaces it).
    detailed = (
        dig(server, "processors")
        or dig(server, "subResources", "Processors", "members")
        or dig(server, "serverInventory", "processors")
        or []
    )
    if isinstance(detailed, list) and detailed:
        for idx, p in enumerate(detailed):
            rows.append(
                make_component_row(
                    server_ctx,
                    category="cpu",
                    type_="processor",
                    name=dig(p, "Name") or dig(p, "name") or dig(p, "model") or f"CPU{idx + 1}",
                    location=dig(p, "Socket") or dig(p, "socket") or "",
                    slot=dig(p, "Socket") or dig(p, "socket") or idx + 1,
                    model=dig(p, "Model") or dig(p, "model") or "",
                    manufacturer=dig(p, "Manufacturer") or dig(p, "manufacturer") or "",
                    speed=str(dig(p, "MaxSpeedMHz") or dig(p, "speedMhz") or dig(p, "speed") or ""),
                    speed_mbps=coerce_int(dig(p, "MaxSpeedMHz") or dig(p, "speedMhz") or dig(p, "speed")),
                    status=dig(p, "Status", "State") or dig(p, "status") or "",
                    health=dig(p, "Status", "Health") or dig(p, "health") or "",
                    extra={
                        "totalCores": dig(p, "TotalCores") or dig(p, "totalCores") or dig(p, "coreCount"),
                        "totalThreads": dig(p, "TotalThreads") or dig(p, "totalThreads") or dig(p, "threadCount"),
                        "instructionSet": dig(p, "InstructionSet"),
                        "architecture": dig(p, "ProcessorArchitecture"),
                    },
                )
            )
        return rows

    # Fallback: roll-up only.
    cpu_count = coerce_int(dig(server, "processorCount"))
    if cpu_count and cpu_count > 0:
        per_socket_cores = coerce_int(dig(server, "processorCoreCount"))
        speed = coerce_int(dig(server, "processorSpeedMhz"))
        cpu_type = dig(server, "processorType") or ""
        for i in range(cpu_count):
            rows.append(
                make_component_row(
                    server_ctx,
                    category="cpu",
                    type_="processor",
                    name=f"CPU{i + 1}",
                    location=f"Socket {i + 1}",
                    slot=i + 1,
                    model=cpu_type,
                    speed=f"{speed} MHz" if speed else "",
                    speed_mbps=speed,
                    extra={"coresPerSocket": per_socket_cores, "source": "roll-up"},
                )
            )
    return rows


def parse_memory(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-DIMM rows if exposed; else a single 'memory-total' row."""
    rows: List[Dict[str, Any]] = []

    dimms = (
        dig(server, "memoryModules")
        or dig(server, "memory", "members")
        or dig(server, "subResources", "Memory", "members")
        or dig(server, "serverInventory", "memory", "dimms")
        or []
    )
    if isinstance(dimms, list) and dimms:
        for idx, d in enumerate(dimms):
            size_mb = (
                coerce_int(dig(d, "CapacityMiB"))
                or coerce_int(dig(d, "sizeMb"))
                or coerce_int(dig(d, "capacityMiB"))
            )
            speed_mhz = (
                coerce_int(dig(d, "OperatingSpeedMhz"))
                or coerce_int(dig(d, "speedMhz"))
                or coerce_int(dig(d, "speed"))
            )
            rows.append(
                make_component_row(
                    server_ctx,
                    category="memory",
                    type_=dig(d, "MemoryType") or dig(d, "type") or "DIMM",
                    name=dig(d, "Name") or dig(d, "name") or dig(d, "DeviceLocator") or f"DIMM{idx + 1}",
                    location=dig(d, "DeviceLocator") or dig(d, "location") or "",
                    slot=dig(d, "Socket") or dig(d, "slot") or "",
                    model=dig(d, "Model") or "",
                    manufacturer=dig(d, "Manufacturer") or dig(d, "manufacturer") or "",
                    part_number=dig(d, "PartNumber") or dig(d, "partNumber") or "",
                    spare_part_number=dig(d, "SparePartNumber") or dig(d, "sparePartNumber") or "",
                    serial_number=dig(d, "SerialNumber") or dig(d, "serialNumber") or "",
                    capacity=f"{size_mb} MB" if size_mb else "",
                    capacity_bytes=mib_to_bytes(size_mb),
                    speed=f"{speed_mhz} MHz" if speed_mhz else "",
                    speed_mbps=speed_mhz,
                    status=dig(d, "Status", "State") or dig(d, "status") or "",
                    health=dig(d, "Status", "Health") or dig(d, "health") or "",
                    extra={
                        "memoryDeviceType": dig(d, "MemoryDeviceType"),
                        "rankCount": dig(d, "RankCount"),
                        "minVoltageVolt": dig(d, "MinVoltageMillivolts"),
                        "errorCorrection": dig(d, "ErrorCorrection"),
                    },
                )
            )
        return rows

    # Fallback: total memory only.
    total_mb = coerce_int(dig(server, "memoryMb"))
    if total_mb:
        rows.append(
            make_component_row(
                server_ctx,
                category="memory",
                type_="memory-total",
                name="System Memory (roll-up)",
                capacity=f"{total_mb} MB",
                capacity_bytes=mib_to_bytes(total_mb),
                extra={"source": "roll-up"},
            )
        )
    return rows


def parse_local_storage(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Controllers, logical drives, physical drives."""
    rows: List[Dict[str, Any]] = []

    controllers = (
        dig(server, "localStorage", "data", "Controllers")
        or dig(server, "localStorage", "Controllers")
        or dig(server, "localStorageControllers")
        or dig(server, "subResources", "LocalStorage", "members")
        or []
    )
    if not isinstance(controllers, list):
        controllers = []

    for ctrl in controllers:
        ctrl_slot = dig(ctrl, "Location") or dig(ctrl, "slotNumber") or ""
        ctrl_name = dig(ctrl, "Name") or dig(ctrl, "model") or dig(ctrl, "Model") or "Storage Controller"
        ctrl_fw = (
            dig(ctrl, "FirmwareVersion", "Current", "VersionString")
            or dig(ctrl, "firmwareVersion")
            or ""
        )
        rows.append(
            make_component_row(
                server_ctx,
                category="storage-controller",
                type_=dig(ctrl, "ControllerType") or "controller",
                name=ctrl_name,
                location=str(ctrl_slot),
                slot=ctrl_slot,
                model=dig(ctrl, "Model") or "",
                manufacturer=dig(ctrl, "Manufacturer") or "",
                serial_number=dig(ctrl, "SerialNumber") or "",
                firmware_version=ctrl_fw,
                status=dig(ctrl, "Status", "State") or dig(ctrl, "status") or "",
                health=dig(ctrl, "Status", "Health") or "",
                extra={
                    "cacheMemorySizeMiB": dig(ctrl, "CacheMemorySizeMiB"),
                    "supportedRAIDLevels": dig(ctrl, "SupportedRAIDLevels"),
                },
            )
        )

        # Logical drives
        for ld in as_list(dig(ctrl, "LogicalDrives") or dig(ctrl, "logicalDrives")):
            cap_mib = coerce_int(dig(ld, "CapacityMiB") or dig(ld, "capacityMiB"))
            rows.append(
                make_component_row(
                    server_ctx,
                    category="storage-logical-drive",
                    type_=dig(ld, "Raid") or dig(ld, "raidLevel") or "logical-drive",
                    name=dig(ld, "LogicalDriveName") or dig(ld, "VolumeUniqueIdentifier") or "",
                    location=f"Controller {ctrl_slot}",
                    slot=ctrl_slot,
                    capacity=f"{cap_mib} MiB" if cap_mib else "",
                    capacity_bytes=mib_to_bytes(cap_mib),
                    status=dig(ld, "Status", "State") or "",
                    health=dig(ld, "Status", "Health") or "",
                    extra=ld,
                )
            )

        # Physical drives
        for pd in as_list(dig(ctrl, "PhysicalDrives") or dig(ctrl, "physicalDrives")):
            cap_gb = coerce_int(dig(pd, "CapacityGB") or dig(pd, "capacityGB"))
            cap_bytes = (
                gb_to_bytes(cap_gb)
                if cap_gb
                else mib_to_bytes(coerce_int(dig(pd, "CapacityMiB")))
            )
            rows.append(
                make_component_row(
                    server_ctx,
                    category="storage-physical-drive",
                    type_=dig(pd, "MediaType") or dig(pd, "mediaType") or "drive",
                    name=dig(pd, "Model") or dig(pd, "model") or "",
                    location=f"Bay {dig(pd, 'Location') or dig(pd, 'bay') or ''}",
                    bay=dig(pd, "Location") or dig(pd, "bay") or "",
                    slot=ctrl_slot,
                    model=dig(pd, "Model") or dig(pd, "model") or "",
                    manufacturer=dig(pd, "Manufacturer") or "",
                    part_number=dig(pd, "PartNumber") or "",
                    serial_number=dig(pd, "SerialNumber") or dig(pd, "serialNumber") or "",
                    firmware_version=dig(pd, "FirmwareVersion", "Current", "VersionString") or dig(pd, "firmwareVersion") or "",
                    capacity=f"{cap_gb} GB" if cap_gb else "",
                    capacity_bytes=cap_bytes,
                    speed=str(dig(pd, "InterfaceSpeedMbps") or dig(pd, "interfaceSpeedMbps") or ""),
                    speed_mbps=coerce_int(dig(pd, "InterfaceSpeedMbps") or dig(pd, "interfaceSpeedMbps")),
                    status=dig(pd, "Status", "State") or "",
                    health=dig(pd, "Status", "Health") or "",
                    extra={
                        "interfaceType": dig(pd, "InterfaceType") or dig(pd, "interfaceType"),
                        "rotationalSpeedRpm": dig(pd, "RotationalSpeedRpm"),
                        "encryptedDrive": dig(pd, "EncryptedDrive"),
                    },
                )
            )

    return rows


def parse_network_adapters(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Ethernet/FC/CNA/HBA ports.  OneView's portMap is the canonical source."""
    rows: List[Dict[str, Any]] = []
    device_slots = dig(server, "portMap", "deviceSlots") or []
    if not isinstance(device_slots, list):
        device_slots = []

    for slot in device_slots:
        slot_location = dig(slot, "location") or dig(slot, "deviceName") or ""
        slot_number = dig(slot, "slotNumber")
        adapter_name = dig(slot, "deviceName") or f"Adapter {slot_number}"
        adapter_model = dig(slot, "deviceName") or ""

        # Cards reported without ports still warrant a row.
        ports = dig(slot, "physicalPorts") or []
        if not ports:
            rows.append(
                make_component_row(
                    server_ctx,
                    category="adapter",
                    type_="adapter",
                    name=adapter_name,
                    location=str(slot_location),
                    slot=slot_number,
                    model=adapter_model,
                    extra=slot,
                )
            )
            continue

        for port in ports:
            port_type = (dig(port, "type") or "").lower()  # Ethernet | FibreChannel | etc.
            port_number = dig(port, "portNumber")
            mac = ""
            wwpn = ""
            wwnn = ""

            # virtualPorts often carries identifiers on Synergy/blade hardware.
            vports = dig(port, "virtualPorts") or []
            for vp in vports:
                vp_type = (dig(vp, "portFunction") or dig(vp, "type") or "").lower()
                if "wwpn" in vp_type or "fc" in vp_type:
                    wwpn = wwpn or dig(vp, "wwpn") or ""
                    wwnn = wwnn or dig(vp, "wwnn") or ""
                elif "mac" in vp_type or "eth" in vp_type:
                    mac = mac or dig(vp, "mac") or ""

            mac = mac or dig(port, "mac") or ""
            wwpn = wwpn or dig(port, "wwpn") or ""
            wwnn = wwnn or dig(port, "wwnn") or ""

            if "fibre" in port_type or "fc" in port_type or wwpn:
                category = "fc-adapter"
            elif "converged" in port_type:
                category = "cna-adapter"
            else:
                category = "net-adapter"

            speed_mbps = coerce_int(dig(port, "interconnectPortLinkSpeed") or dig(port, "linkSpeed"))
            rows.append(
                make_component_row(
                    server_ctx,
                    category=category,
                    type_=port_type or "port",
                    name=f"{adapter_name} Port {port_number}",
                    location=str(slot_location),
                    slot=slot_number,
                    port=port_number,
                    model=adapter_model,
                    speed=str(speed_mbps) + " Mbps" if speed_mbps else "",
                    speed_mbps=speed_mbps,
                    mac_address=mac,
                    wwpn=wwpn,
                    wwnn=wwnn,
                    status=dig(port, "linkState") or "",
                    health=dig(port, "interconnectPortState") or "",
                    extra={
                        "interconnectUri": dig(port, "interconnectUri"),
                        "interconnectName": dig(port, "interconnectName"),
                        "virtualPorts": vports,
                        "oneConnectId": dig(port, "oneConnectId"),
                    },
                )
            )
    return rows


def parse_firmware_inventory(
    server_ctx: Dict[str, Any],
    firmware: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Use the dedicated firmware sub-resource if present."""
    rows: List[Dict[str, Any]] = []
    if not firmware:
        return rows
    components = dig(firmware, "components") or dig(firmware, "members") or []
    for c in components:
        rows.append(
            make_component_row(
                server_ctx,
                category="firmware",
                type_=dig(c, "componentType") or dig(c, "type") or "firmware",
                name=dig(c, "componentName") or dig(c, "name") or "",
                location=dig(c, "componentLocation") or dig(c, "location") or "",
                model=dig(c, "componentKey") or "",
                firmware_version=dig(c, "componentVersion") or dig(c, "version") or "",
                status=dig(c, "componentStatus") or dig(c, "status") or "",
                health=dig(c, "complianceState") or dig(c, "baselineCompliance") or "",
                extra={
                    "baselineVersion": dig(c, "baselineVersion"),
                    "installationDate": dig(c, "installationDate"),
                },
            )
        )
    return rows


def parse_power_supplies(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    psus = (
        dig(server, "powerSupplies")
        or dig(server, "power", "members")
        or dig(server, "subResources", "Power", "members")
        or []
    )
    rows: List[Dict[str, Any]] = []
    for idx, p in enumerate(as_list(psus)):
        capacity_w = coerce_int(dig(p, "PowerCapacityWatts") or dig(p, "capacityWatts"))
        rows.append(
            make_component_row(
                server_ctx,
                category="power-supply",
                type_=dig(p, "PowerSupplyType") or "psu",
                name=dig(p, "Name") or dig(p, "name") or f"PSU{idx + 1}",
                location=str(dig(p, "MemberId") or idx + 1),
                bay=dig(p, "MemberId") or idx + 1,
                model=dig(p, "Model") or dig(p, "model") or "",
                manufacturer=dig(p, "Manufacturer") or dig(p, "manufacturer") or "",
                part_number=dig(p, "PartNumber") or "",
                spare_part_number=dig(p, "SparePartNumber") or "",
                serial_number=dig(p, "SerialNumber") or dig(p, "serialNumber") or "",
                firmware_version=dig(p, "FirmwareVersion") or "",
                capacity=f"{capacity_w} W" if capacity_w else "",
                capacity_bytes="",  # power isn't bytes
                status=dig(p, "Status", "State") or dig(p, "status") or "",
                health=dig(p, "Status", "Health") or "",
                extra=p,
            )
        )
    return rows


def parse_fans(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    fans = (
        dig(server, "fans")
        or dig(server, "thermal", "Fans")
        or dig(server, "subResources", "Thermal", "members")
        or []
    )
    rows: List[Dict[str, Any]] = []
    for idx, f in enumerate(as_list(fans)):
        rows.append(
            make_component_row(
                server_ctx,
                category="fan",
                type_="fan",
                name=dig(f, "Name") or dig(f, "name") or f"Fan{idx + 1}",
                location=str(dig(f, "MemberId") or idx + 1),
                bay=dig(f, "MemberId") or idx + 1,
                model=dig(f, "Model") or "",
                serial_number=dig(f, "SerialNumber") or "",
                status=dig(f, "Status", "State") or dig(f, "status") or "",
                health=dig(f, "Status", "Health") or "",
                extra=f,
            )
        )
    return rows


def parse_bios_security(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    rom = dig(server, "romVersion") or dig(server, "biosVersion")
    bios_date = dig(server, "biosDate") or dig(server, "romDate")
    if rom or bios_date:
        rows.append(
            make_component_row(
                server_ctx,
                category="bios",
                type_="bios",
                name="System ROM/BIOS",
                firmware_version=str(rom or ""),
                extra={"biosDate": bios_date},
            )
        )

    tpm = (
        dig(server, "trustedPlatformModule")
        or dig(server, "tpm")
        or dig(server, "subResources", "TrustedModules")
    )
    if tpm:
        for idx, t in enumerate(as_list(tpm)):
            rows.append(
                make_component_row(
                    server_ctx,
                    category="security",
                    type_="tpm",
                    name=dig(t, "Name") or f"TPM{idx + 1}",
                    model=dig(t, "InterfaceType") or dig(t, "interfaceType") or "",
                    firmware_version=dig(t, "FirmwareVersion") or "",
                    status=dig(t, "Status", "State") or "",
                    health=dig(t, "Status", "Health") or "",
                    extra=t,
                )
            )

    secure_boot = dig(server, "secureBootEnabled") or dig(server, "subResources", "SecureBoot")
    if secure_boot is not None and secure_boot != {}:
        rows.append(
            make_component_row(
                server_ctx,
                category="security",
                type_="secure-boot",
                name="Secure Boot",
                status="Enabled" if secure_boot is True else ("Disabled" if secure_boot is False else ""),
                extra={"raw": secure_boot},
            )
        )

    boot_mode = dig(server, "bootMode") or dig(server, "bios", "bootMode")
    if boot_mode:
        rows.append(
            make_component_row(
                server_ctx,
                category="security",
                type_="boot-mode",
                name="Boot Mode",
                status=str(boot_mode),
            )
        )
    return rows


def parse_pci_devices(server_ctx: Dict[str, Any], server: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    pci = (
        dig(server, "pciDevices")
        or dig(server, "PciDevices")
        or dig(server, "subResources", "PCIDevices", "members")
        or []
    )
    for idx, dev in enumerate(as_list(pci)):
        rows.append(
            make_component_row(
                server_ctx,
                category="pci",
                type_=dig(dev, "DeviceType") or dig(dev, "deviceType") or "pci",
                name=dig(dev, "Name") or dig(dev, "deviceName") or f"PCI{idx + 1}",
                location=dig(dev, "LocationString") or dig(dev, "location") or "",
                slot=dig(dev, "BusNumber"),
                model=dig(dev, "DeviceProductName") or dig(dev, "model") or "",
                part_number=dig(dev, "DeviceID") or "",
                status=dig(dev, "Status", "State") or "",
                health=dig(dev, "Status", "Health") or "",
                extra=dev,
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# Top-level orchestrator
# --------------------------------------------------------------------------- #

class InventoryReporter:
    def __init__(
        self,
        client: OneViewClient,
        appliance_url: str,
        dump_json_dir: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self.client = client
        self.appliance_url = appliance_url
        self.dump_json_dir = dump_json_dir
        self.strict = strict
        self.report_ts = timestamp_now_iso()

        # caches
        self._sh_type_cache: Dict[str, Dict[str, Any]] = {}
        self._enclosure_cache: Dict[str, Dict[str, Any]] = {}
        self._rack_manager_cache: Dict[str, Dict[str, Any]] = {}
        self._profile_cache: Dict[str, Dict[str, Any]] = {}
        self._template_cache: Dict[str, Dict[str, Any]] = {}

        self.stats = {
            "discovered": 0,
            "succeeded": 0,
            "partial": 0,
            "failed": 0,
            "rows_written": 0,
        }

    # ---- cached lookups ----

    def _get_cached(self, cache: Dict[str, Dict[str, Any]], uri: Optional[str]) -> Optional[Dict[str, Any]]:
        if not uri:
            return None
        if uri in cache:
            return cache[uri]
        try:
            data = self.client.get(uri)
            cache[uri] = data or {}
            return cache[uri]
        except Exception as exc:
            LOG.warning("Could not fetch %s: %s", uri, exc)
            cache[uri] = {}
            return cache[uri]

    # ---- per-server pipeline ----

    def _maybe_dump_json(self, name: str, payload: Any) -> None:
        if not self.dump_json_dir:
            return
        try:
            os.makedirs(self.dump_json_dir, exist_ok=True)
            path = os.path.join(self.dump_json_dir, slugify(name) + ".json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(scrub_secrets(payload), fh, indent=2, default=str)
        except Exception as exc:
            LOG.warning("Failed to write raw JSON dump for %s: %s", name, exc)

    def _try(self, label: str, fn: Callable[[], Any], default: Any = None) -> Any:
        try:
            return fn()
        except Exception as exc:
            LOG.warning("Sub-resource '%s' failed: %s", label, exc)
            return default

    def process_server(self, server_summary: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
        """Returns (rows, partial_failure_flag).  Raises only on truly fatal errors."""
        partial = False
        rows: List[Dict[str, Any]] = []

        server_uri = dig(server_summary, "uri")
        server_name = dig(server_summary, "name") or server_uri or "<unnamed>"
        LOG.info("Processing server %s", server_name)

        # Detailed GET
        try:
            server = self.client.get(server_uri) if server_uri else server_summary
        except Exception as exc:
            LOG.error("Failed to GET %s: %s", server_uri, exc)
            self.stats["failed"] += 1
            return [], True

        # Enrichment
        sh_type = self._get_cached(self._sh_type_cache, dig(server, "serverHardwareTypeUri"))
        enclosure = self._get_cached(self._enclosure_cache, dig(server, "locationUri"))
        rack_mgr_uri = dig(server, "rackManagerUri") or dig(enclosure, "rackManagerUri")
        rack_manager = self._get_cached(self._rack_manager_cache, rack_mgr_uri) if rack_mgr_uri else None

        profile_uri = dig(server, "serverProfileUri")
        profile = self._get_cached(self._profile_cache, profile_uri) if profile_uri else None
        template_uri = dig(profile, "serverProfileTemplateUri") if profile else None
        template = self._get_cached(self._template_cache, template_uri) if template_uri else None

        server_ctx = parse_server_identity(
            server,
            sh_type,
            enclosure,
            rack_manager,
            profile,
            template,
            appliance_url=self.appliance_url,
            api_version=self.client.api_version or "",
            report_ts=self.report_ts,
        )

        # Always emit summary row first
        rows.append(parse_server_summary_row(server_ctx, server))

        # Try each parser independently; failures are warnings, not fatal.
        parsers: List[Tuple[str, Callable[[], List[Dict[str, Any]]]]] = [
            ("processors", lambda: parse_processors(server_ctx, server)),
            ("memory", lambda: parse_memory(server_ctx, server)),
            ("local-storage", lambda: parse_local_storage(server_ctx, server)),
            ("network-adapters", lambda: parse_network_adapters(server_ctx, server)),
            ("power-supplies", lambda: parse_power_supplies(server_ctx, server)),
            ("fans", lambda: parse_fans(server_ctx, server)),
            ("bios-security", lambda: parse_bios_security(server_ctx, server)),
            ("pci-devices", lambda: parse_pci_devices(server_ctx, server)),
        ]
        for label, fn in parsers:
            try:
                rows.extend(fn() or [])
            except Exception as exc:
                LOG.warning("Parser '%s' failed on %s: %s", label, server_name, exc)
                partial = True

        # Firmware sub-resource (optional endpoint)
        firmware_payload = None
        if server_uri:
            firmware_payload = self._try(
                "firmware",
                lambda: self.client.get(server_uri.rstrip("/") + "/firmware"),
                default=None,
            )
            if firmware_payload is None:
                LOG.debug("No firmware sub-resource available for %s", server_name)
            try:
                rows.extend(parse_firmware_inventory(server_ctx, firmware_payload))
            except Exception as exc:
                LOG.warning("Firmware parser failed on %s: %s", server_name, exc)
                partial = True

        # Optional raw JSON dump for troubleshooting
        if self.dump_json_dir:
            self._maybe_dump_json(
                server_name,
                {
                    "server": server,
                    "serverHardwareType": sh_type,
                    "enclosure": enclosure,
                    "rackManager": rack_manager,
                    "profile": profile,
                    "template": template,
                    "firmware": firmware_payload,
                },
            )

        return rows, partial

    # ---- main entry point ----

    def run(self, csv_path: str) -> int:
        # Collection: server hardware
        LOG.info("Listing server hardware from %s ...", self.appliance_url)
        try:
            servers = self.client.get_collection("/rest/server-hardware")
        except OneViewError:
            raise
        except Exception as exc:
            raise OneViewError(f"Could not list /rest/server-hardware: {exc}") from exc

        self.stats["discovered"] = len(servers)
        LOG.info("Discovered %d server-hardware records.", len(servers))

        if not servers:
            LOG.warning("OneView returned zero servers.  An empty CSV will be written.")

        # Open CSV up-front so we fail fast on I/O errors.
        os.makedirs(os.path.dirname(os.path.abspath(csv_path)) or ".", exist_ok=True)
        try:
            csv_fh = open(csv_path, "w", newline="", encoding="utf-8")
        except OSError as exc:
            raise OneViewError(f"Cannot open CSV for writing at {csv_path}: {exc}") from exc

        writer = csv.DictWriter(
            csv_fh,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()

        try:
            for idx, srv in enumerate(servers, start=1):
                name = dig(srv, "name") or dig(srv, "uri") or f"server-{idx}"
                LOG.info("[%d/%d] %s", idx, len(servers), name)
                try:
                    rows, partial = self.process_server(srv)
                except Exception as exc:
                    LOG.error("Unhandled error processing %s: %s", name, exc)
                    self.stats["failed"] += 1
                    if self.strict:
                        raise
                    continue

                for r in rows:
                    writer.writerow(r)
                    self.stats["rows_written"] += 1

                if partial:
                    self.stats["partial"] += 1
                else:
                    self.stats["succeeded"] += 1
        finally:
            csv_fh.close()

        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "y", "t")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oneview_hw_inventory_report.py",
        description="On-demand HPE OneView hardware inventory CSV reporter (read-only).",
    )
    p.add_argument("--oneview-url", default=_env("ONEVIEW_URL"),
                   help="OneView appliance base URL, e.g. https://oneview.example.com")
    p.add_argument("--username", default=_env("ONEVIEW_USERNAME"),
                   help="OneView username")
    p.add_argument("--password-env", default="ONEVIEW_PASSWORD",
                   help="Environment variable name containing the password (default: ONEVIEW_PASSWORD)")
    p.add_argument("--prompt-password", action="store_true",
                   help="Interactively prompt for password instead of reading env var")
    p.add_argument("--auth-domain", default=_env("ONEVIEW_AUTH_DOMAIN"),
                   help="Authentication domain, e.g. LOCAL or your AD domain")
    p.add_argument("--api-version", default=_env("ONEVIEW_API_VERSION"),
                   help=f"X-API-Version fallback if /rest/version fails (default: {DEFAULT_API_VERSION})")
    p.add_argument("--output-csv", default=_env("OUTPUT_CSV"),
                   help="Explicit CSV output path; overrides --output-dir")
    p.add_argument("--output-dir", default=_env("OUTPUT_DIR", "./reports"),
                   help="Directory for timestamped output file (default: ./reports)")
    p.add_argument("--verify-tls", default=_env("ONEVIEW_VERIFY_TLS", "true"),
                   help="TLS verification: true (default), false, or path to CA bundle "
                        "(equivalent to --ca-bundle)")
    p.add_argument("--ca-bundle", default=_env("ONEVIEW_CA_BUNDLE"),
                   help="Path to a custom CA bundle PEM file for TLS verification")
    p.add_argument("--dump-raw-json-dir", default=_env("DUMP_RAW_JSON_DIR"),
                   help="If set, write raw per-server JSON (credentials scrubbed) to this directory")
    p.add_argument("--strict", action="store_true", default=_bool_env("STRICT_MODE", False),
                   help="Exit non-zero if any per-server failures occur")
    p.add_argument("--log-level", default=_env("LOG_LEVEL", "INFO"),
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def resolve_verify(verify_tls_arg: str, ca_bundle: Optional[str]) -> Any:
    """Resolve TLS verification setting into the value `requests` expects."""
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            raise OneViewError(f"--ca-bundle path does not exist: {ca_bundle}")
        return ca_bundle

    val = (verify_tls_arg or "true").strip()
    lower = val.lower()
    if lower in ("false", "0", "no", "off", "insecure"):
        LOG.warning(
            "*** TLS VERIFICATION IS DISABLED.  This is INSECURE and intended for "
            "lab environments only.  Use --ca-bundle in production. ***"
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return False
    if lower in ("true", "1", "yes", "on"):
        return True
    # treat as file path
    if not os.path.isfile(val):
        raise OneViewError(f"--verify-tls is not 'true'/'false' and is not a file path: {val}")
    return val


def resolve_csv_path(args: argparse.Namespace, appliance_url: str) -> str:
    if args.output_csv:
        return args.output_csv
    host = ""
    try:
        from urllib.parse import urlparse
        host = urlparse(appliance_url).hostname or "oneview"
    except Exception:
        host = "oneview"
    fname = f"oneview_hw_inventory_{slugify(host)}_{timestamp_for_filename()}.csv"
    return os.path.join(args.output_dir or ".", fname)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    configure_logging(args.log_level)

    if not args.oneview_url:
        LOG.error("--oneview-url (or ONEVIEW_URL) is required.")
        return 2
    if not args.username:
        LOG.error("--username (or ONEVIEW_USERNAME) is required.")
        return 2

    # Resolve password without ever putting it on argv.
    if args.prompt_password or not args.password_env:
        password = getpass.getpass("OneView password: ")
    else:
        password = os.environ.get(args.password_env, "")
        if not password:
            LOG.error("Password env var '%s' is empty.  Set it or use --prompt-password.",
                      args.password_env)
            return 2

    try:
        verify = resolve_verify(args.verify_tls, args.ca_bundle)
    except OneViewError as exc:
        LOG.error("%s", exc)
        return 2

    csv_path = resolve_csv_path(args, args.oneview_url)

    client = OneViewClient(
        base_url=args.oneview_url,
        verify=verify,
        api_version_override=args.api_version,
    )

    rc = 0
    try:
        client.discover_api_version()
        client.login(args.username, password, args.auth_domain)

        reporter = InventoryReporter(
            client=client,
            appliance_url=args.oneview_url,
            dump_json_dir=args.dump_raw_json_dir,
            strict=args.strict,
        )
        reporter.run(csv_path)

        # Final summary
        s = reporter.stats
        LOG.info("=" * 60)
        LOG.info("OneView appliance     : %s", args.oneview_url)
        LOG.info("API version used      : %s", client.api_version)
        LOG.info("Servers discovered    : %d", s["discovered"])
        LOG.info("Servers fully OK      : %d", s["succeeded"])
        LOG.info("Servers partial OK    : %d", s["partial"])
        LOG.info("Servers failed        : %d", s["failed"])
        LOG.info("Component rows written: %d", s["rows_written"])
        LOG.info("CSV output            : %s", csv_path)
        if args.dump_raw_json_dir:
            LOG.info("Raw JSON dump dir     : %s", args.dump_raw_json_dir)
        LOG.info("=" * 60)

        if args.strict and (s["failed"] > 0 or s["partial"] > 0):
            LOG.error("--strict set and at least one server failed or was partial; exiting non-zero.")
            rc = 1
    except OneViewAuthError as exc:
        LOG.error("Authentication failure: %s", exc)
        rc = 3
    except OneViewError as exc:
        LOG.error("Fatal OneView error: %s", exc)
        rc = 4
    except KeyboardInterrupt:
        LOG.warning("Interrupted by user.")
        rc = 130
    finally:
        try:
            client.logout()
        except Exception:
            pass
        # Wipe local copy of secret from memory.
        password = "x" * len(password) if password else ""
        del password

    return rc


if __name__ == "__main__":
    sys.exit(main())
