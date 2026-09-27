# Architecture

OpsControl separates collection, normalization, persistence and presentation.

```mermaid
flowchart LR
    U[Web browser] --> A[FastAPI application]
    A --> S[(SQLite state)]
    A --> I[Inventory configuration]
    A --> C[Collectors]
    C --> SSH[OpenSSH audits]
    C --> P[Proxmox API]
    C --> Z[Zabbix API]
    C --> W[Wazuh API]
    C --> E[Elasticsearch API]
    C --> B[Bacula API]
```

The FastAPI application owns the local state and exposes JSON endpoints to a
framework-free JavaScript interface. Collectors use bounded timeouts and preserve
the distinction between an unknown state, stale evidence and a measured failure.
Remote SSH operations are designed for observation. Host-key verification remains
enabled.

The standalone demo in this directory has no backend and makes no external
requests. It exists for portfolio review and GitHub Pages.
