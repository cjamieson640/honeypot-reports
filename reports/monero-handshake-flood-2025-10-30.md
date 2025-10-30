---
title: "Monero Handshake Flood — Port 18080 / 18081"
date: 2025-10-30
incident_start: 2025-10-21
incident_end: 2025-10-30
source_ip: "162.218.65.219"
asn: 54098
severity: low
tags: ["monero","crypto","scanner","honeytrap"]
---

# Persistent Monero Handshake Flood — Port 18080 / 18081

**Incident Date Range:** October 21 – October 30 2025  
**Honeypot:** Honeytrap (T-Pot CE on AWS EC2)  
**Analyst:** Cole Jamieson  
**Classification:** Automated Cryptocurrency Network Scan / Reconnaissance  
**Severity:** Low

---

## Overview
Since October 21 2025, the honeypot has recorded a sustained flood of TCP connections targeting the default Monero daemon ports 18080 (P2P) and 18081 (JSON-RPC). All traffic originates from **162.218.65.219 (LIONLINK-NETWORKS, United States)** and exhibits identical payload characteristics over the multi-day period.

### Port 18080 – Monero P2P
* **172,500 events** logged as of Oct 30 2025  
* Repeated ~260-byte binary payload containing strings such as `node_data`, `peer_id`, `current_height`, `top_id`, `payload_data`  
* Payload MD5: `97ef55fa1fd19a0e82113fe1286afa23` (unchanged across all events)  
* No file downloads (`download_count = 0`)  
* Behavior consistent with Monero P2P handshake attempts or miner peer probes

### Port 18081 – Monero RPC
* Same source IP initiating repeated connections  
* All payloads length = 0 (md5 `d41d8cd98f00b204e9800998ecf8427e`)  
* Indicates TCP connect scans with no HTTP/JSON-RPC data

---

## Timeline (high-level)
* **2025-10-21** — First observed Monero handshake traffic from `162.218.65.219` to port 18080.  
* **2025-10-21 → 2025-10-30** — Continuous, repeated events, daily.  
* **2025-10-30** — Total observed hits reached **172,500** for 18080 from the source IP.

---

## Technical Details & Evidence
* Example Elastic KQL filters used:
  * All 18080 Honeytrap events:
    ```
    type:"Honeytrap" AND dest_port:18080
    ```
  * Attacker only:
    ```
    type:"Honeytrap" AND dest_port:18080 AND src_ip:"162.218.65.219"
    ```
  * Exact payload fingerprint:
    ```
    type:"Honeytrap" AND dest_port:18080 AND attack_connection.payload.md5_hash:"97ef55fa1fd19a0e82113fe1286afa23"
    ```
  * Empty payloads on 18081:
    ```
    type:"Honeytrap" AND dest_port:18081 AND attack_connection.payload.length:0 AND src_ip:"162.218.65.219"
    ```

* Payload characteristics (18080)
  * `attack_connection.payload.length`: 260
  * `attack_connection.payload.md5_hash`: `97ef55fa1fd19a0e82113fe1286afa23`
  * Printable strings in payload include: `node_data`, `my_port`, `peer_id`, `cumulative_difficulty`, `current_height`, `top_id`, `top_version`

* No downloads or exploitation observed (`download_count = 0`).

---

## Mitigation & Next Steps
1. Rate-limit or block `162.218.65.219` at your firewall to reduce noise.  
2. Tag events in Elastic with `monero_scan_flood` for easier filtering.  
3. Create an alert for RPC activity:
   * Trigger when `dest_port:18081` and `attack_connection.payload.length > 0` to detect future JSON-RPC probes.  
4. Correlate ASN 54098 across other honeypots to determine campaign scope.  
5. Store PCAPs and raw exports in `artifacts/pcaps/` (use Git LFS or off-repo storage for large files) and include checksums in the repo.

---

## Indicators of Activity (IoCs)
* **IPv4:** `162.218.65.219`  
* **ASN:** `54098` (LIONLINK-NETWORKS)  
* **MD5 (P2P payload):** `97ef55fa1fd19a0e82113fe1286afa23`  
* **MD5 (empty 18081):** `d41d8cd98f00b204e9800998ecf8427e`  
* **Ports:** `18080`, `18081`

---

## Artifacts
* `artifacts/pcaps/monero_162.218.65.219_18080_2025-10-30.pcap`  (PCAP — stored externally or via Git LFS)  
* `artifacts/raw-exports/monero_18080_hits_2025-10-21_to_2025-10-30.json` (Kibana/Elastic export)

---

## Notes
* Do **not** publish raw PCAPs that contain sensitive data to a public repo without sanitization. Instead, provide redacted samples or SHA256 checksums and an offline storage location.

---

*Last Updated:* 2025-10-30
