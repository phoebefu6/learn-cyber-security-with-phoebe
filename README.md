# Learn Cyber Security with Phoebe

Fourteen sessions on defending a data estate, taught from the attacker's path inward. Every session names the route an attacker would walk and then the control that closes it or the log that sees it. Defensive throughout: no offensive tooling, no exploitation steps.

**Live:** https://phoebefu6.github.io/learn-cyber-security-with-phoebe/

Two tracks. **Leader, 6 sessions, no SQL:** the attacker's view of a warehouse, NIST CSF 2.0's six functions applied to a data estate, the ATT&CK kill chain through a data stack, backups as attack surface, detecting what you cannot prevent, and the first hour. **Builder, 8 sessions:** one estate inventoried and defended control by control.

- `assets/sec-live.js` holds the **attack-path bench**. Ironwood's estate is a graph of accounts, keys, buckets, a warehouse, the crown-jewel table, backups and an external endpoint. Every control removes or logs specific edges; the engine enumerates every simple path from the internet and from an insider to the table and reports **paths, undetected paths, and tables recoverable after an attacker reaches the admin login**. Nothing is modelled: every number is a path count.
- **The measured ladder:** nine paths with nothing on. MFA 6, key rotation 5, private bucket 4, pinned dependencies 3. **Query logging and egress alerting leave paths at 3 and take undetected from 3 to 0.** **Immutable backups leave paths at 3 and take recoverable tables from 0 to 12.** Least privilege takes paths to **1**: the insider's own legitimate read, which no control can remove without stopping the work, and which is logged.
- **Two over-corrections, both computed:** a perimeter firewall alone closes one door and leaves **7 paths, all unseen, backups still lost**. All prevention with no detection leaves 1 path, unseen.
- **Sources read at the primary:** NIST CSF 2.0 (26 February 2024) for the six functions; MITRE ATT&CK v19.2 for the fifteen Enterprise tactics, including the v19 split of Defense Evasion into Stealth and Defense Impairment.
- **Seams enforced:** model and prompt attacks belong to the AI red-team course; breach-notification law to the governance courses; grants, policies and secrets hygiene to the access-control course. Each page names the boundary.
- Running artifact: a **defended graph** of Ironwood, a fictional mid-size retailer.
- Full source map, verification tiers and frozen canon: `materials/official-course-map.md`

by Phoebe Fu
