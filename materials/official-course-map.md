# Official course map - learn-cyber-security-with-phoebe

Built 2026-09-08. Hub bucket `dsec` (Data Ops & Security), difficulty tier 3. Reuses the hub's
existing `planned` slug. Two tracks: leader 6 x 45 min, builder 8 x 45 min. **Defensive
throughout**: every session names the attacker's path and then the control that closes or sees
it. No offensive tooling, no exploitation walkthroughs.

Running artifact: a **defended graph** of one data estate at **Ironwood**, a fictional mid-size
retailer, with a crown-jewel `customers` table and a backup worth destroying.

---

## The seam against sibling courses (enforced, not aspirational)

| Sibling | What it owns | What this course does instead |
|---|---|---|
| `learn-ai-red-team-with-phoebe` (ai, d3) | "The threat model" and "The attack surface" for MODELS: prompt injection, jailbreaks, agent misuse | The estate underneath the model. Nothing about prompts, models or agents anywhere |
| `learn-data-governance-with-phoebe` (gov, d2) | "Protection & breach response" as LAW and programme: notification duties, DPO, rights | Technical containment and recovery only. Notification duties are pointed at the governance course by name in a6 |
| `learn-data-access-control-with-phoebe` (dsec, d2) | Grants, role hierarchy, row and column policies, masking, secrets hygiene, access review | Assumed, not re-taught. Appear only as edges an attacker uses when they are missing (the "Friday admin grant", the key in a repo). b2 is the attacker's use of a leaked key; the access course's b6 is the hygiene that prevents the leak |
| `learn-data-observability-with-phoebe` (dsec, d1) | Detecting data defects | b5 and b7 detect attacker behaviour from query and egress logs; no data-quality monitoring |
| `learn-dataops-with-phoebe` (dsec, d4) | "Observability, secrets and IaC" in one builder session | IaC appears only as an inventory lane (b1) and a supply-chain surface (b4) |

---

## Verified facts (with their source tier)

**Tier 1, read from the primary source.**

- **NIST Cybersecurity Framework 2.0**, published **26 February 2024** (NIST CSWP 29). Six Core
  Functions: **GOVERN (GV)** - the organization's cybersecurity risk management strategy,
  expectations and policy are established, communicated and monitored; **IDENTIFY (ID)** - the
  organization's current cybersecurity risks are understood; **PROTECT (PR)** - safeguards to
  manage the organization's cybersecurity risks are used; **DETECT (DE)** - possible cybersecurity
  attacks and compromises are found and analyzed; **RESPOND (RS)** - actions regarding a detected
  cybersecurity incident are taken; **RECOVER (RC)** - assets and operations affected by a
  cybersecurity incident are restored. Extracted from the PDF text.
  <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>
- **MITRE ATT&CK Enterprise tactics, version 19.2** (site v5.0.0), **fifteen** tactics in order:
  TA0043 Reconnaissance, TA0042 Resource Development, TA0001 Initial Access, TA0002 Execution,
  TA0003 Persistence, TA0004 Privilege Escalation, **TA0005 Stealth**, **TA0112 Defense
  Impairment**, TA0006 Credential Access, TA0007 Discovery, TA0008 Lateral Movement, TA0009
  Collection, TA0011 Command and Control, TA0010 Exfiltration, TA0040 Impact.
  **Re-verify caveat:** older material says fourteen tactics with "Defense Evasion" as TA0005;
  v19 split it into Stealth and Defense Impairment. Pages must use the v19.2 names.
  <https://attack.mitre.org/tactics/enterprise/>

**Tier 2, widely documented practice, no single primary source.**

- Immutable / object-locked backups as the ransomware control; the principle that warehouse
  time travel and snapshots are deleted with the account that owns them and therefore are not a
  backup against account compromise. Taught as professional norm with the reason.
- Secret scanning of git history, dependency pinning and lockfile verification, egress
  allowlisting. Taught as patterns; no vendor product claims.

**Nothing on the b8 bench is modelled.** The estate is a written inventory; every number is a
path count over the graph that remains after the controls you switch on.

---

## Frozen canon - the b8 attack-path bench

Computed in node from `assets/sec-live.js` before any page quoted a number. Any page citing these
must match exactly. Twelve tables in the warehouse.

| Controls on | Paths to crown jewels | Undetected | Recoverable tables of 12 |
|---|---|---|---|
| Nothing | **9** | 9 | 0 |
| + MFA on every human login | 6 | 6 | 0 |
| + rotate service keys | 5 | 5 | 0 |
| + private export bucket | 4 | 4 | 0 |
| + pinned, verified dependencies | 3 | 3 | 0 |
| + query logging and egress alerting | 3 | **0** | 0 |
| + immutable, restore-tested backups | 3 | 0 | **12** |
| + least privilege on the analyst role | **1** | 0 | 12 |
| **Perimeter firewall only** (over-correction) | 7 | 7 | 0 |
| **All prevention, no detection** | 1 | **1** | 12 |

- The **one remaining path** at the finished design is the insider's own legitimate support
  session reading `customers`. No control removes it without stopping the work; it is logged.
- Logging moves undetected 3 -> 0 **with paths unchanged**. Immutable backups move recoverable
  0 -> 12 **with paths unchanged**. Both rungs exist to show that a control can matter without
  changing the headline path count.
- The perimeter allowlist closes exactly one door (a leaked key used from outside) and leaves
  phishing, the CI runner, the public bucket and both insider paths.

### The nine baseline paths

1. internet > public repo > ETL service key > warehouse > customers
2. internet > phished analyst login > warehouse > customers
3. internet > phished analyst login > admin role (Friday grant) > warehouse > customers
4. internet > phished admin login > warehouse > customers
5. internet > CI runner (malicious package) > ETL service key > warehouse > customers
6. internet > public export bucket > customers extract (**never touches the warehouse**)
7. insider > own analyst login > warehouse > customers
8. insider > own analyst login > admin role (Friday grant) > warehouse > customers
9. insider > own legitimate support session > customers (**cannot be closed, only logged**)

Plus: phished admin login > backups (drop and purge, time travel included) until immutable backups.

---

## Coverage per session

`✓` = taught to working depth. `◐` = named and handed to the session or course that owns it.

### Leader track

| Session | Covers | Depth |
|---|---|---|
| a1 The attacker's view of a warehouse | What is worth stealing, the three doors, the nine-path baseline | ✓ |
| a2 Six functions, one estate | NIST CSF 2.0 Govern/Identify/Protect/Detect/Respond/Recover applied to a data estate, with the date | ✓ |
| a3 The kill chain through a data stack | ATT&CK v19.2 fifteen tactics mapped to warehouse events; the v19 rename | ✓ |
| a4 Backups are attack surface too | Ransomware on data, time travel is not a backup, immutability, restore drills, the canon 0 -> 12 | ✓ |
| a5 Detect what you cannot prevent | What the audit log sees and misses, the export-bucket blind spot, undetected 3 -> 0 | ✓ |
| a6 The first hour, and the report | Containment decisions, who to tell, what to fund; notification duties handed to governance | ✓ |
| Breach notification law | Named, pointed at `learn-data-governance` | ◐ |

### Builder track

| Session | Covers | Depth |
|---|---|---|
| b1 Attack-surface inventory | Five lanes, nodes and edges, three doors, the Ironwood graph | ✓ |
| b2 Credential paths | Keys in git history, token theft, MFA gaps, the Friday admin grant; MFA 9 -> 6, rotation 6 -> 5 | ✓ |
| b3 Misconfiguration | Public buckets, open shares, permissive network policy; private bucket 5 -> 4 | ✓ |
| b4 Supply chain | Packages, dbt packages, connectors, CI runners; pinning 4 -> 3 | ✓ |
| b5 Exfiltration detection | Query history and egress logs, COPY INTO external stages, egress alerting | ✓ |
| b6 Destructive events | Immutable backups, restore drills, recoverable 0 -> 12 | ✓ |
| b7 Detection engineering | Turning ATT&CK techniques into log queries, undetected 3 -> 0 | ✓ |
| b8 The attack-path bench | The full ladder, both over-corrections, the one honest remaining path | ✓ |
| Grants, roles, policies, secrets hygiene | Assumed; pointed at `learn-data-access-control` | ◐ |

## Not covered, by design

- **Attacking models, prompts or agents.** The AI red-team course.
- **Breach notification law and regulator duties.** The governance courses.
- **Offensive tooling or exploitation steps.** Every page stops at "here is the door, here is the
  control that closes it, here is the log that sees it".
- **Network engineering** beyond allowlists and egress rules as inventory lanes.
- **Severity weighting of paths.** Every path counts the same on the bench; a real estate would
  weight by what the path reaches. Named on b8 as the first extension.

## Re-verify before delivery

ATT&CK versions twice a year and v19 renamed a tactic; check the tactic list on a3 against the
live site before teaching. CSF 2.0 is stable.
