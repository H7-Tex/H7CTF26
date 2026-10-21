# H7CTF'26 Finals - OCI provisioning plan (M2)

**Model C, ap-hyderabad-1, 45 h (rehearsal Fri 23 + event Sat 24 - Sun 25 Oct)**  
Prepared by: Finals-P4-Infra · 22 Oct 2026  
Route to: Finals-3 → Finals-2 → Abu for spend approval

---

## 1. Instance inventory

Pricing: E4 $0.025/OCPU-hr + $0.0015/GB-hr; A1 $0.01/OCPU-hr + $0.0015/GB-hr  
Source: Oracle price-list API 2026-10-08 [DOC in recipe 06]

### 1a. Fixed infra VMs

| VM | Shape | OCPU | GB | $/hr | Boot GB | Notes |
|---|---|---|---|---|---|---|
| r1 | E4 | 4 | 16 | 0.124 | 50 | primary router, pcap, WireGuard |
| r2 | E4 | 2 | 16 | 0.074 | 50 | standby router |
| anvil | E4 | 4 | 16 | 0.124 | 150 | finals.h7tex.com, Postgres |
| checker | E4 | 4 | 16 | 0.124 | 150 | tick engine + deploy gate API :8000 |
| hill-gw | E4 | 2 | 16 | 0.074 | 150 | GridWatch KotH hill |
| hill-ht | E4 | 2 | 16 | 0.074 | 150 | Hostile Takeover KotH hill |
| ops | A1 | 2 | 8 | 0.032 | 100 | reset API :8090, automation |
| gitea | A1 | 2 | 8 | 0.032 | 100 | Gitea HTTP :3000 + SSH :2222 |
| mirror | A1 | 4 | 16 | 0.064 | 100 | apt/pip/npm/docker offline mirror + DNS sink |

Infra subtotal: **$0.722/hr** · E4 OCPUs used: 18 · A1 OCPUs used: 8

> Note vs recipe section 9: checker sized at 4/16 not 8/32 (saves $0.12/hr, risk: slow ticks
> under load; can be upgraded before rehearsal if bench shows > 80% CPU). Anvil at 4/16 not
> 4/32 (saves $0.06/hr; 16 GB is sufficient for 15 teams on Postgres). Ops/Gitea/mirror on A1
> to stay well under the 100 E4 OCPU hard limit.

### 1b. Team VMs (option A - recommended: 12 GB vulnbox)

| VM group | Shape | OCPU | GB | Count | $/hr/box | $/hr total |
|---|---|---|---|---|---|---|
| prod vulnbox (teams 1-15 + NOP) | E4 | 2 | 12 | 16 | 0.068 | 1.088 |
| workbench (teams 1-15, x86 required) | E4 | 2 | 16 | 15 | 0.074 | 1.110 |

Team subtotal (A): **$2.198/hr** · E4 OCPUs: 32 (prod) + 30 (wb) = 62

### 1c. Team VMs (option B - alternative: 8 GB vulnbox)

| VM group | Shape | OCPU | GB | Count | $/hr/box | $/hr total |
|---|---|---|---|---|---|---|
| prod vulnbox (teams 1-15 + NOP) | E4 | 2 | 8 | 16 | 0.062 | 0.992 |
| workbench (teams 1-15, x86 required) | E4 | 2 | 16 | 15 | 0.074 | 1.110 |

Team subtotal (B): **$2.102/hr** · E4 OCPUs: 62 (same as A, RAM-only diff)

---

## 2. Quota consumption

| Resource | Option A / B | Limit (verified M1) | Headroom |
|---|---|---|---|
| E4 OCPUs | 80 | 100 | 20 |
| A1 OCPUs | 8 | free tier unlimited | ample |
| Custom images | 3 (base + prod + wb) | 25 | 22 |
| VCN | 1 | 5 | 4 |
| Reserved public IPs | 1 | 5 | 4 |
| Block volumes | ~50 | 150 | 100 |

All E4: 18 infra + 62 team = 80, confirmed within 100-OCPU limit.  
Hills add 4 E4 OCPUs vs base model C; still safe.

---

## 3. Cost table (45 h compute + 5 days storage)

Block volume rates: $0.0255/GB-month  
Boot volumes by shape: r1/r2 50 GB, ops/gitea/mirror 100 GB, all others 150 GB  
Data volumes: pcap 500 GB (on r1), Gitea repos 100 GB, mirror cache 300 GB

| Line item | Option A (12 GB) | Option B (8 GB) |
|---|---|---|
| Infra compute (9 VMs × 45 h) | $32.49 | $32.49 |
| Team compute - prod (16 × 45 h) | **$48.96** | $44.64 |
| Team compute - wb (15 × 45 h) | $49.95 | $49.95 |
| Boot volumes (5700 GB, 5 days) | $10.16 | $10.16 |
| Data volumes (900 GB, 5 days) | $1.60 | $1.60 |
| NAT egress (mirror warm-up ~120 GB) | $1.02 | $1.02 |
| **Total** | **$144** | **$140** |

Hourly all-in: option A $2.920/hr, option B $2.824/hr.  
Each extra hour at full scale: ~$2.90 (A) / $2.82 (B).

> The recipe (section 9) quotes $201 for model C. Delta is explained by: A1 for ops/gitea/mirror
> (-$18), checker 4/16 not 8/32 (-$5.6), anvil 4/16 not 4/32 (-$2.7), and our workbenches at
> 2 OCPU not the recipe's 2/16 cross-check error (this plan uses 2/16 workbenches, same as
> recipe). Net: our config is lighter on the ops layer.

---

## 4. Recommendation

**Go with option A (12 GB vulnbox).**

Reason: under concurrent load (one BuildKit build + staging promotion + checker inbound + one
active exploit flood + OS overhead), the prod box memory budget is tight:

| Consumer | Approx RSS |
|---|---|
| services (mem_limit sum across 3-5 containers) | 4.0 GB |
| staging copy | 0.75 GB |
| BuildKit daemon + one build layer cache | 2.5 GB |
| OS + dockerd | 0.6 GB |
| **8 GB budget** | 7.85 GB with zero headroom |
| **12 GB budget** | 7.85 GB, **4.15 GB free** - survives flood bursts without OOM kills |

Cost delta between options: **$4/45h**. This is not a trade-off worth making. Use 12 GB.

Option B is viable only if we confirm the exact service set and its mem_limit sum comes in under
5.5 GB total. Final call belongs to Abu.

---

## 5. Teardown schedule

- **Sun 25 Oct ~18:00 IST**: event ends. Snapshot `h7f-prod` and `h7f-wb` to custom images.
- **Sun 25 Oct ~20:00 IST**: terminate all team VMs and infra VMs except ops.
- **Export pcaps**: copy `/srv/pcap` on r1 to OCI Object Storage before terminating r1.
- **Keep**: custom images (3), pcap export, Gitea repos backup.
- **Mon 26 Oct**: terminate ops, delete all block volumes. Bill stops.

Estimated total post-event cost (images + storage through teardown): < $5.

---

## 6. Go/no-go gate

This plan requires **Abu's explicit spend approval** before any instance is launched.

Checklist for Abu / Finals-2:
- [ ] 12 GB vulnbox approved (or override to 8 GB)  
- [ ] $144 spend cap confirmed (or if running over $200 recipe estimate, confirm that too)
- [ ] Checker at 4/16 OCPUs accepted (or upgrade to 8/16 before rehearsal: +$5.6 for 45 h)
- [ ] Anvil at 4/16 OCPUs accepted (or upgrade to 4/32: +$2.7)

Signal via Finals-3 with "go M3" to unblock provisioning.
