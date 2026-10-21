# H7CTF'26 Finals - OCI provisioning plan (M2, rev 2)

**Model C, ap-hyderabad-1, Finals-2 architecture approved (22 Oct 2026)**  
Prepared by: Finals-P4-Infra. Reviewed: Finals-2. Awaiting Abu's spend go.

---

## 1. Instance inventory

Prices: E4 $0.025/OCPU-hr + $0.0015/GB-hr; A1 $0.01/OCPU-hr + $0.0015/GB-hr  
Storage: $0.0255/GB-month storage + $0.017/GB-month VPU (Balanced, 10 VPU) = **$0.0425/GB-month**

### 1a. Fixed infra VMs (run Thu midday -> Sun 20:00, ~78 h)

| VM | Shape | OCPU | GB | $/hr | Boot GB | Notes |
|---|---|---|---|---|---|---|
| r1 | E4 | 4 | 16 | 0.124 | 50 | primary router, pcap, WireGuard |
| r2 | E4 | 2 | 16 | 0.074 | 50 | standby router |
| anvil | E4 | 4 | 16 | 0.124 | 150 | finals.h7tex.com, Postgres |
| checker | E4 | **8** | **32** | **0.248** | 150 | tick + Outbreak wave + gate pool |
| hill-gw | E4 | 2 | 16 | 0.074 | 150 | GridWatch II |
| hill-ht | E4 | 2 | 16 | 0.074 | 150 | Hostile Takeover II |
| hill-hc | E4 | 2 | 16 | 0.074 | 150 | Harbor Master |
| ops | A1 | 2 | 8 | 0.032 | 100 | reset API :8090, automation |
| gitea | A1 | 2 | 8 | 0.032 | 100 | Gitea HTTP :3000 + SSH :2222 |
| mirror | A1 | 4 | 16 | 0.064 | 100 | apt/pip/npm/docker offline mirror |

Infra total: **$0.920/hr** · E4 OCPUs: 24 · A1 OCPUs: 8

### 1b. Team VMs (run Fri 08:00 -> Sun 14:00, ~54 h)

| VM group | Shape | OCPU | GB | Count | $/hr/box | $/hr total | Boot GB |
|---|---|---|---|---|---|---|---|
| prod vulnbox (15 teams + NOP) | E4 | 2 | 12 | 16 | 0.068 | 1.088 | 150 |
| workbench (teams 1-15, x86) | E4 | 2 | 16 | 15 | 0.074 | 1.110 | 100 |

Team total: **$2.198/hr** · E4 OCPUs: 62

---

## 2. Quota

| Resource | Used | Limit (verified M1) | Headroom |
|---|---|---|---|
| E4 OCPUs | 24 infra + 62 team = **86** | 100 | **14** |
| A1 OCPUs | 8 | free unlimited | ample |
| Custom images | 3 | 25 | 22 |

Note: checker upgrade 4->8 OCPU costs 4 E4 OCPUs, hill-hc costs 2 more = +6 vs v1. Still within limit.

---

## 3. Cost breakdown

### Compute

| Line | Rate | Hours | Cost |
|---|---|---|---|
| Infra compute (10 VMs) | $0.920/hr | 78 | **$71.76** |
| Team compute - prod 16x (12 GB) | $1.088/hr | 54 | **$58.75** |
| Team compute - wb 15x (16 GB) | $1.110/hr | 54 | **$59.94** |
| **Compute subtotal** | | | **$190.45** |

### Storage (provisioned from ~Thu midday; 5 days billed)

| Volume group | GB | $/GB-month | 5d cost |
|---|---|---|---|
| Router boots (2 x 50 GB) | 100 | 0.0425 | $0.71 |
| Infra VM boots (8 x 100-150 GB) | 950 | 0.0425 | $6.74 |
| Hill boots (3 x 150 GB) | 450 | 0.0425 | $3.19 |
| Prod boots (16 x 150 GB) | 2400 | 0.0425 | $17.00 |
| WB boots (15 x 100 GB) | 1500 | 0.0425 | $10.63 |
| pcap volume (500 GB) | 500 | 0.0425 | $3.54 |
| Gitea data (100 GB) + mirror cache (300 GB) | 400 | 0.0425 | $2.83 |
| **Storage subtotal** | **6300 GB** | | **$44.64** |

### Other

| Line | Cost |
|---|---|
| NAT egress (mirror warm-up ~120 GB @ $0.0085/GB) | $1.02 |
| Budget alerts setup | $0 |

### Grand total

| | Cost |
|---|---|
| Compute | $190.45 |
| Storage | $44.64 |
| Egress | $1.02 |
| **Realistic total** | **~$236** |
| **Hard cap** | **$250** |

Hourly burn at full scale: $3.12/hr (infra+team combined).

---

## 4. Runbook additions (Finals-3 approved)

**Team VM schedule:**
- Do NOT stop any VM during the event. Power-offs require a new boot volume; that's a reset, not a stop.
- Stop team VMs immediately after final scores are exported (~Sun 13:00), before teardown.

**OCI budget alerts:** Set right after the compartment go:
```
oci budgets budget create -c $TENANCY \
  --target-type COMPARTMENT --target-id $C \
  --amount 250 --reset-period MONTHLY --display-name h7f-finals
# Create alerts at $150, $200, $240 (email abu@h7tex.com)
```

**Volume teardown order (Sun ~20:00):**
1. Export pcaps from r1:/srv/pcap to Object Storage.
2. Terminate all team VMs, then infra VMs.
3. Terminate ops last (it runs the teardown script).
4. Delete all block volumes after instances are TERMINATED (detach is automatic on terminate).
5. Keep 3 custom images (h7f-base, h7f-prod, h7f-wb) until post-mortem is done.

---

## 5. Go/no-go checklist for Abu

- [ ] 12 GB vulnbox, ~$236 realistic total (hard cap $250) approved
- [ ] Checker at 8 OCPU / 32 GB approved
- [ ] Service list (8 services: notebook/harbor_id/tidepay/bollard/berth_board/dockyard/tariff_studio/pilot_line) locked
- [ ] Budget alert targets ($150/$200/$240) confirmed
- [ ] Spend go signal: "go M3" via Finals-3 -> P4-Infra

No write calls or instances launched until "go M3" received.
