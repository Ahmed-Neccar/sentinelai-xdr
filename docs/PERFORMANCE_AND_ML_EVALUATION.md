# SentinelAI XDR — Load Test and ML Evaluation (2026-11-10)

Both measurements were taken on one developer laptop and are baselines for this build, not capacity guarantees. Reproduce them with `scripts/loadtest/run_load_test.ps1` and `scripts/ml/evaluate_ml.py`.

## 1. Load test

### Setup

- Host: Intel Core i5-11400H (6 cores, 12 threads), 23.8 GB RAM, Windows 11, Docker Desktop with 12 CPUs and 11.6 GiB assigned.
- A separate Compose project (`sentinelai-loadtest`) with its own PostgreSQL, Redis, API, and worker on ports 18001/15432. It was created empty and deleted afterwards. The normal deployment kept running on the same machine during the test, so the two shared CPU and disk; the live database received no synthetic data.
- Default container settings: one Uvicorn process, Celery worker concurrency 2, untuned `postgres:16-alpine`.
- Workload: synthetic events from about 200 sources, 90 % network connections, 8 % successful and 2 % failed sign-ins, all timestamped inside the last 90 minutes so that every ingestion job exercises the detection look-back. Load generator: 1–32 client threads on the same host.
- One run. Run-to-run variation was not measured.

### Ingestion (upload to job completion, 20,000 events per file)

| Events already stored | Time for the file | Events per second |
|---:|---:|---:|
| 0 | 41.7 s | 480 |
| 20,000 | 37.9 s | 528 |
| 60,000 | 39.9 s | 501 |
| 100,000 | 44.0 s | 454 |
| 140,000 | 46.1 s | 434 |

All eight files completed (160,000 events, none failed or timed out). A ninth file ingested while eight clients were reading took 52.8 s. Throughput is about 430–530 events per second per job and declines slowly as the recent-event window fills.

### Read latency with 160,000 events stored

| Endpoint | Clients | Requests/s | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| `/events` (page of 50) | 1 | 41 | 24 ms | 28 ms | 33 ms |
| | 8 | 75 | 103 ms | 151 ms | 182 ms |
| | 32 | 75 | 429 ms | 615 ms | 712 ms |
| `/events` filtered by type | 32 | 76 | 420 ms | 615 ms | 697 ms |
| `/events?q=` text search | 1 | 1.8 | 579 ms | 623 ms | 656 ms |
| | 8 | 8.6 | 944 ms | 1155 ms | 1279 ms |
| | 32 | 11 | 3409 ms | 3901 ms | 4375 ms |
| `/detections` | 32 | 114 | 275 ms | 403 ms | 493 ms |
| `/cases` | 32 | 116 | 270 ms | 394 ms | 480 ms |
| `/hosts` | 1 | 6.3 | 157 ms | 181 ms | 199 ms |
| | 8 | 17 | 407 ms | 832 ms | 931 ms |
| | 32 | 19 | 1880 ms | 2405 ms | 2721 ms |

No request failed in any scenario. With ingestion running at the same time, `/events` at 8 clients stayed at 70 requests/s (p95 162 ms).

### Peak container usage

| Container | Peak CPU | Peak memory |
|---|---:|---:|
| API | 147 % | 111 MiB |
| Worker | 100 % | 1,875 MiB |
| PostgreSQL | 1,147 % | 454 MiB |
| Redis | 3 % | 6 MiB |

### What the numbers show

1. **Worker memory is the first limit.** Each ingestion job runs detection over every event from the last two hours (`run_detection_for_job` loads them all as ORM objects). With 160,000 recent events the worker reached 1.9 GB. Memory and job time grow with the event rate, not with the file size; a sustained rate several times higher would exhaust a small host. Bounding this (incremental or per-entity windows, column-only queries) is the most valuable performance change.
2. **The API saturates at about 75–115 requests per second.** Throughput does not rise from 8 to 32 clients; latency does. That is one Uvicorn process, not the database. More workers would raise the ceiling.
3. **Text search and the host inventory do not scale.** `q=` is a substring match over all events (0.6 s for one user at 160,000 events, 3–4 s under 32 clients) and `/hosts` aggregates the whole event table on every request. Both will get slower in proportion to stored events.
4. Listing and filtering events, detections, and cases stayed fast at this size.

### What was not tested

Live sensor batches, cloud polling, concurrent uploads, multiple organizations, data volumes beyond 160,000 events (the default 90-day retention can hold far more), a multi-day soak, failure injection, and a network between client and server. The synthetic traffic produced no detections, so correlation and notification cost under an alert burst is unmeasured.

## 2. Isolation Forest evaluation

### State of the feature

**No ML model is running in the current deployment.** `scikit-learn` and `joblib` are in the optional `backend/requirements-ml.txt`, which the container image does not install, and `.data/ml/` contains no model. `score_events` therefore returns nothing, and all 112 detections in the lab database come from rules. `train.py` refers to a `scripts/train_ml.py` that does not exist. This evaluation describes how the model would behave if it were trained and enabled as written.

### Method

- The project's own feature extractor (six per-entity counts) and the training settings from `train.py`: 100 trees, contamination 0.15, decision threshold 0.0.
- A seeded synthetic population of 1,000 entities per run: five benign profiles (workstation 60 %, server 15 %, user with several failed sign-ins 13 %, NAT gateway 8 %, monitoring scanner 4 %) and four attack profiles (brute force, port scan, slow brute force, lateral sweep) at a chosen prevalence. Random 70/30 entity split, fit on the unlabelled training part, scored on the rest. 20 seeds per setting; mean and standard deviation reported.
- Reference point: two plain thresholds (10 or more failed sign-ins, or 20 or more distinct destination ports). This is a stand-in, not the project's rule engine.

### Results on the synthetic population (project settings)

| Share of entities that are attackers | Model false-positive rate | Model recall | Model precision | Threshold FPR | Threshold recall | Threshold precision |
|---:|---:|---:|---:|---:|---:|---:|
| 0 % | 15.1 % (±2.6) | — | — | 4.1 % | — | — |
| 1 % | 16.2 % (±2.5) | 95 % (±13) | 4.9 % | 4.1 % | 67 % | 12.8 % |
| 5 % | 12.8 % (±2.3) | 74 % (±10) | 22 % | 4.1 % | 61 % | 43 % |
| 15 % | 8.4 % (±1.5) | 56 % (±9) | 54 % | 4.1 % | 64 % | 74 % |

Share of each profile flagged by the model:

| Profile | 1 % attackers | 5 % attackers |
|---|---:|---:|
| Workstation (benign) | 0 % | 0 % |
| Server (benign) | 9 % | 9 % |
| User with failed sign-ins (benign) | 18 % | 1 % |
| NAT gateway (benign) | 100 % | 100 % |
| Monitoring scanner (benign) | 88 % | 65 % |
| Brute force | 65 % | 100 % |
| Port scan | 50 % | 100 % |
| Lateral sweep | 55 % | 84 % |
| Slow brute force | 28 % | 7 % |

At 1 % prevalence each test split contains about three attackers, so the per-attack figures in that column are noisy.

Lowering contamination trades false positives for missed attacks: at 0.05 the false-positive rate is 4–6 % with recall 17–41 %; at 0.01 it is 0.5–1.7 % with recall 5–20 %.

### Real telemetry from the lab database (unlabelled)

Feature counts for the 347 entities in the lab database were exported without addresses or host names. No ground truth exists for them, so these are flag rates, not error rates.

| Model | Entities flagged |
|---|---:|
| Trained on the same real data, contamination 0.15 | 15.0 % (52 of 347) |
| Trained on synthetic benign data, contamination 0.15 | 4.0 % (14 of 347) |
| Plain thresholds | 1.7 % (6 of 347) |

### What the numbers show

1. **The contamination setting decides the alert volume.** At 0.15 the model flags about 15 % of whatever it is trained on: 15 % of an all-benign synthetic population and 15 % of the real lab entities. That is a property of the setting, not evidence that 15 % of entities are suspicious.
2. **False positives concentrate on legitimate but unusual hosts.** Every NAT gateway and most monitoring scanners are flagged in every run. These are exactly the hosts an analyst would have to dismiss repeatedly.
3. **It does not beat two fixed thresholds here.** Recall is higher only when attacks are rare, at four times the false-positive rate and lower precision. At 5 % and 15 % prevalence the thresholds are better on precision and comparable or better on recall.
4. **Low-volume attacks are mostly missed** (slow brute force 7–28 %), because six volume counts cannot separate them from a user who mistypes a password.
5. The features have no time window, rate, or per-entity history, and the model assigns severity `low`. More data will not fix this; the feature set would have to change.

### Recommendation

Keep the Isolation Forest disabled, as it is now, and keep deterministic rules as the detection baseline. Do not present an ML false-positive rate for this product: none has been measured on labelled real data. Before enabling any anomaly score, the project needs windowed and rate-based features, per-entity baselines or an allow-list for known gateways and scanners, a labelled or analyst-reviewed real sample, and a contamination value chosen from the alert volume analysts can actually review.

### Limits of this evaluation

The population, its profile mix, and the attack shapes are assumptions written for this test; different assumptions give different numbers. Attacks are single-profile and not mixed with normal activity from the same source. The project's own `entity_aware_split` (alphabetical by entity) was replaced with a random entity split. The real-data check covers one small lab network and has no labels.
