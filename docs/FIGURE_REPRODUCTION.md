# Reproduce required figures from committed measurements

The 2026-10-23 audit regenerated all eight required main figures from committed measurement inputs without an ignored executable, plus the supplemental three-axis/SLO figure. It used fresh `/tmp` copies and preserved all accepted inputs, reports, figures and historical manifests. Every regenerated PNG was byte-identical on the audited environment; the rebuilt numerical reports also matched. Different plotting-library versions can change image bytes, so numerical report equality remains the portable comparison.

| Figure | Committed input directory | Reanalysis input and independent units |
|---|---|---|
| `latency-privacy.png` | `system-fixed-publication-30-20261022` | Actual A–G observer/truth/metrics, 30 fitted-model trials per mode, four whole sessions/trial, 13,440 opportunities total |
| `bandwidth-privacy.png` | Same | Same raw common-workload counters and fitted trial results |
| `cost-attack.png` | Same | Same raw measured wall occupation; declared hypothetical cost model |
| `ablation-attacks.png` | Same | Same per-mode fitted trial results and trial bootstrap |
| `oram-size.png` | `oram-size-30-20261021` | 120 genuine per-controller measurement summaries, 30 each at 16/64/256/1,024 blocks; mean of each trial's read/write p95 values |
| `batching-overhead-vs-epoch.png` | `batch-epoch-current` | 270 actual timer/AEAD trial raw files; 69,120 arrivals/frames and 8,640 emissions; nine period/real-fraction cells |
| `pareto-hot.png` | `scaler-paper-30-final` | Retained public/private/workload raw streams; refit independent trial models and rebuild performance/cost/Pareto summaries |
| `pareto-intensity.png` | Same | Same retained raw streams and independent trial refits |

The A–G command additionally regenerates `pareto-three-axis-slo.png`. The batching command additionally writes the publication PDF. The second autoscaler campaign, `scaler-prewarm2-30-final`, was also rebuilt from raw and both of its PNGs matched exactly.

## Commands that preserve accepted artifacts

Run from the repository root in the pinned research Python environment. The preparation step copies only tracked files for the component measurements; it does not copy ignored binaries. Autoscaler inputs are restricted further to the configuration and three raw gzip streams, deliberately excluding cached reports and figures.

```sh
export FIGURE_AUDIT_ROOT="$(mktemp -d /tmp/oblivion-figure-reproduction-XXXXXX)"
.venv/bin/python - <<'PY'
import os
from pathlib import Path
import shutil
import subprocess

root = Path.cwd()
work = Path(os.environ['FIGURE_AUDIT_ROOT'])
for label, name in [
    ('system', 'system-fixed-publication-30-20261022'),
    ('oram', 'oram-size-30-20261021'),
    ('batch', 'batch-epoch-current'),
]:
    source = root/'experiments/results'/name
    tracked = subprocess.check_output(
        ['git', 'ls-files', str(source.relative_to(root))], text=True).splitlines()
    for name in tracked:
        original = root/name
        destination = work/label/original.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
for label, name in [
    ('scaler-raw', 'scaler-paper-30-final'),
    ('scaler-prewarm2-raw', 'scaler-prewarm2-30-final'),
]:
    destination = work/label
    destination.mkdir()
    for file in ['config.json', 'observer.jsonl.gz', 'private.jsonl.gz',
                 'workloads-private.jsonl.gz']:
        shutil.copy2(root/'experiments/results'/name/file, destination/file)
print(work)
PY

PYTHONPATH="$PWD" .venv/bin/python -m research.analysis.system "$FIGURE_AUDIT_ROOT/system"
PYTHONPATH="$PWD" .venv/bin/python scripts/sweep_oram.py "$FIGURE_AUDIT_ROOT/oram" --plot-only
.venv/bin/python -m research.analysis.open_loop --batch "$FIGURE_AUDIT_ROOT/batch"
.venv/bin/python scripts/regenerate_scaler.py \
  "$FIGURE_AUDIT_ROOT/scaler-raw" "$FIGURE_AUDIT_ROOT/scaler-rebuilt"
.venv/bin/python scripts/regenerate_scaler.py \
  "$FIGURE_AUDIT_ROOT/scaler-prewarm2-raw" "$FIGURE_AUDIT_ROOT/scaler-prewarm2-rebuilt"
```

The autoscaler output directory must be new. For the other three existing analysis interfaces, the temporary measurement copy is the output directory; their analysis files and images are rewritten only inside that copy. No measurement process, compiler or ignored binary is invoked.

## Autoscaler raw reconstruction

The previously available `research.simulation.run --plot-only` consumed a cached report. It remains useful for changing plot rendering, but alone does not reconstruct a report from raw evidence. `scripts/regenerate_scaler.py RAW_SOURCE NEW_OUTPUT` closes that missing route. It reads only `config.json`, `observer.jsonl.gz`, `private.jsonl.gz` and `workloads-private.jsonl.gz`; it neither reads an accepted report nor runs the simulator or workload generator.

The helper checks exact raw schemas, complete unique trial/session/workload/policy sets, contiguous epoch identities, observer feature whitelists, label protocol and public/private alignment before creating output. It reconstructs lifecycle completion/drop/unfinished counts, latency quantiles, SLO failures, cold starts and time-integrated queue waiting as checks against recorded private session counters. It checks cost against recorded instance-seconds and the explicit configured price. Exact instance-seconds and queue maximum remain retained private counters: the public epoch snapshots and request lifecycles do not contain complete per-worker assignment/retirement identities. Their equal-weight target-session aggregation is rebuilt from those raw counters, rather than copied from a report.

For every trial/workload/policy/task, the helper uses the existing `evaluate` implementation: the first four complete sessions profile and the last four test in the recorded eight-session campaigns. The classifier sees only the existing observable vectors; target truth is used for scoring. It recomputes the 5,000-resample trial intervals, positive-control results, three-axis point-estimate Pareto membership and 1% SLO-filtered cost/leakage frontier using the existing functions and original prices. It writes new input/source hash provenance, report, figures and an output artifact manifest. Failure to validate inputs creates no analysis directory. Synthetic campaigns with imported traces are outside this bounded reconstruction route.

Both accepted autoscaler campaigns passed a raw-only replay using four-file copies with no cached report or images. Each replay validated **4,800 public sessions, 4,800 private sessions and 960 workload sessions**, rebuilt **1,050 trial/task/policy results and 35 summaries**, and exactly matched the accepted configuration, trial metrics, summaries, positive-control results and both images. Original inputs were hashed before/after and remained unchanged. Tests create genuine small simulator fixtures, remove their reports/images, forbid simulator calls during reconstruction, and check missing/duplicate sessions, private observer fields and inconsistent raw counters.

## Audit identities

The tracked-file component audit copied 4,211 system files, 258 ORAM files and 547 batching files into `/tmp/oblivion-figure-audit-20261023-bxf3q0pf`. Its raw-derived A–G summaries/trials, ORAM summary and batching analysis exactly matched accepted values. All nine generated PNGs, including supplemental Pareto, matched accepted bytes. The raw-only autoscaler audit used `/tmp/oblivion-scaler-raw-audit-20261023-l6kdr6hm`; these temporary paths are local audit evidence, not required inputs for another clone.

Analysis source SHA-256 fingerprints at this audit:

```text
250f9836cce295f2c14ac724ca03f2b363e105195b0aaa7f99be61212f230800  research/analysis/system.py
32b34d78fa5e2fcccd1acf1bd7b04afddde58efe6b55efd11af1e6f9bca0a35d  research/attacks/joint.py
1b10e7450e646a99327f0de5301391fcc5484092e8457741ad3f7349438b8af1  scripts/sweep_oram.py
c7f54682eff8141b9834c8c716f0ddaabde457767c529ea4f698e73e54f97b42  research/analysis/open_loop.py
64182dd9e18dc16016da5dd21e3ae0f61babaadfe6380e6b96a2da100069a940  research/simulation/run.py
ca38bdf58c402cb9c30ce4f0e754c7db97abaf8b3aa8ef75a19919d459d09568  research/simulation/scaler.py
c801d8fca16758f5b456f21a8c9667a8d7b1e28bf0d5f430208a26a364a43c03  scripts/regenerate_scaler.py
```

The new raw reconstruction helper fingerprints itself and both simulation modules in each regenerated report. The accepted scaler-paper raw input SHA-256 values are:

```text
18b0a2a2835fcfa33743f11641ceb83a88064c658bda72383e2fc8f5792b1af4  config.json
95456302d4d475337950c7da146816ce32737b29558c496f3099150450a8e641  observer.jsonl.gz
17fda95887b760f97f14f8b0ed49cd6d8c40cb3fe28f6aebb0043d62f701e742  private.jsonl.gz
01045b7e0d826ce66d9406a321303509b2ea6f9c4e9abce841a9c019ae21f508  workloads-private.jsonl.gz
```

Presence/intersection raw reconstruction is documented separately in [PRESENCE_EVALUATION.md](PRESENCE_EVALUATION.md), including its compatibility check for an absent ignored measurement executable and accurate available-artifact verification counts.

Compact machine-readable audit records are retained under [figure-reproduction-20261023](../experiments/results/figure-reproduction-20261023/): [component audit](../experiments/results/figure-reproduction-20261023/component-audit.json), [raw-only scaler replays](../experiments/results/figure-reproduction-20261023/scaler-raw-audit.json), [binary-free presence replay](../experiments/results/figure-reproduction-20261023/presence-clone-audit.json), and their [artifact hashes](../experiments/results/figure-reproduction-20261023/artifact-sha256.json). They record consumed-input fingerprints, source fingerprints, sample counts, comparisons, output figure hashes and unchanged-original checks without duplicating raw streams or PNGs. The component record distinguishes retained preanalysis snapshot hashes verified afterward from its original before/after audit; the scaler record preserves explicit raw fingerprints before and after reconstruction.
