# Full-path CPU cost sensitivity

Updated 2026-10-26. This analysis normalizes measurements from the retained
[extended open-loop experiment](RUNTIME_POPULATION_EXTENDED.md); it performs no
new system collection and does not estimate a cloud bill.

## Method

Each observation is one fresh full-path executor process from the extended
experiment. CPU is the observed Linux procfs process-tree total for the driver,
executor, and two PIR children. Startup and teardown CPU are excluded. The
primary measure is the ratio of total observed CPU seconds to total successful
outputs, scaled to 1,000 outputs. Confidence intervals use 5,000 deterministic
bootstrap resamples of whole trial processes, preserving each process as the
unit of resampling. A resample with zero successful outputs has an undefined
success-normalized ratio; the report counts these draws explicitly and forms
the interval only from defined draws. The secondary normalization uses total
offered requests. SLO failure is weighted by offered requests. RSS is sampled
aggregate process tree RSS, not peak or billable memory.

The report validates the source experiment's hash manifest before analyzing
its 60 rows. It records the three input artifact hashes, analysis-script hash,
input-manifest hash, Python/NumPy versions, and source Git head in the output.
No rate file was supplied, so the retained output contains no dollar values.

## Results

| Offered-load profile | Successful / offered | CPU seconds / 1,000 successes (95% trial bootstrap) | CPU seconds / 1,000 offers (95% trial bootstrap) | Offered-load SLO failures |
| --- | ---: | ---: | ---: | ---: |
| steady-128-i150-q2 | 3,840 / 3,840 | 9.758 [9.458, 10.086] | 9.758 [9.458, 10.086] | 0% |
| overload-256-i25-q2 | 1,980 / 7,680 | 7.237 [6.965, 7.500] | 1.866 [1.796, 1.934] | 99.22% |

The overloaded profile's lower CPU per successful output is a consequence of
admission dropping 5,700 of 7,680 offers. It is not evidence of better useful
capacity: nearly all offered requests fail the SLO. The per-offer normalization
makes the wasted offered work visible alongside the success-normalized ratio.
Both profiles have similar sampled aggregate RSS (about 25.64 MiB), but this
measurement is not a peak-memory bound.

## Reproduction

Install the locked research dependencies as described in
[EXPERIMENTS.md](EXPERIMENTS.md), then run from the repository root:

```sh
.venv/bin/python research/analysis/runtime_cost_sensitivity.py \
  --input experiments/results/runtime-population-extended-20261024 \
  --output experiments/results/runtime-cost-sensitivity-reproduced
```

The output directory must not already exist. The default run is deterministic
for the saved input and writes `report.json`, `analysis-provenance.json`, and
the two PNG figures. Optional price sensitivities can be supplied explicitly
as a JSON array, for example
`[{"label":"analyst scenario","usd_per_vcpu_hour":0.25}]` via `--rates
rates.json`. The conversion is CPU-seconds per 1,000 successes multiplied by
the supplied USD per vCPU-hour rate and divided by 3,600. Such a value is only
the named analyst scenario; it is not a provider recommendation or a measured
price.

The checked-in corrected result is in
[`experiments/results/runtime-cost-sensitivity-20261026-v2/`](../experiments/results/runtime-cost-sensitivity-20261026-v2/).
It was generated without `--rates` from the source artifact manifest whose
hash is retained in `analysis-provenance.json`. Both profiles had all 5,000
success-normalized bootstrap draws defined; the report still records those
counts explicitly.

## Limits

This is a single-host, shared-host measurement from the existing synthetic
load profiles. It excludes network egress, storage rent, idle capacity,
autoscaler instance-seconds, startup/teardown CPU, and provider-specific
resource accounting. It does not establish remote or multi-host capacity,
long-term workload behavior, production billing, or a cost/privacy optimum.
Treat the bootstrap intervals as uncertainty over these trial processes only,
not as general deployment uncertainty.
