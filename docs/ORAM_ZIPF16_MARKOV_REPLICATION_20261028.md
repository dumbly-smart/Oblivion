# ORAM Zipf-16 Markov Leaf/Timing Replication — Results

This report records the study frozen in
[the preregistration](ORAM_ZIPF16_MARKOV_REPLICATION_PREREG_20261028.md).
The experiment ran from 2026-10-28 13:22:26 to 13:23:54 UTC using the pushed
preregistration commit `1cc21e3b3ddde8f939eb9150611f44e9a0f07b81`.

## Result

The sole primary metric was mean per-trial ROC AUC over 30 fitted attacks,
with a percentile bootstrap across those 30 trial means. Both positive
controls passed their preregistered thresholds before Path ORAM was evaluated.

| Mode | Mean AUC | 95% trial-bootstrap interval | Mean balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: | ---: |
| Plaintext | 1.0000 | [1.0000, 1.0000] | 0.9997 | 0.5706 |
| Encrypt-only | 1.0000 | [1.0000, 1.0000] | 0.9999 | 0.5706 |
| Path ORAM | 0.4968 | [0.4864, 0.5072] | 0.4983 | 0.5706 |

The positive controls show that the frozen attacker could distinguish hot
from cold addresses under the two leaky configurations. For Path ORAM the
primary interval includes 0.5, and the measured mean is slightly below chance.
No score direction was reversed after seeing the result. This run did not
reproduce the earlier possible weak timing signal under this workload and
measurement boundary. It does not rule out a smaller effect, different
attacker, workload, host, or timing interface, and it is not a security proof.

The configured hot-class base probability was 0.5827; its realized proportion
across paired traces was 0.5785. The realized read proportion was 0.8014. The
profile-majority baseline therefore scored 57.06% raw accuracy, which is why
ROC AUC is the primary metric and raw accuracy is not treated as chance here.

## Work actually measured

Each of 30 trials used eight fresh sessions of 256 accesses: four complete
profile sessions and four disjoint target sessions. There were 61,440 logical
accesses per mode and 30,720 held-out target observations per mode. The same
deterministically seeded address and read/write schedule was checked across
plaintext, encrypt-only and ORAM modes. Cryptographic keys and ORAM state were
fresh per session.

The 32-block Path ORAM used six buckets per root-to-leaf path. Each logical
access therefore produced 12 actual bucket-service events (six reads and six
writes), each with a 316-byte bucket payload and fixed 325-byte service
request/response frames. The service timer covered only the in-memory bucket
handler. It excluded ORAM path calculation, pipe waiting, request decoding,
response encoding and trace output. This is isolated component timing, not
end-to-end or remote-network timing.

The host was a 24-logical-CPU Intel Core i7-14650HX running Linux. The bucket
service was pinned to logical CPU 0 and the driver to CPU 2, which were on
different physical cores at preregistration time. The cores were not reserved.
The one-minute load average rose from 6.46 at run start to 7.52 at run end;
host scheduling, interrupts, frequency changes and unrelated work remain
possible timing noise. The study took 88.44 seconds.

## Integrity and reproducibility

The run retained 1,440 compressed raw observer/driver files, three-mode
predictions, the machine-readable configuration, host snapshots, service-child
metadata, source/binary hashes, `report.json`, `verification.json` and the AUC
figure. Independent post-run checks matched all 1,440 SHA-256 entries, checked
all 240 paired trial/session schedules, checked 720 service-process CPU masks,
recomputed all 90 per-mode trial means and bootstrap intervals, and verified
that every profile/target split was disjoint. The result bundle occupies about
11 MiB.

The focused ORAM replication/timing test modules passed 12 tests before
collection, and both release measurement examples built. The exact collection
command is frozen in the preregistration. The plot is
[`auc.png`](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/auc.png);
the summary and the raw data used to produce it are in the linked result
directory. Run `research.analysis.oram_isolated_replication` with the
preregistered configuration and a new output directory to repeat the complete
collection. The runner refuses to overwrite existing results.

## Artifacts

- [Frozen configuration](../experiments/configs/oram-isolated-zipf16-markov-replication-20261028.json)
- [Raw report and metadata](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/report.json)
- [Independent verification record](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/verification.json)
- [Raw observer and driver traces](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/raw/)
- [Per-trial predictions](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/predictions/)
- [AUC figure](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/auc.png)

The attacker implementation, source files and both release binaries are
identified by SHA-256 hashes in `report.json`. This experiment changes the
workload and repeats the established classifier; it does not independently
reimplement or cryptographically analyze that classifier or Path ORAM.
