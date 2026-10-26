# Persistent autoscaler privacy accounting

`research.simulation.privacy_ledger.PersistentUserPrivacyLedger` optionally
extends the autoscaler experiment's per-artifact basic composition accountant
across separate batch-run processes. It does not change the noise mechanism or
create a privacy guarantee. The mechanism's stated guarantee remains
conditional on its fixed-horizon observer, contribution bound, identity
assumptions, and random-bit source; deterministic seeded experiment artifacts
do not have a differential-privacy guarantee.

## Accounting behavior

The caller supplies a stable authenticated principal ID for each release. The
ledger stores a domain-separated HMAC-SHA256 pseudonym for each principal and
for each release, along with exact decimal epsilon/delta totals and release
counts. Raw principal IDs, individual release ID strings, the HMAC key, and
filesystem paths are not written to the database or report; the report records
a random run namespace and key/identity fingerprints. The database reader can
still link a principal pseudonym across releases and observe participation
relationships, release counts, and accumulated budget values.

Every release uses a SQLite `BEGIN IMMEDIATE` transaction. The ledger checks
the duplicate release token and every affected principal's lifetime budget
before writing any rows. The release row, updated per-principal totals, and
release-to-principal links commit atomically. Concurrent processes therefore
serialize budget checks. The optional epsilon and delta ceilings and the
identity-registry fingerprint are fixed when the ledger is created; reopening
with different limits, key material, or registry contents fails closed.

The batch runner requires authenticated user IDs, a nonzero user contribution
cap, and the `dp_laplace` policy before it accepts ledger paths. It generates
a fresh CSPRNG run ID, records that ID and key/identity fingerprints in the
artifact config, and prefixes release IDs with it. The report distinguishes
the run-local `privacy_composition` from the cumulative
`persistent_privacy_ledger` snapshot. Ledger charging occurs before the
corresponding simulated horizon is processed. A later process or output
failure can therefore conservatively consume budget without producing a
complete artifact.

## Local setup and use

The ledger's parent directory and key file must be owner-only. The key must be
an owner-owned regular file containing exactly 32 random bytes. Create it
outside the repository and keep a durable protected backup; losing it makes
the existing ledger unreadable.

```sh
umask 077
mkdir -m 700 "$HOME/oblivion-private-ledger"
python3 - <<'PY'
import os
import secrets

path = os.path.expanduser("~/oblivion-private-ledger/ledger.key")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    remaining = memoryview(secrets.token_bytes(32))
    while remaining:
        written = os.write(fd, remaining)
        remaining = remaining[written:]
finally:
    os.close(fd)
PY

.venv/bin/python -m research.simulation.run \
  experiments/configs/YOUR_AUTHENTICATED_USER_DP_CONFIG.json \
  experiments/results/YOUR_NEW_RUN \
  --identity-registry /secure/path/identity-registry.json \
  --privacy-ledger "$HOME/oblivion-private-ledger/ledger.sqlite3" \
  --privacy-ledger-key "$HOME/oblivion-private-ledger/ledger.key" \
  --privacy-ledger-max-epsilon 10 \
  --privacy-ledger-max-delta 0.01
```

The database file is created with mode `0600`; its containing directory must
already exist with mode `0700` or stricter. CLI recording redacts ledger and
key paths. The identity registry must remain byte-identical while using one
ledger. Identity-key rotation and canonical account migration are not
implemented; use a reviewed migration procedure rather than silently opening
a new ledger and resetting composition.

Offline `scripts/regenerate_scaler.py` refits reports from retained raw
sessions. If the source artifact has a persistent-ledger snapshot, the
regenerator checks that snapshot against the artifact's local SHA-256 manifest
and copies it with `snapshot_status=copied_from_source_report_not_recomputed`.
It does not open the SQLite database or recompute lifetime composition.

## Security boundaries and limitations

This is a local research facility, not a remote accounting service. Its
security depends on the host OS protecting the owner-only directory and key
from other unprivileged users. A privileged operator or compromised process
can read the HMAC key, inspect the database, impersonate authenticated
principals, or edit local files. HMAC pseudonyms conceal direct identifiers
from a database-only reader without the key but do not conceal equality or
participation patterns.

There is no authenticated append-only log, remote witness, hardware monotonic
counter, or anti-rollback anchor. Restoring an older database backup can erase
later releases and bypass a lifetime budget; filesystem permissions and
SQLite transactions do not prevent that. Database corruption is detected as
an operational error where SQLite detects it, but records are not individually
authenticated. A deployment requiring rollback resistance needs an external
trusted monotonic anchor and a reviewed state-recovery protocol.

The accounting uses basic sequential composition over the releases recorded
by this ledger. It does not verify the implementation's sensitivity proof,
protect workload labels or private performance artifacts, account for
unrecorded external releases, prove stable real-world identity, or cover
queueing, timing, cost, host metadata, and the complete runtime transcript.
See [`SAMPLER_AUDIT.md`](SAMPLER_AUDIT.md) and
[`SECURITY_ASSUMPTIONS.md`](SECURITY_ASSUMPTIONS.md) for the separate
mechanism and identity assumptions.
