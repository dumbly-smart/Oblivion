# Incomplete campaign: host filesystem exhaustion

The first fault campaign stopped after launch 107 when the host filesystem returned ENOSPC while rewriting trials.json. That file was truncated to zero bytes. Per-launch stdout/stderr and initial metadata remain; there is no complete aggregate or accepted result for this directory. The stdout evidence from earlier launches is not promoted into a complete campaign.

The runner was fixed with atomic replacement and independent per-trial records; an injected-publication-error regression test verifies that previously written records survive. The entire 210-launch experiment was then rerun in a fresh directory `../fault-campaign-30-20261023-retry/`, with stable source and binary hashes and all assertions passing. Only project build caches were temporarily moved to /tmp to free space, then returned once disk space became available. No source or raw result was removed.
