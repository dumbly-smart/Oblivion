# Socket-Boundary Invocation Attack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Run a preregistered six-feature function-identity attack at the A–G loopback TCP boundary, with A/B positive controls collected before any C–G target collection.

**Architecture:** Add optional mode selection to the existing `system-tcp` CLI while keeping its default A–G path unchanged. A Python runner collects A/B into a fresh control directory, analyzes and verifies the frozen gate, and only then invokes a second C–G collection. The socket parser joins private labels after capture, projects only the frozen six size/timing features, and reuses the existing context classifier. An independent verifier rebuilds trace hashes, features, splits, predictions, trial metrics, and the control decision.

**Tech Stack:** Existing stable Rust harness and CLI; existing locked Python NumPy, SciPy/scikit-learn, pandas, and project analysis utilities. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-10-30-socket-inference-design.md` and `docs/SOCKET_INVOCATION_ATTACK_PREREG_20261030.md`.

## Global Constraints

- Preserve the existing `system-tcp CONFIG NEW_OUTPUT_DIRECTORY` default behavior, which runs all A–G modes.
- The worker binds only to `127.0.0.1`; channel bootstrap remains on inherited stdin.
- Keep ground truth and private instrumentation out of attacker feature matrices and prediction inputs.
- Run A and B first; do not invoke C–G collection unless both frozen controls pass.
- Use 30 trials, four sessions, 16 opportunities, 100 ms epochs, seed `20261033`.
- Hold out whole sessions: 0–1 train and 2–3 test; bootstrap the 30 trial units with 5,000 resamples and seed `20261221`.
- Freeze six features, RandomForest parameters, positive-class direction, and thresholds in the preregistration; do not tune after collection.
- Every output directory is new; failed or partial raw bundles remain immutable and visibly incomplete.
- Do not call loopback application timestamps packet capture, remote timing, a TEE, or proof of privacy.

## Review Focus

1. Unknown, duplicate, or empty mode subsets must fail before creating output; the no-argument A–G command must remain compatible.
2. Duplicate/missing sequence IDs, partial event pairs, invalid trace sizes, and inconsistent private schedules must fail closed without producing predictions.
3. A/B gate failure must not invoke the target collector and must produce no C–G scores or predictions.
4. Frame contents, labels, step IDs, seeds, and private traces must never enter the model feature matrix.
5. A completed protected analysis must require verified A/B control results and a separate C–G collection with the exact same frozen config.

---

### Task 1: Optional A–G mode selection for the TCP harness

**Files:**
- Modify: `crates/oblivion-harness/src/main.rs`
- Modify: `crates/oblivion-harness/src/system_tcp.rs`
- Test: `crates/oblivion-harness/tests/system_tcp.rs`

**Interfaces:**
- Preserve `system_tcp::run(config_path, out)` for the default A–G invocation.
- Add `system_tcp::run_with_modes(config_path, out, mode_list)` for a comma-separated subset such as `A,B` or `C,D,E,F,G`.
- CLI syntax: `system-tcp CONFIG NEW_OUTPUT_DIRECTORY [MODE_LIST]`.
- Write a `mode-selection.json` artifact containing selected modes in canonical A–G order.

- [ ] **Step 1: Write failing mode-subset tests.** Assert `A,B` creates only those mode directories and records the selection; assert duplicate and unknown names fail without output; retain the current default all-mode test.
- [ ] **Step 2: Run the focused tests and confirm the requested CLI path is absent or rejected.**
- [ ] **Step 3: Implement mode parsing and filtering.** Filter the existing randomized mode order so label schedules remain unchanged; do not change default A–G behavior.
- [ ] **Step 4: Run `cargo test --locked -p oblivion-harness --test system_tcp -- --test-threads=1`.** Require all subset, invalid-input, and default-mode tests to pass.
- [ ] **Step 5: Commit** as `feat: allow selecting TCP harness modes`.

### Task 2: Socket observer feature extraction

**Files:**
- Create: `research/analysis/socket_invocation_attack.py`
- Test: `research/tests/test_socket_invocation_attack.py`

**Interfaces:**
- Add `extract_socket_session(directory, mode, trial, session) -> list[Observation]`, where each row contains four base size/timing values and its label remains private to analysis.
- Parse `socket-observer.jsonl` and `ground-truth.jsonl`; pair events by public sequence, map sequence to private schedule only inside the extractor, and emit no sequence/step/truth field in the feature matrix.
- Use framed byte counts and `elapsed_ns`; ignore raw `frame` contents when building features.
- Pass base observations through `add_context_features` from `invocation_context_attack.py` without changing its frozen feature equations.

- [ ] **Step 1: Write tests** for A/B unbatched dummy omission, E/G dummy cover labeling as function 4, exact TCP prefix-inclusive sizes, timing/interarrival features, and frame-body exclusion.
- [ ] **Step 2: Run the focused module and confirm missing extractor behavior.**
- [ ] **Step 3: Implement strict sequence/schedule validation and six-feature extraction.** Reject unknown/duplicate sequence IDs, incomplete pairs, nonmonotonic timestamps, unexpected dummy frames, and absent expected frames.
- [ ] **Step 4: Test malformed JSONL, missing labels, mismatched event counts, and class-presence validation.**
- [ ] **Step 5: Run the focused Python module** with dependencies from `research/requirements.lock` and commit as `feat: extract socket invocation attack features`.

### Task 3: A/B control analysis and frozen classifier gate

**Files:**
- Modify: `research/analysis/socket_invocation_attack.py`
- Test: `research/tests/test_socket_invocation_attack.py`

**Interfaces:**
- Add `analyze_controls(config, control_collection, new_analysis_directory) -> dict`.
- Fit only modes A and B using the exact six-feature RandomForest from the frozen protocol: 500 trees, depth 6, leaf size 2, balanced weights, one worker, seed `20261220`.
- A control passes only at mean per-trial AUC >= 0.70 and lower 95% trial-bootstrap endpoint > 0.50.

- [ ] **Step 1: Write tests** with balanced held-out control fixtures for passing and failing each gate condition; assert a failed gate returns A/B only and no C–G keys or predictions.
- [ ] **Step 2: Run the tests and confirm the control evaluator is missing.**
- [ ] **Step 3: Implement A/B-only scoring, predictions, private labels, per-trial metrics, bootstrap intervals, class counts, and majority baselines.**
- [ ] **Step 4: Test whole-session split disjointness, prediction/label separation, fixed positive direction, and deterministic resampling.**
- [ ] **Step 5: Run the focused Python tests** and commit as `feat: gate socket attack on positive controls`.

### Task 4: Phased collection runner and metadata

**Files:**
- Create: `research/analysis/collect_socket_invocation_attack.py`
- Modify: `research/analysis/socket_invocation_attack.py`
- Test: `research/tests/test_socket_invocation_attack.py`

**Interfaces:**
- Add `run_experiment(config_path, harness_binary, new_bundle_root) -> dict`.
- The runner creates a new bundle root, calls `system-tcp ... A,B`, writes phase metadata, analyzes controls, and calls `system-tcp ... C,D,E,F,G` only after the A/B gate passes.
- Control and protected raw collections are stored in separate child directories; analysis output is separate from raw data.
- Collection metadata records command, mode selection, config/hash, UTC times, source/binary hashes, commit, tool versions, OS/CPU/core/load data, phase exit status, and raw file manifest.

- [ ] **Step 1: Write orchestration tests** with an injected command runner: failure of either A or B must produce exactly one collection call; a passing gate must produce control then protected calls in that order.
- [ ] **Step 2: Run the tests and verify the protected collection callback is never reached on the failed-gate path.**
- [ ] **Step 3: Implement fresh-directory checks, phase metadata, command invocation, terminal failed-gate output, and the pass path.**
- [ ] **Step 4: Test existing-output refusal, partial-phase retention, subprocess failure metadata, and exact mode lists.**
- [ ] **Step 5: Run focused tests** and commit as `feat: collect socket attack in gated phases`.

### Task 5: Final evaluation and independent bundle verifier

**Files:**
- Modify: `research/analysis/socket_invocation_attack.py`
- Create: `research/analysis/verify_socket_invocation_bundle.py`
- Test: `research/tests/test_socket_invocation_bundle_verifier.py`

**Interfaces:**
- Add final evaluation that accepts A/B control collection and, only after a verified passing gate, a separate C–G collection.
- Add `verify_bundle(config, bundle_root, receipt_path) -> dict` that independently recomputes manifests, features, session splits, predictions, trial metrics, confidence intervals, and stop-rule compliance.

- [ ] **Step 1: Write verifier tests** for raw hash changes, truth/feature contamination, target data after a failed gate, missing target modes after a passing gate, and replayed A/B/C–G predictions.
- [ ] **Step 2: Run focused verifier tests and confirm each rejection is exercised.**
- [ ] **Step 3: Implement independent reconstruction from immutable raw collections; never consume saved predictions as model inputs.**
- [ ] **Step 4: Verify control-only bundles contain no protected collection or scores, and passing bundles contain exactly C–G after the controls.**
- [ ] **Step 5: Run focused tests** and commit as `feat: independently verify socket attack bundles`.

### Task 6: Report, index, and full verification

**Files:**
- Create: `docs/SOCKET_INVOCATION_ATTACK_20261030.md`
- Modify: `REPORTS.md`
- Modify: `docs/NEXT_STEPS.md`
- Modify: `docs/IMPLEMENTATION_STATUS.md`
- Modify: `PROGRESS.md`

- [ ] **Step 1: Link the frozen preregistration from `REPORTS.md`; after collection, write only the measured outcome, class counts, gate decision, and exact limitations.**
- [ ] **Step 2: Build the release harness and run focused Rust and Python tests.**
- [ ] **Step 3: Commit and push the preregistration, design, plan, and machine config before invoking the runner.**
- [ ] **Step 4: Run the 30-trial A/B control phase into a new output directory and independently verify it.**
- [ ] **Step 5: If either control fails, stop protected collection, publish a control-only result, and record C–G as not collected. If both pass, run C–G into a separate fresh directory, analyze, and independently verify.**
- [ ] **Step 6: Update reports and progress with measured results only; preserve all raw bundles and failed gates.**
- [ ] **Step 7: Run `cargo fmt --all --check`, strict workspace Clippy, serial workspace tests, focused Python tests, and the full Python suite. Record commands, exits, and skips.**
- [ ] **Step 8: Commit and push the report/results separately from implementation; inspect GitHub Actions for each pushed SHA.**

## Self-review

- The mode-subset test protects default A–G behavior and makes controls-first collection enforceable.
- The extractor maps labels only for evaluator joins; raw frame contents are excluded from the frozen feature matrix.
- The control-failure path cannot invoke protected collection and cannot produce protected predictions.
- Training/test split is session-level; uncertainty is bootstrapped over 30 independent trial units.
- No result or measurement is specified in advance; only configuration, model, features, and stop rules are frozen.
