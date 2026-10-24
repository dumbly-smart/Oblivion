"""Synthetic sensitivity analysis for semantic presence/intersection attacks.

This models declared observables only; it is not a network-capture experiment.
"""
import argparse
import hashlib
import json
import math
import random
from pathlib import Path

LIMITATIONS = [
    "synthetic scenarios only; no real network capture or packet timing is modeled",
    "simulated noisy beacon is not differential privacy",
    "attacker receives only per-session client-presence observations and the public beacon bit sequence",
    "sessions, not epochs, are the independent sampling and split units",
]


def load_config(value):
    config = json.loads(Path(value).read_text()) if isinstance(value, (str, Path)) else value
    if not isinstance(config, dict) or config.get("schema") != 1:
        raise ValueError("config schema must be 1")
    if not isinstance(config.get("scenarios"), list) or not config["scenarios"]:
        raise ValueError("at least one scenario is required")
    for key, low, high in (("beacon_sensitivity", 0, 1), ("beacon_false_positive", 0, 1),
                           ("enrollment_churn", 0, 1), ("missed_cover_rate", 0, 1),
                           ("owner_online_probability", 0, 1)):
        for scenario in config["scenarios"]:
            if not low <= scenario.get(key, -1) <= high:
                raise ValueError(f"{key} must be in [{low}, {high}]")
    if config.get("sessions", 0) < 4 or config.get("epochs", 0) < 1:
        raise ValueError("sessions must be >= 4 and epochs >= 1")
    fraction = config.get("train_fraction", 0)
    if not 0 < fraction < 1:
        raise ValueError("train_fraction must be between zero and one")
    if config.get("bootstrap_replicates", 0) < 100:
        raise ValueError("bootstrap_replicates must be >= 100")
    for scenario in config["scenarios"]:
        pop = scenario.get("population")
        if (not isinstance(pop, list) or len(pop) != 2 or pop[0] < 2 or pop[1] < pop[0]):
            raise ValueError("population must be [minimum, maximum] with minimum >= 2")
    return config


def _sessions(config, scenario, seed):
    rng = random.Random(seed)
    rows = []
    minimum, maximum = scenario["population"]
    for _ in range(config["sessions"]):
        count = rng.randint(minimum, maximum)
        owner = rng.randrange(count)
        # Latent state is used only by the simulator; it is never returned to inference.
        enrolled = [rng.random() < 0.6 for _ in range(count)]
        enrolled[owner] = True
        visible, beacon = [], []
        for _epoch in range(config["epochs"]):
            for candidate in range(count):
                if rng.random() < scenario["enrollment_churn"]:
                    enrolled[candidate] = not enrolled[candidate]
            owner_online = enrolled[owner] and rng.random() < scenario["owner_online_probability"]
            real_present = [candidate for candidate, active in enumerate(enrolled)
                            if active and (candidate != owner or owner_online)]
            # Only these two sequences are given to the attacker.
            visible.append([candidate for candidate in real_present
                            if rng.random() >= scenario["missed_cover_rate"]])
            event_prob = (scenario["beacon_sensitivity"] if owner in real_present
                          else scenario["beacon_false_positive"])
            beacon.append(int(rng.random() < event_prob))
        rows.append({"owner": owner, "population": count,
                     "observable": {"participants": visible, "beacon": beacon}})
    order = list(range(len(rows)))
    random.Random(seed ^ 0x5E5510).shuffle(order)
    cut = max(1, min(len(order)-1, round(len(order)*config["train_fraction"])))
    return rows, order[:cut], order[cut:]


def _infer(observable, population, sensitivity, false_positive, missed_cover):
    # Bayes factor for each candidate: beacon likelihood when that client's
    # presence marker is seen versus absent. Hidden labels/owner never enter.
    p1 = max(1e-6, min(1-1e-6, sensitivity * (1-missed_cover)))
    p0 = max(1e-6, min(1-1e-6, false_positive + sensitivity * missed_cover * 0.15))
    scores = [0.0] * population
    for seen, event in zip(observable["participants"], observable["beacon"]):
        seen = set(seen)
        for candidate in range(population):
            p = p1 if candidate in seen else p0
            scores[candidate] += math.log(p if event else 1-p)
    return max(range(population), key=lambda candidate: (scores[candidate], -candidate))


def _interval(values, seed, replicates):
    n = len(values)
    mean = sum(values) / n
    rng = random.Random(seed)
    samples = sorted(sum(rng.choice(values) for _ in range(n))/n for _ in range(replicates))
    return {"mean": mean, "ci95": [samples[int(.025*replicates)], samples[min(replicates-1, int(.975*replicates))]],
            "unit": "whole independent test session"}


def evaluate(raw_config):
    config = load_config(raw_config)
    results = []
    for index, scenario in enumerate(config["scenarios"]):
        rows, train_ids, test_ids = _sessions(config, scenario, config["seed"] + index * 100003)
        # Estimate the base beacon rate on training sessions only. It is the
        # class baseline; no session is split across train and test.
        train_events = [event for i in train_ids for event in rows[i]["observable"]["beacon"]]
        base_rate = sum(train_events) / len(train_events)
        attacker, random_baseline, prior_baseline = [], [], []
        for i in test_ids:
            row = rows[i]
            prediction = _infer(row["observable"], row["population"], scenario["beacon_sensitivity"],
                                scenario["beacon_false_positive"], scenario["missed_cover_rate"])
            attacker.append(int(prediction == row["owner"]))
            random_baseline.append(1 / row["population"])
            prior_baseline.append(int(row["owner"] == 0))
        reps = config["bootstrap_replicates"]
        results.append({
            "name": scenario["name"], "label": "synthetic explicitly labeled scenario",
            "description": scenario["description"],
            "parameters": {key: scenario[key] for key in ("population", "beacon_sensitivity", "beacon_false_positive", "enrollment_churn", "missed_cover_rate", "owner_online_probability")},
            "split": {"unit": "whole independent session", "train_sessions": len(train_ids), "test_sessions": len(test_ids),
                      "train_base_beacon_rate": base_rate},
            "attacker": {"accuracy": _interval(attacker, config["seed"]+index*11, reps),
                         "successes": sum(attacker)},
            "class_baselines": {"uniform_random_expected_accuracy": sum(random_baseline)/len(random_baseline),
                                "fixed_first_candidate_accuracy": _interval(prior_baseline, config["seed"]+index*17, reps)},
            "chance_by_population": {str(n): 1/n for n in sorted(set(row["population"] for row in rows))},
        })
    control_names = config.get("positive_controls", ["positive_control"])
    controls = []
    by_name = {result["name"]: result for result in results}
    for name in control_names:
        if name not in by_name:
            raise ValueError(f"positive control scenario is missing: {name}")
        control = by_name[name]
        chance = control["class_baselines"]["uniform_random_expected_accuracy"]
        lower = control["attacker"]["accuracy"]["ci95"][0]
        if lower <= chance:
            raise RuntimeError(f"positive control {name} did not exceed its population-adjusted random baseline")
        controls.append({"scenario": name, "lower_ci95_exceeds_uniform_random": True,
                         "accuracy": control["attacker"]["accuracy"], "uniform_random_expected_accuracy": chance})
    return {"schema": 1, "seed": config["seed"], "sessions": config["sessions"],
            "epochs": config["epochs"], "train_fraction": config["train_fraction"],
            "bootstrap_replicates": config["bootstrap_replicates"],
            "label": config.get("label", "synthetic explicitly labeled scenarios"),
            "method": "Per-session likelihood ranking using only client-presence markers and semantic beacon bits.",
            "attacker_observables": ["client identity presence by epoch", "semantic beacon bit by epoch"],
            "positive_controls": controls,
            "limitations": LIMITATIONS, "scenarios": results}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = evaluate(args.config)
    config_path = Path(args.config)
    result["run_parameters"] = {"seed": result.get("seed"), "sessions_per_scenario": result.get("sessions"),
                                "epochs_per_session": result.get("epochs"),
                                "train_fraction": result.get("train_fraction"),
                                "bootstrap_replicates": result.get("bootstrap_replicates")}
    result["provenance"] = {
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "analysis_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "frozen_presence_analysis_sha256": hashlib.sha256(Path(__file__).with_name("presence.py").read_bytes()).hexdigest(),
        "frozen_presence_attack_sha256": hashlib.sha256(Path(__file__).parents[1].joinpath("attacks", "presence.py").read_bytes()).hexdigest(),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(out), "scenarios": len(result["scenarios"]),
                      "positive_controls": result["positive_controls"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
