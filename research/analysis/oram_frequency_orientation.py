"""Select a score orientation using labeled profile sessions only."""

from dataclasses import dataclass

from sklearn.metrics import roc_auc_score

from research.analysis.oram_attack_families import TagFrequencyAttack


@dataclass(frozen=True)
class OrientationSelection:
    sign: int
    validation_auc: float
    validation_sessions: int
    validation_observations: int


def orientation_from_validation(labels, scores):
    """Choose a score sign from validation labels; ties keep the original sign."""
    if len(labels) != len(scores) or not labels:
        raise ValueError("validation labels and scores must be non-empty and aligned")
    if any(label not in (0, 1) for label in labels):
        raise ValueError("validation labels must be binary")
    if any(not isinstance(score, (int, float)) for score in scores):
        raise ValueError("validation scores must be numeric")
    if set(labels) != {0, 1}:
        raise ValueError("both validation classes are required")
    auc = float(roc_auc_score(labels, scores))
    sign = -1 if auc < 0.5 else 1
    return OrientationSelection(sign, auc, 0, len(labels))


def select_profile_orientation(profile_rows, profile_labels):
    """Cross-validate score direction by leaving out each whole profile session."""
    if len(profile_rows) != len(profile_labels) or not profile_rows:
        raise ValueError("profile rows and labels must be non-empty and aligned")
    sessions = sorted({row.get("session") for row in profile_rows})
    if len(sessions) < 2 or None in sessions:
        raise ValueError("at least two identified profile sessions are required")
    if any(label not in (0, 1) for label in profile_labels):
        raise ValueError("profile labels must be binary")

    validation_labels = []
    validation_scores = []
    for held_out in sessions:
        train_indices = [i for i, row in enumerate(profile_rows) if row["session"] != held_out]
        test_indices = [i for i, row in enumerate(profile_rows) if row["session"] == held_out]
        train_rows = [profile_rows[i] for i in train_indices]
        train_labels = [profile_labels[i] for i in train_indices]
        test_rows = [profile_rows[i] for i in test_indices]
        if set(train_labels) != {0, 1} or not test_rows:
            raise ValueError("each held-out profile fold requires both training classes")
        model = TagFrequencyAttack().fit(train_rows, train_labels)
        _, scores = model.run(test_rows, {held_out})
        validation_labels.extend(profile_labels[i] for i in test_indices)
        validation_scores.extend(scores)

    selected = orientation_from_validation(validation_labels, validation_scores)
    return OrientationSelection(
        selected.sign,
        selected.validation_auc,
        len(sessions),
        selected.validation_observations,
    )
