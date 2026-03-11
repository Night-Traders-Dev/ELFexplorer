def _ordered_scores(scores):
    return sorted((scores or {}).items(), key=lambda item: item[1], reverse=True)


def explain_scores(scores, predicted, top_n=5):
    ordered = _ordered_scores(scores)
    top = ordered[:top_n]
    max_score = top[0][1] if top else 0
    second_score = top[1][1] if len(top) > 1 else 0
    margin = max_score - second_score

    competitors = [
        {"label": label, "score": score}
        for label, score in ordered
        if label != predicted
    ][:top_n]

    low_confidence = margin <= 2 or max_score <= 0
    reason = "Strong separation from competitors."
    if predicted == "Unknown":
        reason = "No class crossed minimum confidence threshold."
    elif str(predicted).startswith("Ambiguous:"):
        reason = "Multiple classes tied with close scores."
    elif low_confidence:
        reason = "Small score margin against competing classes."

    return {
        "predicted": predicted,
        "top_positive": [{"label": label, "score": score} for label, score in top],
        "top_competitors": competitors,
        "score_margin": margin,
        "max_score": max_score,
        "confidence_note": reason,
        "low_confidence": low_confidence,
    }


def build_scan_explanations(scan_result):
    artifact = scan_result.get("artifact_profile", {})
    return {
        "language": explain_scores(
            scan_result.get("language_scores", {}),
            scan_result.get("source_language", "Unknown"),
        ),
        "compiler": explain_scores(
            scan_result.get("compiler_scores", {}),
            scan_result.get("compiler", "Unknown"),
        ),
        "build_system": explain_scores(
            scan_result.get("build_scores", {}),
            scan_result.get("build_system", "Unknown"),
        ),
        "artifact": explain_scores(
            artifact.get("scores", {}),
            artifact.get("artifact_type", "Unknown"),
        ),
    }

