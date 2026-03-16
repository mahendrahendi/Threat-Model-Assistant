"""
DREAD Risk Scoring Engine.
Provides scoring utilities, risk classification, and score aggregation.
"""

from engine.threat_model import DREADScore


# DREAD factor descriptions for UI tooltips
DREAD_FACTORS = {
    "damage": {
        "name": "Damage Potential",
        "description": "How severe would the damage be if this threat is exploited?",
        "scale": {
            1: "Minimal impact — cosmetic or negligible",
            3: "Minor data disclosure or limited functionality impact",
            5: "Moderate — single user account compromise or partial data loss",
            7: "Significant — multiple accounts, substantial data breach",
            9: "Severe — full system compromise, massive data breach",
            10: "Catastrophic — complete business destruction, regulatory penalties"
        }
    },
    "reproducibility": {
        "name": "Reproducibility",
        "description": "How easy is it to reproduce this attack consistently?",
        "scale": {
            1: "Nearly impossible — requires rare conditions",
            3: "Difficult — needs specific timing or conditions",
            5: "Moderate — reproducible with some effort",
            7: "Easy — can be reproduced reliably with known steps",
            9: "Trivial — always works, fully automated",
            10: "Guaranteed — exploit is deterministic"
        }
    },
    "exploitability": {
        "name": "Exploitability",
        "description": "How easy is it to actually perform this attack?",
        "scale": {
            1: "Expert-level — requires deep knowledge and custom tools",
            3: "Advanced — needs security expertise",
            5: "Intermediate — script kiddie level with available tools",
            7: "Easy — point-and-click exploit tools exist",
            9: "Trivial — browser/curl is sufficient",
            10: "No skill needed — can be triggered accidentally"
        }
    },
    "affected_users": {
        "name": "Affected Users",
        "description": "How many users or systems would be impacted?",
        "scale": {
            1: "None or single test account",
            3: "Individual user or small group",
            5: "Subset of users (e.g., one role or department)",
            7: "Large portion of users",
            9: "All users of the system",
            10: "All users plus downstream systems/partners"
        }
    },
    "discoverability": {
        "name": "Discoverability",
        "description": "How easy is it for an attacker to discover this vulnerability?",
        "scale": {
            1: "Extremely difficult — requires insider knowledge",
            3: "Difficult — needs advanced reconnaissance",
            5: "Moderate — discoverable through systematic testing",
            7: "Easy — common vulnerability scanning tools will find it",
            9: "Obvious — visible in public documentation or UI",
            10: "Already publicly known or documented"
        }
    }
}


def calculate_risk_level(score):
    """Classify a DREAD overall score into a risk level."""
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"


def get_risk_color(level):
    """Return color hex for a given risk level."""
    return {
        "Critical": "#ff0040",
        "High": "#ff4757",
        "Medium": "#ffa502",
        "Low": "#2ed573"
    }.get(level, "#747d8c")


def update_threat_score(threat, scores):
    """
    Update a threat's DREAD scores from user input.
    scores: dict with keys damage, reproducibility, exploitability, affected_users, discoverability
    """
    if "damage" in scores:
        threat.dread_score.damage = DREADScore._clamp(scores["damage"])
    if "reproducibility" in scores:
        threat.dread_score.reproducibility = DREADScore._clamp(scores["reproducibility"])
    if "exploitability" in scores:
        threat.dread_score.exploitability = DREADScore._clamp(scores["exploitability"])
    if "affected_users" in scores:
        threat.dread_score.affected_users = DREADScore._clamp(scores["affected_users"])
    if "discoverability" in scores:
        threat.dread_score.discoverability = DREADScore._clamp(scores["discoverability"])
    return threat


def aggregate_risk_summary(threats):
    """
    Calculate aggregate risk metrics across all threats.
    Returns summary statistics for executive reporting.
    """
    if not threats:
        return {
            "total_threats": 0,
            "by_risk_level": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "by_stride": {},
            "average_score": 0,
            "highest_risk": None,
            "risk_distribution": []
        }

    by_level = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_stride = {}
    scores = []

    for t in threats:
        level = t.dread_score.risk_level
        by_level[level] = by_level.get(level, 0) + 1

        cat = t.category
        if cat not in by_stride:
            by_stride[cat] = {"count": 0, "avg_score": 0, "scores": []}
        by_stride[cat]["count"] += 1
        by_stride[cat]["scores"].append(t.dread_score.overall)

        scores.append(t.dread_score.overall)

    # Calculate averages per STRIDE category
    for cat in by_stride:
        cat_scores = by_stride[cat]["scores"]
        by_stride[cat]["avg_score"] = round(sum(cat_scores) / len(cat_scores), 1)
        del by_stride[cat]["scores"]

    sorted_threats = sorted(threats, key=lambda t: t.dread_score.overall, reverse=True)

    return {
        "total_threats": len(threats),
        "by_risk_level": by_level,
        "by_stride": by_stride,
        "average_score": round(sum(scores) / len(scores), 1),
        "highest_risk": sorted_threats[0].to_dict() if sorted_threats else None,
        "risk_distribution": [
            {"level": level, "count": count, "color": get_risk_color(level)}
            for level, count in by_level.items()
        ]
    }


def get_dread_factors_info():
    """Return DREAD factor descriptions for UI display."""
    return DREAD_FACTORS
