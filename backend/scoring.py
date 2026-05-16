import os
from math import ceil
from typing import Dict, Literal, TypedDict

from models import AttackObjective, MaestroLayer, AtfaaThreat


MAESTRO_WEIGHT: Dict[MaestroLayer, float] = {
    MaestroLayer.FOUNDATION_MODEL: 1.25,
    MaestroLayer.DATA_OPS: 1.30,
    MaestroLayer.AGENT_FRAMEWORK: 1.10,
    MaestroLayer.INFRASTRUCTURE: 1.35,
    MaestroLayer.SECURITY: 1.50,
    MaestroLayer.AGENT_ECOSYSTEM: 1.15,
}


ATFAA_WEIGHT: Dict[AtfaaThreat, float] = {
    AtfaaThreat.COGNITIVE: 1.20,
    AtfaaThreat.PERSISTENCE: 1.15,
    AtfaaThreat.EXECUTION: 1.30,
    AtfaaThreat.BOUNDARY: 1.40,
    AtfaaThreat.GOVERNANCE: 1.50,
}


CVSS_SCOPE: Dict[Literal["U", "C"], float] = {
    "U": 6.42,
    "C": 7.52,
}

CVSS_AV: Dict[Literal["N", "A", "L", "P"], float] = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.20,
}

CVSS_AC: Dict[Literal["L", "H"], float] = {
    "L": 0.77,
    "H": 0.44,
}

CVSS_PR_U: Dict[Literal["N", "L", "H"], float] = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27,
}

CVSS_PR_C: Dict[Literal["N", "L", "H"], float] = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}

CVSS_UI: Dict[Literal["N", "R"], float] = {
    "N": 0.85,
    "R": 0.62,
}

CVSS_IMPACT: Dict[Literal["N", "L", "H"], float] = {
    "N": 0.00,
    "L": 0.22,
    "H": 0.56,
}


class CvssMetrics(TypedDict):
    scope: Literal["U", "C"]
    av: Literal["N", "A", "L", "P"]
    ac: Literal["L", "H"]
    pr: Literal["N", "L", "H"]
    ui: Literal["N", "R"]
    c: Literal["N", "L", "H"]
    i: Literal["N", "L", "H"]
    a: Literal["N", "L", "H"]


def assign_base_scores(obj: AttackObjective):
    vulnerability = obj.vulnerability_type.lower()

    impact = 5
    exploitability = 5
    exposure = 5
    privilege = 5
    sensitivity = 5

    # --- Direct attacks ---
    if "rce" in vulnerability or "command injection" in vulnerability:
        impact = 10
        exploitability = 8
        privilege = 9
        sensitivity = 8
    elif "sql injection" in vulnerability:
        impact = 9
        exploitability = 7
        exposure = 8
        sensitivity = 9
    elif "ssrf" in vulnerability:
        impact = 8
        exploitability = 7
        exposure = 9
    elif "rbac" in vulnerability or "access control" in vulnerability:
        impact = 9
        exploitability = 6
        privilege = 8
    elif "system prompt leak" in vulnerability:
        impact = 7
        exploitability = 8
        exposure = 8
        sensitivity = 9

    # --- Indirect attacks ---
    elif "pdf" in vulnerability or "lfi" in vulnerability:
        impact = 7
        exploitability = 6
        exposure = 8
    elif "indirect data exfil" in vulnerability or "data exfil" in vulnerability:
        impact = 8
        exploitability = 7
        exposure = 8
        sensitivity = 9

    # Prompt injection (direct and indirect — matched after more specific checks)
    elif "prompt injection" in vulnerability:
        impact = 6
        exploitability = 9
        exposure = 10

    # --- Multi-turn attacks ---
    elif "multi-turn" in vulnerability or "multiturn" in vulnerability:
        impact = 7
        exploitability = 8
        exposure = 9
        sensitivity = 6
    elif "memory" in vulnerability or "context poisoning" in vulnerability:
        impact = 7
        exploitability = 7
        exposure = 8
        sensitivity = 7

    # --- MCP attacks ---
    elif "mcp tool poisoning" in vulnerability:
        impact = 9
        exploitability = 8
        exposure = 7
        privilege = 7
        sensitivity = 8
    elif "mcp excessive permissions" in vulnerability:
        impact = 8
        exploitability = 6
        exposure = 6
        privilege = 9
    elif "mcp missing authentication" in vulnerability:
        impact = 9
        exploitability = 9
        exposure = 8
        privilege = 8
        sensitivity = 6
    elif "mcp tool shadowing" in vulnerability:
        impact = 9
        exploitability = 7
        exposure = 7
        privilege = 7
        sensitivity = 8
    elif "rug pull" in vulnerability:
        impact = 8
        exploitability = 6
        exposure = 6
        privilege = 7
        sensitivity = 8
    elif "mcp insecure transport" in vulnerability:
        impact = 7
        exploitability = 7
        exposure = 8
        sensitivity = 7
    elif "mcp cross-agent" in vulnerability or "cross-agent" in vulnerability:
        impact = 8
        exploitability = 7
        exposure = 7
        privilege = 8
        sensitivity = 6

    # --- RAG attacks ---
    elif "rag knowledge base injection" in vulnerability or "knowledge base injection" in vulnerability:
        impact = 9
        exploitability = 7
        exposure = 9
        sensitivity = 8
    elif "rag indirect prompt injection" in vulnerability:
        impact = 8
        exploitability = 8
        exposure = 9
        sensitivity = 7
    elif "cross-tenant" in vulnerability:
        impact = 9
        exploitability = 6
        exposure = 8
        sensitivity = 10
    elif "retrieval bypass" in vulnerability:
        impact = 7
        exploitability = 7
        exposure = 8
        sensitivity = 6
    elif "context window stuffing" in vulnerability:
        impact = 6
        exploitability = 7
        exposure = 8
    elif "embedding inversion" in vulnerability:
        impact = 7
        exploitability = 5
        exposure = 7
        sensitivity = 9

    return impact, exploitability, exposure, privilege, sensitivity


def _round_up_1_decimal(value: float) -> float:
    return ceil(value * 10) / 10.0


def infer_cvss_metrics(obj: AttackObjective) -> CvssMetrics:
    vulnerability = obj.vulnerability_type.lower()

    metrics: CvssMetrics = {
        "scope": "U",
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "c": "L",
        "i": "L",
        "a": "L",
    }

    if "rce" in vulnerability or "command injection" in vulnerability:
        metrics.update({"scope": "C", "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "H"})
    elif "sql injection" in vulnerability:
        metrics.update({"scope": "C", "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "H", "i": "H", "a": "L"})
    elif "ssrf" in vulnerability:
        metrics.update({"scope": "C", "av": "N", "ac": "L", "pr": "N", "ui": "N", "c": "L", "i": "L", "a": "L"})
    elif "prompt injection" in vulnerability:
        metrics.update({"scope": "C", "av": "N", "ac": "L", "pr": "N", "ui": "R", "c": "L", "i": "H", "a": "L"})
    elif "rbac" in vulnerability or "access control" in vulnerability:
        metrics.update({"scope": "C", "av": "N", "ac": "L", "pr": "L", "ui": "N", "c": "H", "i": "H", "a": "L"})
    elif "pdf" in vulnerability or "lfi" in vulnerability:
        metrics.update({"scope": "U", "av": "N", "ac": "H", "pr": "N", "ui": "R", "c": "L", "i": "L", "a": "L"})

    return metrics


def calculate_cvss_base_severity(obj: AttackObjective) -> float:
    metrics = infer_cvss_metrics(obj)

    impact_subscore = 1 - (
        (1 - CVSS_IMPACT[metrics["c"]])
        * (1 - CVSS_IMPACT[metrics["i"]])
        * (1 - CVSS_IMPACT[metrics["a"]])
    )

    if metrics["scope"] == "U":
        impact = CVSS_SCOPE["U"] * impact_subscore
        pr_value = CVSS_PR_U[metrics["pr"]]
    else:
        impact = CVSS_SCOPE["C"] * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
        pr_value = CVSS_PR_C[metrics["pr"]]

    exploitability = 8.22 * CVSS_AV[metrics["av"]] * CVSS_AC[metrics["ac"]] * pr_value * CVSS_UI[metrics["ui"]]

    if impact <= 0:
        return 0.0

    if metrics["scope"] == "U":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)

    return _round_up_1_decimal(score)


def calculate_base_severity(obj: AttackObjective) -> float:
    impact, exploitability, exposure, privilege, sensitivity = assign_base_scores(obj)

    base_score = (
        impact * 0.35
        + exploitability * 0.25
        + exposure * 0.15
        + privilege * 0.15
        + sensitivity * 0.10
    )

    return round(base_score, 2)


def compute_final_severity(obj: AttackObjective) -> float:
    scoring_mode = os.getenv("SCORING_MODE", "cvss").strip().lower()

    cvss_base = calculate_cvss_base_severity(obj)

    if scoring_mode == "hybrid":
        maestro_multiplier = MAESTRO_WEIGHT.get(obj.maestro_layer, 1.0)
        atfaa_multiplier = ATFAA_WEIGHT.get(obj.atfaa_domain, 1.0)
        final_score = cvss_base * maestro_multiplier * atfaa_multiplier
        return round(min(final_score, 10.0), 2)

    if scoring_mode == "legacy":
        base = calculate_base_severity(obj)

        maestro_multiplier = MAESTRO_WEIGHT.get(obj.maestro_layer, 1.0)
        atfaa_multiplier = ATFAA_WEIGHT.get(obj.atfaa_domain, 1.0)

        final_score = base * maestro_multiplier * atfaa_multiplier
        return round(min(final_score, 10.0), 2)

    return round(cvss_base, 2)


def derive_priority(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def score_attack(obj: AttackObjective):
    severity = compute_final_severity(obj)
    obj.severity = severity
    obj.priority = derive_priority(severity)
    return severity