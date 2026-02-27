from typing import Dict

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


def assign_base_scores(obj: AttackObjective):
    vulnerability = obj.vulnerability_type.lower()

    impact = 5
    exploitability = 5
    exposure = 5
    privilege = 5
    sensitivity = 5

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
    elif "prompt injection" in vulnerability:
        impact = 6
        exploitability = 9
        exposure = 10
    elif "rbac" in vulnerability or "access control" in vulnerability:
        impact = 9
        exploitability = 6
        privilege = 8
    elif "pdf" in vulnerability or "lfi" in vulnerability:
        impact = 7
        exploitability = 6
        exposure = 8

    return impact, exploitability, exposure, privilege, sensitivity


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
    base = calculate_base_severity(obj)

    maestro_multiplier = MAESTRO_WEIGHT.get(obj.maestro_layer, 1.0)
    atfaa_multiplier = ATFAA_WEIGHT.get(obj.atfaa_domain, 1.0)

    final_score = base * maestro_multiplier * atfaa_multiplier
    return round(min(final_score, 10.0), 2)


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