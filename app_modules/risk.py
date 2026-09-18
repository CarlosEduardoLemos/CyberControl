def calculate_risk_score(cvss_score, asset_criticality="Média", internet_exposed=False, kev=False):
    """Calcula um score contextual simples para priorização.

    O resultado é um mecanismo de triagem e não substitui uma avaliação formal de risco.
    """
    criticality_weight = {
        "Baixa": 0.75,
        "Média": 1.0,
        "Alta": 1.15,
        "Crítica": 1.30,
    }.get(asset_criticality, 1.0)

    score = float(cvss_score) * criticality_weight
    if internet_exposed:
        score += 0.8
    if kev:
        score += 1.5
    return round(min(score, 10.0), 1)


def risk_level(score):
    score = float(score)
    if score >= 9:
        return "Crítico"
    if score >= 7:
        return "Alto"
    if score >= 4:
        return "Médio"
    return "Baixo"
