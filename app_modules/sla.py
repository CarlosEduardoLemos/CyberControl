from datetime import date, datetime, timedelta

SLA_DAYS = {
    "Crítica": 7,
    "Alta": 15,
    "Média": 30,
    "Baixa": 60,
    "Nenhuma": 90,
}


def default_due_date(discovered_date, severity):
    if isinstance(discovered_date, str):
        discovered = date.fromisoformat(discovered_date)
    elif isinstance(discovered_date, datetime):
        discovered = discovered_date.date()
    else:
        discovered = discovered_date
    return (discovered + timedelta(days=SLA_DAYS.get(severity, 30))).isoformat()


def sla_status(due_date, status, today=None):
    if status == "Resolvida":
        return "Resolvida"
    if not due_date:
        return "Sem prazo"
    current = today or date.today()
    deadline = date.fromisoformat(due_date) if isinstance(due_date, str) else due_date
    days = (deadline - current).days
    if days < 0:
        return "Vencido"
    if days <= 3:
        return "Próximo do vencimento"
    return "Dentro do SLA"
