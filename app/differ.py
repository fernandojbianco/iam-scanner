"""
Compara dois ScanResults e retorna as diferenças de atribuições IAM.
Só gera eventos para mudanças em níveis CRITICO e ALTO por padrão.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass
class Change:
    kind: Literal["added", "removed"]
    source: Literal["azure", "entra", "group"]
    risk_level: str
    principal: str
    principal_type: str
    role: str
    scope: str
    subscription: str = ""   # azure only
    workload: str = ""       # entra only: "Entra ID" ou "M365"


def _azure_key(r: dict) -> str:
    return f"{r['subscription_id']}|{r['principal']}|{r['role']}|{r['scope']}"


def _entra_key(r: dict) -> str:
    return f"{r['principal']}|{r['role']}|{r['scope']}"


NOTIFY_LEVELS = {"CRITICO", "ALTO"}


def diff(previous, current, notify_levels: set[str] = NOTIFY_LEVELS) -> list[Change]:
    """
    Recebe dois ScanResult.__dict__ (ou dicts com azure_assignments / entra_assignments).
    Retorna lista de Change com novidades e remoções.
    """
    changes: list[Change] = []

    # ---- Azure RBAC ----
    prev_az = {_azure_key(r): r for r in (previous.get("azure_assignments") or [])}
    curr_az = {_azure_key(r): r for r in (current.get("azure_assignments") or [])}

    for key, r in curr_az.items():
        if key not in prev_az and r["risk_level"] in notify_levels:
            changes.append(Change(
                kind="added", source="azure",
                risk_level=r["risk_level"],
                principal=r["principal"], principal_type=r["principal_type"],
                role=r["role"], scope=r["scope"], subscription=r["subscription"],
            ))

    for key, r in prev_az.items():
        if key not in curr_az and r["risk_level"] in notify_levels:
            changes.append(Change(
                kind="removed", source="azure",
                risk_level=r["risk_level"],
                principal=r["principal"], principal_type=r["principal_type"],
                role=r["role"], scope=r["scope"], subscription=r["subscription"],
            ))

    # ---- Entra ID ----
    prev_en = {_entra_key(r): r for r in (previous.get("entra_assignments") or [])}
    curr_en = {_entra_key(r): r for r in (current.get("entra_assignments") or [])}

    for key, r in curr_en.items():
        if key not in prev_en and r["risk_level"] in notify_levels:
            changes.append(Change(
                kind="added", source="entra",
                risk_level=r["risk_level"],
                principal=r["principal"], principal_type=r["principal_type"],
                role=r["role"], scope=r["scope"], workload=r.get("workload", "Entra ID"),
            ))

    for key, r in prev_en.items():
        if key not in curr_en and r["risk_level"] in notify_levels:
            changes.append(Change(
                kind="removed", source="entra",
                risk_level=r["risk_level"],
                principal=r["principal"], principal_type=r["principal_type"],
                role=r["role"], scope=r["scope"], workload=r.get("workload", "Entra ID"),
            ))

    # Críticos primeiro, depois adicionados antes de removidos
    priority = {"CRITICO": 0, "ALTO": 1}
    changes.sort(key=lambda c: (priority.get(c.risk_level, 9), c.kind != "added"))
    return changes


def diff_groups(
    previous: dict[str, list[dict]],
    current: dict[str, list[dict]],
    group_names: dict[str, str],
) -> list[Change]:
    """
    Compara membership de cada grupo monitorado entre duas coletas.
    Sempre gera evento (não é filtrado por notify_levels — grupos monitorados
    são escolhidos explicitamente pelo usuário).
    """
    changes: list[Change] = []
    group_ids = set(previous) | set(current)

    for gid in group_ids:
        group_name = group_names.get(gid, gid)
        prev_members = {m["id"]: m for m in previous.get(gid, [])}
        curr_members = {m["id"]: m for m in current.get(gid, [])}

        for mid, m in curr_members.items():
            if mid not in prev_members:
                changes.append(Change(
                    kind="added", source="group",
                    risk_level="GRUPO",
                    principal=m["principal"], principal_type=m["principal_type"],
                    role=group_name, scope=gid,
                ))

        for mid, m in prev_members.items():
            if mid not in curr_members:
                changes.append(Change(
                    kind="removed", source="group",
                    risk_level="GRUPO",
                    principal=m["principal"], principal_type=m["principal_type"],
                    role=group_name, scope=gid,
                ))

    changes.sort(key=lambda c: c.kind != "added")
    return changes
