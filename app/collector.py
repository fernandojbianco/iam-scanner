"""
Coleta de dados IAM: Azure RBAC (todas as subscriptions) + Entra ID directory roles.
Autentica via Service Principal (client_id + client_secret).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx
from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient

log = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

RISK_CRITICAL = {
    "Owner", "User Access Administrator", "IAM Admin",
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}
RISK_HIGH = {
    "Contributor", "Key Vault Administrator", "Key Vault Data Access Administrator",
    "User Administrator", "Security Administrator", "Authentication Administrator",
    "Hybrid Identity Administrator", "Conditional Access Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Directory Writers", "Groups Administrator", "Helpdesk Administrator",
    "Password Administrator",
    # Microsoft 365
    "Exchange Administrator", "SharePoint Administrator", "Teams Administrator",
    "Teams Communications Administrator", "Skype for Business Administrator",
    "Office Apps Administrator",
}
RISK_MEDIUM = {
    "Key Vault Secrets Officer", "Key Vault Contributor", "Storage Account Key Operator Service Role",
    "Cognitive Services Contributor", "SQL DB Contributor", "Automation Contributor",
    "Storage Blob Data Owner", "Data Factory Contributor", "Avere Contributor",
    "Global Reader", "Directory Readers", "Security Reader", "Security Operator",
    "Identity Governance Administrator", "Compliance Administrator",
    "Compliance Data Administrator", "Guest Inviter",
    # Microsoft 365
    "Exchange Recipient Administrator", "SharePoint Embedded Administrator",
    "Teams Devices Administrator", "Teams Communications Support Engineer",
    "Teams Communications Support Specialist", "Viva Engage Administrator",
    "Viva Goals Administrator", "Viva Pulse Administrator", "Insights Administrator",
    "Search Administrator", "Message Center Privacy Reader", "Kaizala Administrator",
}
RISK_LOW = {
    "Reader", "Billing Reader", "Cost Management Reader", "Storage Blob Data Reader",
    "Storage Queue Data Reader", "Container Registry Repository Reader",
    "Reports Reader", "License Administrator", "Attribute Assignment Reader",
    "Attribute Definition Reader", "Directory Synchronization Accounts",
    "Usage Summary Reports Reader",
    # Microsoft 365
    "Insights Business Leader", "Message Center Reader", "Search Editor",
}

# Roles administrativas específicas do Microsoft 365 (Exchange/SharePoint/Teams/Viva/etc.)
# usadas apenas para rotular a origem ("workload") da atribuição no dashboard/notificações —
# a coleta em si já vem do mesmo endpoint de directory roles do Entra ID.
M365_ROLES = {
    "Exchange Administrator", "Exchange Recipient Administrator",
    "SharePoint Administrator", "SharePoint Embedded Administrator",
    "Teams Administrator", "Teams Communications Administrator",
    "Teams Communications Support Engineer", "Teams Communications Support Specialist",
    "Teams Devices Administrator", "Skype for Business Administrator",
    "Viva Engage Administrator", "Viva Goals Administrator", "Viva Pulse Administrator",
    "Insights Administrator", "Insights Business Leader",
    "Office Apps Administrator", "Search Administrator", "Search Editor",
    "Message Center Reader", "Message Center Privacy Reader", "Kaizala Administrator",
}


def classify_risk(role: str) -> str:
    if role in RISK_CRITICAL:
        return "CRITICO"
    if role in RISK_HIGH:
        return "ALTO"
    if role in RISK_MEDIUM:
        return "MEDIO"
    if role in RISK_LOW:
        return "LEITURA"
    return "INFO"


def classify_workload(role: str) -> str:
    return "M365" if role in M365_ROLES else "Entra ID"


def scope_type(scope: str, sub_id: str) -> str:
    s = scope.replace(f"/subscriptions/{sub_id}", "")
    if not s or s == "/":
        return "Subscription"
    if "Microsoft.Management/managementGroups" in s:
        return "Management Group"
    parts = [p for p in s.split("/") if p]
    return "Resource Group" if len(parts) <= 2 else "Recurso"


@dataclass
class RoleAssignment:
    subscription: str
    subscription_id: str
    principal_type: str
    principal: str
    role: str
    risk_level: str
    scope_type: str
    scope: str


@dataclass
class EntraAssignment:
    principal_type: str
    principal: str
    role: str
    risk_level: str
    scope: str
    workload: str = "Entra ID"


@dataclass
class ScanResult:
    collected_at: str
    subscriptions: list[dict]
    azure_assignments: list[dict]
    entra_assignments: list[dict]
    summary: dict
    errors: list[str] = field(default_factory=list)
    group_names: dict[str, str] = field(default_factory=dict)
    group_memberships: dict[str, list[dict]] = field(default_factory=dict)


class IAMCollector:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)

    # ------------------------------------------------------------------ #
    # Azure RBAC                                                           #
    # ------------------------------------------------------------------ #

    def _list_subscriptions(self) -> list[dict]:
        client = SubscriptionClient(self.credential)
        subs = []
        for s in client.subscriptions.list():
            if s.state == "Enabled":
                subs.append({"id": s.subscription_id, "name": s.display_name})
        log.info("Found %d enabled subscriptions", len(subs))
        return subs

    def _resolve_principal_names(self, ids: set[str], token: str) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        names: dict[str, str] = {}
        ids_list = [i for i in ids if i]
        with httpx.Client(timeout=30) as client:
            for i in range(0, len(ids_list), 1000):
                batch = ids_list[i:i + 1000]
                resp = client.post(
                    f"{GRAPH_BASE}/directoryObjects/getByIds",
                    headers=headers,
                    json={"ids": batch},
                )
                resp.raise_for_status()
                for obj in resp.json().get("value", []):
                    names[obj["id"]] = obj.get("userPrincipalName") or obj.get("displayName") or obj["id"]
        return names

    def _collect_rbac(self, sub_id: str, sub_name: str) -> list[RoleAssignment]:
        client = AuthorizationManagementClient(self.credential, sub_id)
        assignments = []
        try:
            role_names = {
                rd.id: rd.role_name
                for rd in client.role_definitions.list(scope=f"/subscriptions/{sub_id}")
            }
            for a in client.role_assignments.list_for_subscription():
                role = role_names.get(a.role_definition_id) or (a.role_definition_id or "").rsplit("/", 1)[-1]
                principal = a.principal_id or ""
                p_type = (a.principal_type or "").value if hasattr(a.principal_type, "value") else str(a.principal_type or "")
                scope = a.scope or ""
                scope_short = scope.replace(f"/subscriptions/{sub_id}", "") or "(subscription)"
                assignments.append(RoleAssignment(
                    subscription=sub_name,
                    subscription_id=sub_id,
                    principal_type=p_type,
                    principal=principal,
                    role=role,
                    risk_level=classify_risk(role),
                    scope_type=scope_type(scope, sub_id),
                    scope=scope_short,
                ))
        except Exception as e:
            log.warning("RBAC error on %s: %s", sub_name, e)
        return assignments

    # ------------------------------------------------------------------ #
    # Entra ID (Microsoft Graph)                                           #
    # ------------------------------------------------------------------ #

    def _graph_get(self, path: str, token: str) -> dict:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        with httpx.Client(timeout=30) as client:
            resp = client.get(f"{GRAPH_BASE}{path}", headers=headers)
            resp.raise_for_status()
            return resp.json()

    def _graph_paginate(self, path: str, token: str) -> list[dict]:
        items = []
        url = f"{GRAPH_BASE}{path}"
        headers = {"Authorization": f"Bearer {token}"}
        with httpx.Client(timeout=30) as client:
            while url:
                resp = client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
        return items

    def _collect_entra(self) -> list[EntraAssignment]:
        token = self.credential.get_token("https://graph.microsoft.com/.default").token

        # Role definitions (template IDs -> names)
        role_defs_raw = self._graph_paginate(
            "/roleManagement/directory/roleDefinitions?$select=id,displayName&$top=200", token
        )
        role_map = {r["id"]: r["displayName"] for r in role_defs_raw}

        # All role assignments with expanded principal
        raw = self._graph_paginate(
            "/roleManagement/directory/roleAssignments?$expand=principal&$top=999", token
        )

        assignments = []
        for a in raw:
            role = role_map.get(a.get("roleDefinitionId", ""), "?")
            principal = a.get("principal") or {}
            p_type = principal.get("@odata.type", "").replace("#microsoft.graph.", "")
            p_name = (
                principal.get("userPrincipalName")
                or principal.get("displayName")
                or principal.get("id", "?")
            )
            scope = a.get("directoryScopeId", "/")
            assignments.append(EntraAssignment(
                principal_type=p_type,
                principal=p_name,
                role=role,
                risk_level=classify_risk(role),
                scope=scope if scope != "/" else "Tenant inteiro",
                workload=classify_workload(role),
            ))
        return assignments

    # ------------------------------------------------------------------ #
    # Grupos monitorados                                                    #
    # ------------------------------------------------------------------ #

    def _collect_group_names(self, group_ids: list[str], token: str) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {token}"}
        names: dict[str, str] = {}
        with httpx.Client(timeout=30) as client:
            for gid in group_ids:
                resp = client.get(f"{GRAPH_BASE}/groups/{gid}?$select=id,displayName", headers=headers)
                resp.raise_for_status()
                names[gid] = resp.json().get("displayName", gid)
        return names

    def _collect_group_members(self, group_id: str, token: str) -> list[dict]:
        raw = self._graph_paginate(f"/groups/{group_id}/members?$select=id,displayName,userPrincipalName", token)
        members = []
        for m in raw:
            p_type = m.get("@odata.type", "").replace("#microsoft.graph.", "") or "user"
            name = m.get("userPrincipalName") or m.get("displayName") or m.get("id")
            members.append({"id": m.get("id"), "principal": name, "principal_type": p_type})
        return members

    def _collect_watched_groups(self, group_ids: list[str], errors: list[str]) -> tuple[dict[str, str], dict[str, list[dict]]]:
        group_names: dict[str, str] = {}
        group_memberships: dict[str, list[dict]] = {}
        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default").token
        except Exception as e:
            log.warning("Failed to acquire token for watched groups: %s", e)
            errors.append(f"watched_groups: {e}")
            return group_names, group_memberships

        try:
            group_names = self._collect_group_names(group_ids, token)
        except Exception as e:
            log.warning("Failed to resolve watched group names: %s", e)
            errors.append(f"watched_groups/names: {e}")
            group_names = {gid: gid for gid in group_ids}

        for gid in group_ids:
            try:
                group_memberships[gid] = self._collect_group_members(gid, token)
            except Exception as e:
                log.warning("Failed to collect members for group %s: %s", gid, e)
                errors.append(f"watched_groups/{gid}: {e}")

        return group_names, group_memberships

    # ------------------------------------------------------------------ #
    # Full scan                                                             #
    # ------------------------------------------------------------------ #

    def run(self, subscription_ids: Optional[list[str]] = None, watched_group_ids: Optional[list[str]] = None) -> ScanResult:
        now = datetime.now(timezone.utc).isoformat()
        errors: list[str] = []

        # Subscriptions
        try:
            all_subs = self._list_subscriptions()
        except Exception as e:
            log.error("Failed to list subscriptions: %s", e)
            all_subs = []
            errors.append(f"subscriptions: {e}")

        if subscription_ids:
            subs = [s for s in all_subs if s["id"] in subscription_ids]
        else:
            subs = all_subs

        # Azure RBAC
        azure_rows: list[RoleAssignment] = []
        for sub in subs:
            log.info("Collecting RBAC for %s ...", sub["name"])
            try:
                rows = self._collect_rbac(sub["id"], sub["name"])
                azure_rows.extend(rows)
                log.info("  → %d assignments", len(rows))
            except Exception as e:
                log.warning("RBAC failed for %s: %s", sub["name"], e)
                errors.append(f"rbac/{sub['name']}: {e}")

        # Resolve nomes dos principals do Azure RBAC (a API do ARM só retorna o principal_id)
        if azure_rows:
            try:
                token = self.credential.get_token("https://graph.microsoft.com/.default").token
                names = self._resolve_principal_names({r.principal for r in azure_rows}, token)
                for r in azure_rows:
                    r.principal = names.get(r.principal, r.principal)
            except Exception as e:
                log.warning("Falha ao resolver nomes de principals: %s", e)
                errors.append(f"resolve_principals: {e}")

        # Entra ID
        entra_rows: list[EntraAssignment] = []
        try:
            log.info("Collecting Entra ID role assignments ...")
            entra_rows = self._collect_entra()
            log.info("  → %d entra assignments", len(entra_rows))
        except Exception as e:
            log.warning("Entra ID collection failed: %s", e)
            errors.append(f"entra: {e}")

        # Grupos monitorados
        group_names: dict[str, str] = {}
        group_memberships: dict[str, list[dict]] = {}
        if watched_group_ids:
            log.info("Collecting membership of %d watched group(s) ...", len(watched_group_ids))
            group_names, group_memberships = self._collect_watched_groups(watched_group_ids, errors)

        # Summary
        from collections import Counter
        risk_counter_azure = Counter(r.risk_level for r in azure_rows)
        risk_counter_entra = Counter(r.risk_level for r in entra_rows)
        m365_rows = [r for r in entra_rows if r.workload == "M365"]
        risk_counter_m365 = Counter(r.risk_level for r in m365_rows)

        summary = {
            "total_subscriptions": len(subs),
            "total_azure_assignments": len(azure_rows),
            "total_entra_assignments": len(entra_rows),
            "total_m365_assignments": len(m365_rows),
            "azure_by_risk": dict(risk_counter_azure),
            "entra_by_risk": dict(risk_counter_entra),
            "m365_by_risk": dict(risk_counter_m365),
            "critical_azure": risk_counter_azure.get("CRITICO", 0),
            "critical_entra": risk_counter_entra.get("CRITICO", 0),
            "critical_m365": risk_counter_m365.get("CRITICO", 0),
            "total_watched_groups": len(group_memberships),
            "total_watched_group_members": sum(len(m) for m in group_memberships.values()),
        }

        def as_dict(obj):
            return obj.__dict__

        return ScanResult(
            collected_at=now,
            subscriptions=subs,
            azure_assignments=[as_dict(r) for r in sorted(azure_rows, key=lambda x: (
                ["CRITICO","ALTO","MEDIO","LEITURA","INFO",""].index(x.risk_level) if x.risk_level in ["CRITICO","ALTO","MEDIO","LEITURA","INFO"] else 9,
                x.subscription, x.principal
            ))],
            entra_assignments=[as_dict(r) for r in sorted(entra_rows, key=lambda x: (
                ["CRITICO","ALTO","MEDIO","LEITURA","INFO",""].index(x.risk_level) if x.risk_level in ["CRITICO","ALTO","MEDIO","LEITURA","INFO"] else 9,
                x.principal
            ))],
            summary=summary,
            errors=errors,
            group_names=group_names,
            group_memberships=group_memberships,
        )
