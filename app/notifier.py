"""
Envia notificações de mudanças IAM para o Microsoft Teams via Incoming Webhook.
Usa Adaptive Cards para formatação rica.
"""

import logging
from datetime import datetime, timezone

import httpx

from .differ import Change

log = logging.getLogger(__name__)

_RISK_COLOR = {
    "CRITICO": "attention",   # vermelho
    "ALTO":    "warning",     # laranja/amarelo
    "MEDIO":   "accent",      # azul
    "LEITURA": "good",        # verde
    "GRUPO":   "warning",     # laranja/amarelo
}

_RISK_EMOJI = {
    "CRITICO": "🔴",
    "ALTO":    "🟠",
    "MEDIO":   "🟡",
    "LEITURA": "🟢",
    "GRUPO":   "👥",
}

_SOURCE_LABEL = {
    "azure": "Azure RBAC",
    "entra": "Entra ID",
    "group": "Grupo Monitorado",
}

_WORKLOAD_LABEL = {
    "M365": "Microsoft 365",
    "Entra ID": "Entra ID",
}


def _source_label(c: "Change") -> str:
    if c.source == "entra":
        return _WORKLOAD_LABEL.get(c.workload, "Entra ID")
    return _SOURCE_LABEL[c.source]

_KIND_LABEL = {
    "added":   "➕ ADICIONADO",
    "removed": "➖ REMOVIDO",
}


def _build_card(changes: list[Change], scan_time: str, dashboard_url: str) -> dict:
    """Monta o payload Adaptive Card para o Teams."""

    added   = [c for c in changes if c.kind == "added"]
    removed = [c for c in changes if c.kind == "removed"]
    critical_added = [c for c in added if c.risk_level == "CRITICO"]

    title = (
        f"🚨 {len(critical_added)} acesso(s) CRÍTICO(S) detectado(s)"
        if critical_added
        else f"⚠️ {len(changes)} mudança(s) de acesso detectada(s)"
    )

    dt = datetime.fromisoformat(scan_time).astimezone().strftime("%d/%m/%Y %H:%M")

    # --- Rows da tabela de mudanças ---
    def change_rows(lst: list[Change]) -> list[dict]:
        rows = []
        for c in lst:
            scope_display = c.scope if c.scope else "Tenant inteiro"
            sub_display = f" ({c.subscription})" if c.subscription else ""
            rows.append({
                "type": "TableRow",
                "cells": [
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": f"{_RISK_EMOJI[c.risk_level]} **{c.risk_level}**", "wrap": True, "color": _RISK_COLOR.get(c.risk_level, "default")}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": _source_label(c), "wrap": True, "isSubtle": True}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": c.principal, "wrap": True, "fontType": "Monospace", "size": "Small"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": c.role, "wrap": True, "size": "Small"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": scope_display + sub_display, "wrap": True, "isSubtle": True, "size": "Small"}]},
                ],
            })
        return rows

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": title,
            "weight": "Bolder",
            "size": "Large",
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": f"Scan concluído em **{dt}** · Paraná Banco S/A",
            "isSubtle": True,
            "size": "Small",
            "spacing": "None",
        },
        {"type": "Container", "spacing": "Medium", "separator": True, "items": [
            {"type": "ColumnSet", "columns": [
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": f"**{len(added)}** adicionados", "color": "attention" if added else "default"}]},
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": f"**{len(removed)}** removidos", "color": "good" if removed else "default"}]},
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": f"**{len(changes)}** total", "isSubtle": True}]},
            ]},
        ]},
    ]

    if added:
        body.append({"type": "TextBlock", "text": "➕ Acessos Adicionados", "weight": "Bolder", "spacing": "Medium", "color": "attention"})
        body.append({
            "type": "Table",
            "columns": [
                {"width": 1}, {"width": 1}, {"width": 2}, {"width": 2}, {"width": 2},
            ],
            "firstRowAsHeader": True,
            "rows": [
                {"type": "TableRow", "style": "emphasis", "cells": [
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Nível", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Fonte", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Principal", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Role", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Escopo", "weight": "Bolder"}]},
                ]},
                *change_rows(added),
            ],
        })

    if removed:
        body.append({"type": "TextBlock", "text": "➖ Acessos Removidos", "weight": "Bolder", "spacing": "Medium", "color": "good"})
        body.append({
            "type": "Table",
            "columns": [{"width": 1}, {"width": 1}, {"width": 2}, {"width": 2}, {"width": 2}],
            "firstRowAsHeader": True,
            "rows": [
                {"type": "TableRow", "style": "emphasis", "cells": [
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Nível", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Fonte", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Principal", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Role", "weight": "Bolder"}]},
                    {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Escopo", "weight": "Bolder"}]},
                ]},
                *change_rows(removed),
            ],
        })

    actions = []
    if dashboard_url:
        actions.append({
            "type": "Action.OpenUrl",
            "title": "Abrir Dashboard",
            "url": dashboard_url,
            "style": "positive",
        })

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": body,
                "actions": actions if actions else [],
                "msteams": {"width": "Full"},
            },
        }],
    }
    return card


def _build_summary_card(result_dict: dict, scan_time: str, dashboard_url: str) -> dict:
    """Card de resumo periódico sem mudanças (heartbeat opcional)."""
    s = result_dict.get("summary", {})
    dt = datetime.fromisoformat(scan_time).astimezone().strftime("%d/%m/%Y %H:%M")

    body = [
        {"type": "TextBlock", "text": "✅ Scan IAM concluído — sem mudanças críticas", "weight": "Bolder", "size": "Medium"},
        {"type": "TextBlock", "text": f"Concluído em {dt} · Paraná Banco S/A", "isSubtle": True, "size": "Small", "spacing": "None"},
        {"type": "FactSet", "spacing": "Medium", "facts": [
            {"title": "Subscriptions:",         "value": str(s.get("total_subscriptions", 0))},
            {"title": "Atribuições Azure RBAC:", "value": str(s.get("total_azure_assignments", 0))},
            {"title": "Roles Críticas Azure:",   "value": str(s.get("critical_azure", 0))},
            {"title": "Atribuições Entra ID:",   "value": str(s.get("total_entra_assignments", 0))},
            {"title": "Roles Críticas Entra:",   "value": str(s.get("critical_entra", 0))},
            {"title": "Atribuições Microsoft 365:", "value": str(s.get("total_m365_assignments", 0))},
            {"title": "Roles Críticas M365:",    "value": str(s.get("critical_m365", 0))},
        ]},
    ]
    actions = []
    if dashboard_url:
        actions.append({"type": "Action.OpenUrl", "title": "Ver Dashboard", "url": dashboard_url})

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": body,
                "actions": actions,
                "msteams": {"width": "Full"},
            },
        }],
    }


def send_changes(
    webhook_url: str,
    changes: list[Change],
    scan_time: str,
    dashboard_url: str = "",
) -> bool:
    """Envia notificação de mudanças para o Teams. Retorna True se enviou com sucesso."""
    if not webhook_url or not changes:
        return False
    payload = _build_card(changes, scan_time, dashboard_url)
    return _post(webhook_url, payload)


def send_summary(
    webhook_url: str,
    result_dict: dict,
    scan_time: str,
    dashboard_url: str = "",
) -> bool:
    """Envia card de resumo periódico (heartbeat) para o Teams."""
    if not webhook_url:
        return False
    payload = _build_summary_card(result_dict, scan_time, dashboard_url)
    return _post(webhook_url, payload)


def _post(url: str, payload: dict) -> bool:
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, json=payload)
            if 200 <= resp.status_code < 300:
                log.info("Teams notification sent successfully (status %s).", resp.status_code)
                return True
            log.warning("Teams webhook returned %s: %s", resp.status_code, resp.text[:200])
            return False
    except Exception as e:
        log.error("Failed to send Teams notification: %s", e)
        return False
