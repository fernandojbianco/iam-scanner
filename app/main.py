"""
IAM Scanner — servidor web + scheduler de coleta periódica.
"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from .collector import IAMCollector, ScanResult
from .differ import diff as iam_diff
from .differ import diff_groups
from .notifier import send_changes, send_summary

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Config                                                               #
# ------------------------------------------------------------------ #

TENANT_ID       = os.environ["AZURE_TENANT_ID"]
CLIENT_ID       = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET   = os.environ["AZURE_CLIENT_SECRET"]
SCAN_INTERVAL      = int(os.getenv("SCAN_INTERVAL_MINUTES", "60"))
SUB_IDS_RAW        = os.getenv("SUBSCRIPTION_IDS", "")
SUBSCRIPTION_IDS: Optional[list[str]] = (
    [s.strip() for s in SUB_IDS_RAW.split(",") if s.strip()] or None
)
TEAMS_WEBHOOK_URL  = os.getenv("TEAMS_WEBHOOK_URL", "")
TEAMS_DASHBOARD_URL = os.getenv("TEAMS_DASHBOARD_URL", "")
TEAMS_HEARTBEAT    = os.getenv("TEAMS_HEARTBEAT", "false").lower() == "true"
NOTIFY_LEVELS_RAW  = os.getenv("NOTIFY_LEVELS", "CRITICO,ALTO")
NOTIFY_LEVELS      = {lvl.strip() for lvl in NOTIFY_LEVELS_RAW.split(",") if lvl.strip()}
WATCHED_GROUPS_RAW = os.getenv("WATCHED_GROUPS", "")
WATCHED_GROUPS: Optional[list[str]] = (
    [g.strip() for g in WATCHED_GROUPS_RAW.split(",") if g.strip()] or None
)

# ------------------------------------------------------------------ #
# State (in-memory, single instance)                                   #
# ------------------------------------------------------------------ #

_state: dict = {
    "result": None,          # ScanResult atual
    "previous_result": None, # ScanResult anterior (para diff)
    "last_scan": None,       # ISO timestamp
    "next_scan": None,
    "scanning": False,
    "error": None,
}


def do_scan():
    if _state["scanning"]:
        log.warning("Scan already in progress, skipping.")
        return
    _state["scanning"] = True
    _state["error"] = None
    log.info("Starting IAM scan ...")
    try:
        collector = IAMCollector(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        result = collector.run(SUBSCRIPTION_IDS, WATCHED_GROUPS)

        previous: Optional[ScanResult] = _state["result"]
        _state["previous_result"] = previous
        _state["result"] = result
        _state["last_scan"] = result.collected_at

        log.info(
            "Scan complete: %d Azure + %d Entra assignments collected.",
            result.summary["total_azure_assignments"],
            result.summary["total_entra_assignments"],
        )
        if result.errors:
            log.warning("Partial errors: %s", result.errors)

        # ---- Notificações Teams ----
        if TEAMS_WEBHOOK_URL:
            curr_dict = {
                "azure_assignments": result.azure_assignments,
                "entra_assignments": result.entra_assignments,
            }
            if previous is not None:
                prev_dict = {
                    "azure_assignments": previous.azure_assignments,
                    "entra_assignments": previous.entra_assignments,
                }
                changes = iam_diff(prev_dict, curr_dict, notify_levels=NOTIFY_LEVELS)
                if WATCHED_GROUPS:
                    group_changes = diff_groups(previous.group_memberships, result.group_memberships, result.group_names)
                    if group_changes:
                        log.info("Detected %d watched group membership change(s).", len(group_changes))
                    changes = group_changes + changes
                if changes:
                    log.info("Detected %d IAM change(s) — sending Teams notification.", len(changes))
                    send_changes(TEAMS_WEBHOOK_URL, changes, result.collected_at, TEAMS_DASHBOARD_URL)
                elif TEAMS_HEARTBEAT:
                    log.info("No changes detected — sending Teams heartbeat summary.")
                    send_summary(TEAMS_WEBHOOK_URL, result.summary, result.collected_at, TEAMS_DASHBOARD_URL)
            else:
                log.info("First scan complete — no previous state to diff.")
                if TEAMS_HEARTBEAT:
                    send_summary(TEAMS_WEBHOOK_URL, result.summary, result.collected_at, TEAMS_DASHBOARD_URL)

    except Exception as e:
        log.error("Scan failed: %s", e, exc_info=True)
        _state["error"] = str(e)
    finally:
        _state["scanning"] = False


# ------------------------------------------------------------------ #
# Lifecycle + scheduler                                                #
# ------------------------------------------------------------------ #

scheduler = BackgroundScheduler(timezone="UTC")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting IAM Scanner (interval=%dm, subs=%s)", SCAN_INTERVAL, SUBSCRIPTION_IDS or "auto-discover")
    scheduler.add_job(do_scan, "interval", minutes=SCAN_INTERVAL, id="iam_scan", replace_existing=True)
    scheduler.start()
    # Run first scan immediately in background thread
    import threading
    threading.Thread(target=do_scan, daemon=True).start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="IAM Scanner", lifespan=lifespan)

# ------------------------------------------------------------------ #
# API                                                                  #
# ------------------------------------------------------------------ #

@app.get("/api/status")
def status():
    job = scheduler.get_job("iam_scan")
    return {
        "scanning":  _state["scanning"],
        "last_scan": _state["last_scan"],
        "next_scan": job.next_run_time.isoformat() if job and job.next_run_time else None,
        "error":     _state["error"],
        "interval_minutes": SCAN_INTERVAL,
    }


@app.get("/api/data")
def get_data():
    if _state["result"] is None:
        if _state["scanning"]:
            raise HTTPException(status_code=202, detail="Scan em andamento, aguarde.")
        if _state["error"]:
            raise HTTPException(status_code=500, detail=_state["error"])
        raise HTTPException(status_code=503, detail="Nenhum dado disponível ainda.")
    r: ScanResult = _state["result"]
    return {
        "collected_at":        r.collected_at,
        "summary":             r.summary,
        "subscriptions":       r.subscriptions,
        "azure_assignments":   r.azure_assignments,
        "entra_assignments":   r.entra_assignments,
        "errors":              r.errors,
        "watched_groups": [
            {"id": gid, "name": r.group_names.get(gid, gid), "members": r.group_memberships.get(gid, [])}
            for gid in (WATCHED_GROUPS or [])
        ],
    }


@app.post("/api/refresh")
def trigger_refresh():
    if _state["scanning"]:
        raise HTTPException(status_code=409, detail="Scan já em andamento.")
    import threading
    threading.Thread(target=do_scan, daemon=True).start()
    return {"message": "Scan iniciado."}


@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------------ #
# Dashboard                                                            #
# ------------------------------------------------------------------ #

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IAM Scanner — Paraná Banco</title>
<style>
:root{
  --bg:#EDF1F7;--surface:#FFF;--s2:#F5F7FA;--border:#D3DCE8;
  --text:#18263A;--t2:#4B5D72;--t3:#8A9BB0;
  --az:#0078D4;--azl:#E6F2FB;
  --purple:#5C2D91;--purplel:#EDE7F6;
  --rc:#B91C1C;--rc-bg:#FEF2F2;
  --rh:#B45309;--rh-bg:#FFFBEB;
  --rm:#6D28D9;--rm-bg:#F5F3FF;
  --rl:#166534;--rl-bg:#F0FDF4;
  --ri:#1D4ED8;--ri-bg:#EFF6FF;
  --rad:6px;
  --mono:"Cascadia Code","Consolas","SF Mono",ui-monospace,monospace;
  --ui:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ui);background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}

.hdr{background:linear-gradient(135deg,#0078D4 0%,#5C2D91 100%);color:#fff;padding:13px 28px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:60;box-shadow:0 1px 6px rgba(0,0,0,.25)}
.hdr-ico{width:32px;height:32px;background:rgba(255,255,255,.15);border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.hdr-ico svg{width:18px;height:18px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.hdr-title{font-size:15px;font-weight:700;letter-spacing:-.01em}
.hdr-sub{font-size:11px;opacity:.72;font-family:var(--mono);margin-top:1px}
.hdr-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.chip{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.22);border-radius:4px;padding:3px 10px;font-size:11px;font-family:var(--mono)}
.chip.scanning{background:rgba(251,191,36,.25);border-color:rgba(251,191,36,.5);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.btn{display:flex;align-items:center;gap:6px;padding:6px 13px;border:none;border-radius:4px;font-size:12px;font-weight:600;font-family:var(--ui);cursor:pointer;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn:disabled{opacity:.5;pointer-events:none}
.btn-white{background:#fff;color:var(--az)}
.btn-csv{background:#fff;color:var(--purple)}
.btn svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

.ctr{max-width:1380px;margin:0 auto;padding:20px 24px}

.section-title{font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--t2);margin-bottom:10px;margin-top:20px}
.section-title:first-child{margin-top:0}

.gstats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px}
@media(max-width:900px){.gstats{grid-template-columns:repeat(3,1fr)}}
.gs{background:var(--surface);border:1px solid var(--border);border-radius:var(--rad);padding:14px 18px}
.gs-lbl{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--t2)}
.gs-val{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1;margin-top:3px}
.gs-hint{font-size:11px;color:var(--t3);margin-top:4px}
.gs.danger .gs-val{color:var(--rc)}
.gs.warn .gs-val{color:var(--rh)}
.gs.ok .gs-val{color:var(--rl)}

.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--rad);overflow:hidden;margin-bottom:20px}
.panel-hdr{display:flex;align-items:center;gap:10px;padding:11px 16px;border-bottom:1px solid var(--border);background:var(--s2)}
.panel-title{font-size:13px;font-weight:600;flex:1}
.panel-count{font-size:11px;color:var(--t3);font-variant-numeric:tabular-nums}

.toolbar{display:flex;align-items:center;gap:8px;padding:9px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.sw{position:relative;flex:1;min-width:180px;max-width:340px}
.sw svg{position:absolute;left:9px;top:50%;transform:translateY(-50%);width:13px;height:13px;fill:none;stroke:var(--t3);stroke-width:2;stroke-linecap:round;stroke-linejoin:round;pointer-events:none}
.srch{width:100%;padding:6px 10px 6px 28px;border:1px solid var(--border);border-radius:var(--rad);font-size:12.5px;font-family:var(--ui);color:var(--text);background:var(--surface);outline:none}
.srch:focus{border-color:var(--az);box-shadow:0 0 0 2px var(--azl)}
.fsel{padding:6px 9px;border:1px solid var(--border);border-radius:var(--rad);font-size:12.5px;font-family:var(--ui);color:var(--text);background:var(--surface);outline:none;cursor:pointer}
.rcount{margin-left:auto;font-size:11px;color:var(--t3);font-variant-numeric:tabular-nums}

.tw{overflow-x:auto;max-height:420px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead{position:sticky;top:0;z-index:1}
th{text-align:left;padding:7px 14px;font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--t2);background:var(--s2);border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:7px 14px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr.dr:hover td{background:#F8FAFD}
.mono{font-family:var(--mono);font-size:11.5px;word-break:break-all}

.pill{display:inline-flex;align-items:center;border-radius:3px;padding:2px 7px;font-size:10.5px;font-weight:600;white-space:nowrap}
.pc{background:var(--rc-bg);color:var(--rc)}
.ph{background:var(--rh-bg);color:var(--rh)}
.pm{background:var(--rm-bg);color:var(--rm)}
.pl{background:var(--rl-bg);color:var(--rl)}
.pi{background:var(--ri-bg);color:var(--ri)}
.pt-u{background:#F0FDF4;color:#166534;font-size:9.5px;padding:1px 5px;border-radius:2px;font-weight:700}
.pt-g{background:#EFF6FF;color:#1D4ED8;font-size:9.5px;padding:1px 5px;border-radius:2px;font-weight:700}
.pt-s{background:#F5F3FF;color:#6D28D9;font-size:9.5px;padding:1px 5px;border-radius:2px;font-weight:700}

.sb{display:inline-block;font-size:9px;font-weight:800;padding:1px 4px;border-radius:2px;letter-spacing:.05em;text-transform:uppercase;margin-right:3px}
.sb-sub{background:var(--rc-bg);border:1px solid #FECACA;color:var(--rc)}
.sb-rg{background:var(--ri-bg);border:1px solid #BFDBFE;color:var(--ri)}
.sb-mg{background:var(--rh-bg);border:1px solid #FDE68A;color:var(--rh)}
.sb-res{background:#F3F4F6;border:1px solid #D1D5DB;color:#374151}

.empty{text-align:center;padding:32px;color:var(--t3);font-size:13px}
.loading{text-align:center;padding:60px;color:var(--t3)}
.loading svg{animation:spin 1s linear infinite;margin-bottom:12px}
@keyframes spin{to{transform:rotate(360deg)}}

.sub-tabs{display:flex;border-bottom:1px solid var(--border);padding:0 14px;gap:2px;background:var(--s2);overflow-x:auto;scrollbar-width:thin}
.stab{padding:9px 13px;font-size:12.5px;font-weight:500;color:var(--t2);cursor:pointer;border:none;border-bottom:2px solid transparent;margin-bottom:-1px;background:none;font-family:var(--ui);display:flex;align-items:center;gap:5px;transition:color .12s;flex-shrink:0;white-space:nowrap}
.stab:hover{color:var(--text)}
.stab.active{color:var(--az);border-bottom-color:var(--az)}
.stab-cnt{background:var(--bg);border-radius:9px;padding:1px 6px;font-size:10.5px;font-variant-numeric:tabular-nums}
.stab.active .stab-cnt{background:var(--azl);color:var(--az)}
.tab-panel{display:none}
.tab-panel.active{display:block}

.err-banner{background:var(--rc-bg);border:1px solid #FECACA;border-left:3px solid var(--rc);border-radius:var(--rad);padding:10px 14px;margin-bottom:14px;font-size:12px;color:#7F1D1D}
.err-banner code{font-family:var(--mono);font-size:11px}

.footer{text-align:center;padding:18px;font-size:11px;color:var(--t3)}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-ico">
    <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
  </div>
  <div>
    <div class="hdr-title">IAM Scanner</div>
    <div class="hdr-sub" id="hdr-sub">Paraná Banco S/A — Auditoria contínua de acessos</div>
  </div>
  <div class="hdr-right">
    <span class="chip" id="chip-status">Carregando…</span>
    <span class="chip" id="chip-next" style="display:none"></span>
    <button class="btn btn-white" id="btn-refresh" onclick="triggerRefresh()">
      <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
      Atualizar agora
    </button>
    <button class="btn btn-csv" onclick="exportCSV('azure')">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      CSV
    </button>
  </div>
</div>

<div class="ctr">
  <div id="loading" class="loading">
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--t3)" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-dashoffset="12"/></svg>
    <p>Coletando dados do ambiente Azure…</p>
    <p style="font-size:11px;margin-top:6px;color:var(--t3)">O primeiro scan pode levar alguns minutos.</p>
  </div>

  <div id="content" style="display:none">
    <div id="err-banner" class="err-banner" style="display:none"></div>

    <div class="gstats" id="gstats"></div>

    <!-- AZURE RBAC -->
    <div class="section-title">Azure RBAC — Role Assignments</div>
    <div class="panel">
      <div class="sub-tabs" id="azure-tabs"></div>
      <div id="azure-panels"></div>
    </div>

    <!-- ENTRA ID -->
    <div class="section-title">Entra ID &amp; Microsoft 365 — Directory Roles</div>
    <div class="panel">
      <div class="panel-hdr">
        <span class="panel-title">Atribuições de roles do diretório, incluindo M365 (Graph API)</span>
        <span class="panel-count" id="entra-count"></span>
        <button class="btn btn-csv" onclick="exportCSV('entra')" style="margin-left:8px">
          <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          CSV Entra
        </button>
      </div>
      <div class="toolbar">
        <div class="sw"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input class="srch" id="srch-entra" placeholder="Filtrar…"></div>
        <select class="fsel" id="fsel-entra"><option value="">Todos os níveis</option><option value="CRITICO">Crítico</option><option value="ALTO">Alto</option><option value="MEDIO">Médio</option><option value="LEITURA">Leitura</option></select>
        <select class="fsel" id="ftype-entra"><option value="">Todos os tipos</option><option value="user">Usuário</option><option value="servicePrincipal">Service Principal</option><option value="group">Grupo</option></select>
        <select class="fsel" id="fwl-entra"><option value="">Todas as origens</option><option value="Entra ID">Entra ID</option><option value="M365">Microsoft 365</option></select>
        <span class="rcount" id="rc-entra"></span>
      </div>
      <div class="tw"><table><thead><tr><th>Principal</th><th>Tipo</th><th>Role</th><th>Origem</th><th>Nível</th><th>Escopo</th></tr></thead><tbody id="tbl-entra"></tbody></table></div>
      <div class="empty" id="empty-entra" style="display:none">Nenhum resultado.</div>
    </div>

    <!-- GRUPOS MONITORADOS -->
    <div class="section-title" id="groups-section-title" style="display:none">Grupos Monitorados</div>
    <div class="panel" id="groups-panel" style="display:none">
      <div class="sub-tabs" id="groups-tabs"></div>
      <div id="groups-panels"></div>
    </div>
  </div>
</div>
<div class="footer" id="footer">IAM Scanner — Paraná Banco S/A</div>

<script>
const TC = {CRITICO:"pc",ALTO:"ph",MEDIO:"pm",LEITURA:"pl",INFO:"pi"};
let _data = null;

function esc(v){const s=String(v??"");return s.includes(",")||s.includes('"')||s.includes("\\n")?'"'+s.replace(/"/g,'""')+'"':s;}

function scopeBadge(s){
  if(!s||s==="(subscription)"||/subscription/i.test(s)) return '<span class="sb sb-sub">SUB</span>';
  if(/management.group/i.test(s)||/MG/i.test(s)) return '<span class="sb sb-mg">MG</span>';
  if(/resourceGroups\/[^/]+$/.test(s)) return '<span class="sb sb-rg">RG</span>';
  if(/resourceGroups\//.test(s)) return '<span class="sb sb-res">RES</span>';
  return '';
}
function typePill(t){
  if(t==="User"||t==="user") return '<span class="pt-u">USR</span>';
  if(t==="Group"||t==="group") return '<span class="pt-g">GRP</span>';
  return '<span class="pt-s">SP</span>';
}

// ---- fetch loop ----
async function fetchStatus(){
  try{
    const r=await fetch("/api/status");
    const s=await r.json();
    const chip=document.getElementById("chip-status");
    if(s.scanning){chip.textContent="Coletando…";chip.className="chip scanning";}
    else if(s.error){chip.textContent="Erro";chip.className="chip";}
    else{chip.textContent="Ativo";chip.className="chip";}
    const nc=document.getElementById("chip-next");
    if(s.next_scan){nc.style.display="";nc.textContent="Próx: "+new Date(s.next_scan).toLocaleTimeString("pt-BR",{hour:"2-digit",minute:"2-digit"});}
    document.getElementById("btn-refresh").disabled=s.scanning;
  }catch{}
}

async function fetchData(){
  try{
    const r=await fetch("/api/data");
    if(r.status===202||r.status===503){setTimeout(fetchData,4000);return;}
    if(!r.ok){const e=await r.json();console.error(e);setTimeout(fetchData,8000);return;}
    _data=await r.json();
    render(_data);
  }catch(e){console.error(e);setTimeout(fetchData,8000);}
}

// ---- render ----
function render(data){
  document.getElementById("loading").style.display="none";
  document.getElementById("content").style.display="";

  // errors
  if(data.errors&&data.errors.length){
    const b=document.getElementById("err-banner");
    b.style.display="";
    b.innerHTML="<strong>Erros parciais:</strong> "+data.errors.map(e=>`<code>${e}</code>`).join(" · ");
  }

  // stats
  const s=data.summary;
  document.getElementById("gstats").innerHTML=`
    <div class="gs"><div class="gs-lbl">Subscriptions</div><div class="gs-val">${s.total_subscriptions}</div><div class="gs-hint">Descobertas automaticamente</div></div>
    <div class="gs"><div class="gs-lbl">Azure RBAC</div><div class="gs-val">${(s.total_azure_assignments||0).toLocaleString("pt-BR")}</div><div class="gs-hint">Atribuições coletadas</div></div>
    <div class="gs danger"><div class="gs-lbl">RBAC Crítico</div><div class="gs-val">${s.critical_azure||0}</div><div class="gs-hint">Owner / UAA</div></div>
    <div class="gs"><div class="gs-lbl">Entra ID</div><div class="gs-val">${(s.total_entra_assignments||0).toLocaleString("pt-BR")}</div><div class="gs-hint">Roles do diretório</div></div>
    <div class="gs danger"><div class="gs-lbl">Entra Crítico</div><div class="gs-val">${s.critical_entra||0}</div><div class="gs-hint">Global Admin / PRA</div></div>
    <div class="gs"><div class="gs-lbl">Microsoft 365</div><div class="gs-val">${(s.total_m365_assignments||0).toLocaleString("pt-BR")}</div><div class="gs-hint">Exchange / SharePoint / Teams</div></div>
    <div class="gs danger"><div class="gs-lbl">M365 Crítico</div><div class="gs-val">${s.critical_m365||0}</div><div class="gs-hint">Admins de workload M365</div></div>
    <div class="gs ok"><div class="gs-lbl">Última coleta</div><div class="gs-val" style="font-size:14px;padding-top:4px">${new Date(data.collected_at).toLocaleTimeString("pt-BR",{hour:"2-digit",minute:"2-digit"})}</div><div class="gs-hint">${new Date(data.collected_at).toLocaleDateString("pt-BR")}</div></div>
  `;

  // Azure RBAC tabs por subscription
  buildAzureTabs(data.subscriptions, data.azure_assignments);

  // Entra ID table
  buildEntraTable(data.entra_assignments);

  // Grupos monitorados
  buildGroupsTabs(data.watched_groups);

  // footer
  document.getElementById("footer").textContent=
    `IAM Scanner — Atualizado em ${new Date(data.collected_at).toLocaleString("pt-BR")} · Próximo scan em ${document.getElementById("chip-next").textContent.replace("Próx: ","")||"—"}`;
}

function buildAzureTabs(subs, allRows){
  const tabsEl=document.getElementById("azure-tabs");
  const panelsEl=document.getElementById("azure-panels");
  tabsEl.innerHTML=""; panelsEl.innerHTML="";

  // "Todos" tab
  const allSub = {id:"__all__", name:"Todos"};
  const subList = [allSub, ...subs];

  subList.forEach((sub,i)=>{
    const rows = sub.id==="__all__" ? allRows : allRows.filter(r=>r.subscription_id===sub.id);
    const btn=document.createElement("button");
    btn.className="stab"+(i===0?" active":"");
    btn.dataset.panel="az-"+sub.id;
    btn.innerHTML=`${sub.name} <span class="stab-cnt">${rows.length}</span>`;
    tabsEl.appendChild(btn);

    const panel=document.createElement("div");
    panel.className="tab-panel"+(i===0?" active":"");
    panel.id="az-"+sub.id;
    panel.innerHTML=`
      <div class="toolbar">
        <div class="sw"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input class="srch" data-tbl="az-tbl-${sub.id}" placeholder="Filtrar…"></div>
        <select class="fsel" data-tbl="az-tbl-${sub.id}"><option value="">Todos</option><option value="CRITICO">Crítico</option><option value="ALTO">Alto</option><option value="MEDIO">Médio</option><option value="LEITURA">Leitura</option></select>
        <select class="fsel fsel-type" data-tbl="az-tbl-${sub.id}"><option value="">Todos tipos</option><option value="User">Usuário</option><option value="Group">Grupo</option><option value="ServicePrincipal">SP</option></select>
        <span class="rcount" id="rc-az-${sub.id}"></span>
      </div>
      <div class="tw"><table><thead><tr><th>Principal</th><th>Tipo</th><th>Role</th><th>Nível</th><th>Tipo Escopo</th><th>Escopo</th>${sub.id==="__all__"?'<th>Subscription</th>':''}</tr></thead><tbody id="az-tbl-${sub.id}"></tbody></table></div>
      <div class="empty" id="az-empty-${sub.id}" style="display:none">Nenhum resultado.</div>
    `;
    panelsEl.appendChild(panel);
    renderAzureTbl(sub.id, rows, sub.id==="__all__");
  });

  // tab click
  tabsEl.addEventListener("click",e=>{
    const btn=e.target.closest(".stab"); if(!btn) return;
    tabsEl.querySelectorAll(".stab").forEach(t=>t.classList.remove("active"));
    panelsEl.querySelectorAll(".tab-panel").forEach(p=>p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.panel).classList.add("active");
  });
}

function renderAzureTbl(subId, rows, showSub){
  const tbody=document.getElementById("az-tbl-"+subId);
  const rcEl=document.getElementById("rc-az-"+subId);
  const empEl=document.getElementById("az-empty-"+subId);
  const panel=tbody.closest(".tab-panel");
  const srch=panel.querySelector(`input[data-tbl="az-tbl-${subId}"]`);
  const fsel=panel.querySelector(`select[data-tbl="az-tbl-${subId}"]`);
  const ftype=panel.querySelector(`select.fsel-type[data-tbl="az-tbl-${subId}"]`);

  function render(){
    const q=(srch.value||"").toLowerCase(), pf=fsel.value, pt=ftype.value;
    let n=0, prevP=null;
    tbody.innerHTML="";
    rows.forEach(r=>{
      if(pf&&r.risk_level!==pf) return;
      if(pt&&r.principal_type!==pt) return;
      if(q&&!(r.principal+r.role+r.scope+r.subscription).toLowerCase().includes(q)) return;
      n++;
      const tr=document.createElement("tr"); tr.className="dr";
      const td1=document.createElement("td"); if(r.principal!==prevP){td1.innerHTML=`<span class="mono">${r.principal}</span>`;prevP=r.principal;}
      const td2=document.createElement("td"); td2.innerHTML=typePill(r.principal_type);
      const td3=document.createElement("td"); td3.innerHTML=`<span class="mono" style="font-size:11px">${r.role}</span>`;
      const td4=document.createElement("td"); td4.innerHTML=`<span class="pill ${TC[r.risk_level]||'pi'}">${r.risk_level}</span>`;
      const td5=document.createElement("td"); td5.innerHTML=`<span style="font-size:11px;color:var(--t2)">${r.scope_type}</span>`;
      const td6=document.createElement("td"); td6.innerHTML=`<span class="mono" style="font-size:10.5px">${scopeBadge(r.scope)}${r.scope}</span>`;
      tr.append(td1,td2,td3,td4,td5,td6);
      if(showSub){const td7=document.createElement("td");td7.innerHTML=`<span style="font-size:11px;color:var(--t2)">${r.subscription}</span>`;tr.appendChild(td7);}
      tbody.appendChild(tr);
    });
    rcEl.textContent=n+" atribuições";
    empEl.style.display=n===0?"":"none";
  }
  srch.addEventListener("input",render);
  fsel.addEventListener("change",render);
  ftype.addEventListener("change",render);
  render();
}

function workloadBadge(w){
  return w==="M365" ? '<span class="pt-s">M365</span>' : '<span class="pt-g">ENTRA</span>';
}

function buildEntraTable(rows){
  const tbody=document.getElementById("tbl-entra");
  const srch=document.getElementById("srch-entra");
  const fsel=document.getElementById("fsel-entra");
  const ftype=document.getElementById("ftype-entra");
  const fwl=document.getElementById("fwl-entra");
  const rc=document.getElementById("rc-entra");
  const emp=document.getElementById("empty-entra");
  document.getElementById("entra-count").textContent=rows.length+" atribuições";

  function render(){
    const q=(srch.value||"").toLowerCase(), pf=fsel.value, pt=ftype.value, wl=fwl.value;
    let n=0, prevP=null;
    tbody.innerHTML="";
    rows.forEach(r=>{
      if(pf&&r.risk_level!==pf) return;
      if(pt&&r.principal_type!==pt) return;
      if(wl&&(r.workload||"Entra ID")!==wl) return;
      if(q&&!(r.principal+r.role).toLowerCase().includes(q)) return;
      n++;
      const tr=document.createElement("tr"); tr.className="dr";
      const td1=document.createElement("td"); if(r.principal!==prevP){td1.innerHTML=`<span class="mono">${r.principal}</span>`;prevP=r.principal;}
      const td2=document.createElement("td"); td2.innerHTML=typePill(r.principal_type);
      const td3=document.createElement("td"); td3.innerHTML=`<span class="mono" style="font-size:11px">${r.role}</span>`;
      const td4=document.createElement("td"); td4.innerHTML=workloadBadge(r.workload||"Entra ID");
      const td5=document.createElement("td"); td5.innerHTML=`<span class="pill ${TC[r.risk_level]||'pi'}">${r.risk_level}</span>`;
      const td6=document.createElement("td"); td6.innerHTML=`<span class="mono" style="font-size:10.5px">${r.scope}</span>`;
      tr.append(td1,td2,td3,td4,td5,td6); tbody.appendChild(tr);
    });
    rc.textContent=n+" atribuições";
    emp.style.display=n===0?"":"none";
  }
  srch.addEventListener("input",render);
  fsel.addEventListener("change",render);
  ftype.addEventListener("change",render);
  fwl.addEventListener("change",render);
  render();
}

function buildGroupsTabs(groups){
  const titleEl=document.getElementById("groups-section-title");
  const panelEl=document.getElementById("groups-panel");
  if(!groups||!groups.length){titleEl.style.display="none";panelEl.style.display="none";return;}
  titleEl.style.display="";panelEl.style.display="";

  const tabsEl=document.getElementById("groups-tabs");
  const panelsEl=document.getElementById("groups-panels");
  tabsEl.innerHTML=""; panelsEl.innerHTML="";

  groups.forEach((g,i)=>{
    const btn=document.createElement("button");
    btn.className="stab"+(i===0?" active":"");
    btn.dataset.panel="grp-"+g.id;
    btn.innerHTML=`${g.name} <span class="stab-cnt">${g.members.length}</span>`;
    tabsEl.appendChild(btn);

    const panel=document.createElement("div");
    panel.className="tab-panel"+(i===0?" active":"");
    panel.id="grp-"+g.id;
    panel.innerHTML=`
      <div class="toolbar">
        <div class="sw"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input class="srch" data-tbl="grp-tbl-${g.id}" placeholder="Filtrar…"></div>
        <span class="rcount" id="rc-grp-${g.id}"></span>
      </div>
      <div class="tw"><table><thead><tr><th>Membro</th><th>Tipo</th></tr></thead><tbody id="grp-tbl-${g.id}"></tbody></table></div>
      <div class="empty" id="grp-empty-${g.id}" style="display:none">Nenhum membro.</div>
    `;
    panelsEl.appendChild(panel);
    renderGroupTbl(g.id, g.members);
  });

  tabsEl.addEventListener("click",e=>{
    const btn=e.target.closest(".stab"); if(!btn) return;
    tabsEl.querySelectorAll(".stab").forEach(t=>t.classList.remove("active"));
    panelsEl.querySelectorAll(".tab-panel").forEach(p=>p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.panel).classList.add("active");
  });
}

function renderGroupTbl(gid, members){
  const tbody=document.getElementById("grp-tbl-"+gid);
  const rcEl=document.getElementById("rc-grp-"+gid);
  const empEl=document.getElementById("grp-empty-"+gid);
  const panel=tbody.closest(".tab-panel");
  const srch=panel.querySelector(`input[data-tbl="grp-tbl-${gid}"]`);

  function render(){
    const q=(srch.value||"").toLowerCase();
    let n=0;
    tbody.innerHTML="";
    members.forEach(m=>{
      if(q&&!(m.principal||"").toLowerCase().includes(q)) return;
      n++;
      const tr=document.createElement("tr"); tr.className="dr";
      const td1=document.createElement("td"); td1.innerHTML=`<span class="mono">${m.principal}</span>`;
      const td2=document.createElement("td"); td2.innerHTML=typePill(m.principal_type);
      tr.append(td1,td2); tbody.appendChild(tr);
    });
    rcEl.textContent=n+" membros";
    empEl.style.display=n===0?"":"none";
  }
  srch.addEventListener("input",render);
  render();
}

function exportCSV(type){
  if(!_data) return;
  const rows = type==="entra" ? _data.entra_assignments : _data.azure_assignments;
  const hdrs = type==="entra"
    ? ["Tipo","Principal","Role","Origem","Nivel_Risco","Escopo"]
    : ["Subscription","Subscription_ID","Tipo_Principal","Principal","Role","Nivel_Risco","Tipo_Escopo","Escopo"];
  const keyMap = type==="entra"
    ? {Tipo:"principal_type",Principal:"principal",Role:"role",Origem:"workload",Nivel_Risco:"risk_level",Escopo:"scope"}
    : {Subscription:"subscription",Subscription_ID:"subscription_id",Tipo_Principal:"principal_type",Principal:"principal",Role:"role",Nivel_Risco:"risk_level",Tipo_Escopo:"scope_type",Escopo:"scope"};
  const lines=["\\uFEFF"+hdrs.join(","), ...rows.map(r=>hdrs.map(h=>esc(r[keyMap[h]]??"")).join(","))];
  const fname=type==="entra"?"entra_id_audit.csv":"azure_rbac_audit.csv";
  const a=Object.assign(document.createElement("a"),{href:URL.createObjectURL(new Blob([lines.join("\\r\\n")],{type:"text/csv;charset=utf-8"})),download:fname});
  a.click(); URL.revokeObjectURL(a.href);
}

async function triggerRefresh(){
  document.getElementById("btn-refresh").disabled=true;
  await fetch("/api/refresh",{method:"POST"});
  document.getElementById("chip-status").textContent="Coletando…";
  document.getElementById("chip-status").className="chip scanning";
  setTimeout(()=>{ fetchData(); fetchStatus(); },3000);
}

// poll status every 30s
setInterval(fetchStatus,30000);
// poll for data when scanning
async function pollData(){
  await fetchStatus();
  await fetchData();
  if(_data===null) setTimeout(pollData,4000);
}
pollData();
</script>
</body>
</html>"""
