#Requires -Version 7.0
<#
.SYNOPSIS
    Cria o App Registration "IAM-Scanner" e configura todas as permissões necessárias.

.DESCRIPTION
    - Cria o App Registration e Service Principal no Entra ID
    - Gera um client secret com validade de 2 anos
    - Adiciona permissões de aplicativo no Microsoft Graph:
        · Directory.Read.All
        · RoleManagement.Read.Directory
    - Concede admin consent nas permissões Graph
    - Atribui a role "Reader" em cada subscription listada
    - Exibe os valores prontos para colar no arquivo .env

.NOTES
    Pré-requisito: az login com uma conta que tenha:
        · Global Administrator (para admin consent no Entra ID)
        · Owner (para criar role assignments nas subscriptions)

    Execução:
        .\setup-sp.ps1

    Para sobrescrever um App Registration existente com o mesmo nome, use:
        .\setup-sp.ps1 -Force
#>
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# -------------------------------------------------------------------------- #
# Configuração                                                                #
# -------------------------------------------------------------------------- #

$AppName  = "IAM-Scanner"
$TenantId = "<seu-tenant-id-aqui>"   # ex: 00000000-0000-0000-0000-000000000000

$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Permissões de aplicativo (Application, não Delegated)
$GraphPermissions = @(
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role"   # Directory.Read.All
    "483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role"   # RoleManagement.Read.Directory
)

# Liste aqui os IDs das subscriptions que o scanner deve monitorar.
$Subscriptions = @(
    "<subscription-id-1>"   # ex: Produção
    "<subscription-id-2>"   # ex: Homologação
)

# -------------------------------------------------------------------------- #
# Helpers                                                                     #
# -------------------------------------------------------------------------- #

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "    AVISO: $Message" -ForegroundColor Yellow
}

function Invoke-Az {
    param([string[]]$Arguments)
    $output = az @Arguments 2>&1
    $stdout = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    $stderr = ($output | Where-Object { $_ -is  [System.Management.Automation.ErrorRecord] }) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "az $($Arguments[0..1] -join ' ') falhou: $stderr"
    }
    return $stdout.Trim()
}

# -------------------------------------------------------------------------- #
# Verificar login                                                             #
# -------------------------------------------------------------------------- #

Write-Step "Verificando autenticação no Azure"
$accountJson = Invoke-Az @("account", "show", "--output", "json")
$account = $accountJson | ConvertFrom-Json
Write-Ok "Autenticado como: $($account.user.name)"
Write-Ok "Tenant: $($account.tenantId)"

if ($account.tenantId -ne $TenantId) {
    throw "Tenant incorreto. Esperado: $TenantId | Atual: $($account.tenantId). Execute: az login --tenant $TenantId"
}

# -------------------------------------------------------------------------- #
# App Registration                                                            #
# -------------------------------------------------------------------------- #

Write-Step "Verificando App Registration existente: $AppName"
$existingJson = az ad app list --display-name $AppName --query "[0].appId" -o tsv 2>$null
$AppId = if ($existingJson) { $existingJson.Trim() } else { $null }

if ($AppId -and -not $Force) {
    Write-Warn "App Registration '$AppName' já existe (App ID: $AppId)."
    Write-Warn "Use -Force para recriar o secret. Continuando com o existente..."
} else {
    if ($AppId -and $Force) {
        Write-Warn "Removendo App Registration existente..."
        Invoke-Az @("ad", "app", "delete", "--id", $AppId)
    }

    Write-Step "Criando App Registration: $AppName"
    $AppId = Invoke-Az @("ad", "app", "create",
        "--display-name", $AppName,
        "--sign-in-audience", "AzureADMyOrg",
        "--query", "appId",
        "--output", "tsv")
    Write-Ok "App ID: $AppId"
}

# -------------------------------------------------------------------------- #
# Service Principal                                                           #
# -------------------------------------------------------------------------- #

Write-Step "Verificando Service Principal"
$SpObjId = $null
$spRaw = az ad sp show --id $AppId --query id -o tsv 2>$null
if ($spRaw) { $SpObjId = $spRaw.Trim() }

if (-not $SpObjId) {
    Write-Host "    Criando Service Principal..." -ForegroundColor Gray
    $SpObjId = Invoke-Az @("ad", "sp", "create", "--id", $AppId, "--query", "id", "--output", "tsv")
}
Write-Ok "SP Object ID: $SpObjId"

# -------------------------------------------------------------------------- #
# Client Secret                                                               #
# -------------------------------------------------------------------------- #

Write-Step "Gerando client secret (validade: 2 anos)"
$Secret = Invoke-Az @("ad", "app", "credential", "reset",
    "--id",     $AppId,
    "--years",  "2",
    "--query",  "password",
    "--output", "tsv")
Write-Ok "Secret gerado com sucesso."
Write-Warn "Copie o secret agora — ele não será exibido novamente pelo Azure!"

# -------------------------------------------------------------------------- #
# Permissões Microsoft Graph                                                  #
# -------------------------------------------------------------------------- #

Write-Step "Adicionando permissões Microsoft Graph (Application)"
foreach ($perm in $GraphPermissions) {
    $permId = $perm.Split("=")[0]
    Write-Host "    Adicionando: $perm" -ForegroundColor Gray
    Invoke-Az @("ad", "app", "permission", "add",
        "--id",              $AppId,
        "--api",             $GraphAppId,
        "--api-permissions", $perm) | Out-Null
}
Write-Ok "Permissões adicionadas."

Write-Step "Concedendo admin consent nas permissões Graph"
Write-Host "    Aguardando propagação do Service Principal (15s)..." -ForegroundColor Gray
Start-Sleep -Seconds 15

# NOTA: "az ad app permission admin-consent" usa a API legada do Azure AD Graph,
# que retorna "Consent validation failed" de forma intermitente mesmo com permissões
# corretas. Para contornar, o consentimento é concedido diretamente via Microsoft Graph
# API (appRoleAssignments), que é o mecanismo real por trás do admin consent para
# permissões de aplicativo (Role).
$GraphSpId = (Invoke-Az @("ad", "sp", "show", "--id", $GraphAppId, "--query", "id", "--output", "tsv")).Trim()

$existingAssignmentsJson = Invoke-Az @("rest",
    "--method", "GET",
    "--uri",    "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjId/appRoleAssignments")
$existingAppRoleIds = ($existingAssignmentsJson | ConvertFrom-Json).value.appRoleId

foreach ($perm in $GraphPermissions) {
    $appRoleId = $perm.Split("=")[0]

    if ($existingAppRoleIds -contains $appRoleId) {
        Write-Host "    Já concedido: $appRoleId" -ForegroundColor DarkGray
        continue
    }

    Write-Host "    Concedendo: $appRoleId" -ForegroundColor Gray
    $body = @{
        principalId = $SpObjId
        resourceId  = $GraphSpId
        appRoleId   = $appRoleId
    } | ConvertTo-Json -Compress

    # O JSON é gravado em arquivo e referenciado com "@arquivo" porque passar o payload
    # direto como argumento quebra no Windows: az.cmd (batch) reprocessa as aspas do
    # array de argumentos e corrompe o JSON antes de chegar na API.
    $bodyFile = Join-Path $env:TEMP "iam-scanner-approle-$appRoleId.json"
    $body | Set-Content -Path $bodyFile -Encoding utf8NoBOM

    try {
        Invoke-Az @("rest",
            "--method", "POST",
            "--uri",    "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjId/appRoleAssignments",
            "--body",   "@$bodyFile",
            "--headers", "Content-Type=application/json") | Out-Null
    } finally {
        Remove-Item -Path $bodyFile -ErrorAction SilentlyContinue
    }
}
Write-Ok "Admin consent concedido."

# -------------------------------------------------------------------------- #
# Role Assignments (Reader em cada subscription)                              #
# -------------------------------------------------------------------------- #

Write-Step "Atribuindo role 'Reader' nas subscriptions"
$assignErrors = @()

foreach ($SubId in $Subscriptions) {
    $scope = "/subscriptions/$SubId"
    Write-Host "    $scope" -ForegroundColor Gray

    # Verifica se o assignment já existe
    $existing = az role assignment list `
        --assignee $AppId `
        --role     "Reader" `
        --scope    $scope `
        --query    "[0].id" `
        --output   tsv 2>$null

    if ($existing) {
        Write-Host "      (já existe — ignorado)" -ForegroundColor DarkGray
        continue
    }

    try {
        Invoke-Az @("role", "assignment", "create",
            "--assignee", $AppId,
            "--role",     "Reader",
            "--scope",    $scope,
            "--output",   "none") | Out-Null
        Write-Host "      OK" -ForegroundColor Green
    } catch {
        $assignErrors += $scope
        Write-Warn "Falha em $scope — verifique se você tem permissão de Owner."
    }
}

if ($assignErrors.Count -gt 0) {
    Write-Host "`n    Subscriptions com erro (atribua manualmente):" -ForegroundColor Yellow
    $assignErrors | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
}

# -------------------------------------------------------------------------- #
# Output — valores para o .env                                               #
# -------------------------------------------------------------------------- #

$SubsCsv = $Subscriptions -join ","

$envContent = @"
AZURE_TENANT_ID=$TenantId
AZURE_CLIENT_ID=$AppId
AZURE_CLIENT_SECRET=$Secret
SUBSCRIPTION_IDS=$SubsCsv
SCAN_INTERVAL_MINUTES=60
TEAMS_WEBHOOK_URL=
TEAMS_DASHBOARD_URL=
TEAMS_HEARTBEAT=false
NOTIFY_LEVELS=CRITICO,ALTO
"@

Write-Host "`n"
Write-Host ("=" * 62) -ForegroundColor Green
Write-Host "  Valores para o arquivo .env:" -ForegroundColor Green
Write-Host ("=" * 62) -ForegroundColor Green
Write-Host $envContent
Write-Host ("=" * 62) -ForegroundColor Green

# Pergunta se quer salvar direto no .env
$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envPath)) {
    $save = Read-Host "`nDeseja salvar em .env agora? (s/N)"
    if ($save -match "^[sS]$") {
        $envContent | Set-Content -Path $envPath -Encoding UTF8
        Write-Ok ".env criado em: $envPath"
        Write-Warn "NUNCA versione o .env com credenciais reais!"
    }
} else {
    Write-Warn ".env já existe em $envPath — copie os valores manualmente para não sobrescrever."
}

Write-Host "`n==> Configuração concluída!" -ForegroundColor Green
Write-Host "    App Registration : $AppName" -ForegroundColor White
Write-Host "    App ID           : $AppId" -ForegroundColor White
Write-Host "    SP Object ID     : $SpObjId" -ForegroundColor White