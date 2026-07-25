# IAM Scanner

Auditoria contínua de acessos privilegiados em ambientes Azure. A aplicação varre periodicamente dois planos de identidade e permissão — **Azure RBAC** (subscriptions) e **Entra ID** (diretório) — classifica cada atribuição por nível de risco, detecta o que mudou entre uma coleta e a próxima, e avisa a equipe de segurança no Microsoft Teams quando algo sensível é concedido ou revogado.

O objetivo é dar visibilidade contínua de "quem tem acesso a quê" sem depender de auditorias manuais pontuais — qualquer concessão de um papel crítico (`Owner`, `User Access Administrator`, `Global Administrator`, ...) aparece no dashboard e gera alerta assim que é detectada.

## O que a aplicação entrega

### Dashboard web (`/`)

- **Azure RBAC**, com uma aba por subscription (mais uma aba "Todos"), mostrando para cada atribuição: principal (usuário/grupo/service principal), role, nível de risco, tipo e escopo (Subscription / Management Group / Resource Group / Recurso — com badges `SUB`/`MG`/`RG`/`RES`).
- **Entra ID**, com as atribuições de directory roles do tenant inteiro (ex: quem é Global Administrator, Privileged Role Administrator, etc.).
- Cartões de resumo no topo: total de subscriptions descobertas, total de atribuições Azure/Entra, quantas são críticas em cada plano, e horário da última coleta.
- Busca e filtro por nível de risco e tipo de principal em cada tabela, exportação para **CSV** (Azure e Entra separados) e botão **"Atualizar agora"** para forçar uma nova coleta sem esperar o próximo ciclo.

### Classificação de risco

Toda role encontrada (Azure ou Entra) é enquadrada automaticamente em um nível, usado tanto no dashboard quanto para decidir o que notificar:

| Nível | Exemplos de roles |
|---|---|
| `CRITICO` | Owner, User Access Administrator, Global Administrator, Privileged Role Administrator |
| `ALTO` | Contributor, Security Administrator, Application Administrator, Key Vault Administrator |
| `MEDIO` | Key Vault Secrets Officer, Storage Blob Data Owner, Security Reader, Compliance Administrator |
| `LEITURA` | Reader, Billing Reader, Storage Blob Data Reader, Security Reader |
| `INFO` | Qualquer role não mapeada nas listas acima |

(Ver a classificação completa em [`app/collector.py`](app/collector.py).)

### Detecção de mudanças e alertas no Teams

A cada scan, o resultado é comparado com o anterior ([`app/differ.py`](app/differ.py)): toda atribuição que apareceu ou desapareceu desde a última coleta vira um evento de mudança (`added`/`removed`). Por padrão, só os níveis `CRITICO` e `ALTO` geram notificação (configurável via `NOTIFY_LEVELS`), evitando ruído por mudanças de baixo risco.

Quando há mudança relevante, um **Adaptive Card** é enviado ao canal Teams configurado ([`app/notifier.py`](app/notifier.py)), destacando concessões críticas em vermelho, com link direto para o dashboard. Se `TEAMS_HEARTBEAT=true`, também é enviado um resumo mesmo quando não há mudanças, como sinal de que o scanner está vivo.

## Como funciona

1. Autentica no Azure via `ClientSecretCredential` (App Registration dedicado), com app-only permissions.
2. Descobre as subscriptions acessíveis (ou usa a lista fixa em `SUBSCRIPTION_IDS`) e coleta os `role assignments` de cada uma via `azure-mgmt-authorization`, resolvendo os nomes de role e de principal (usuário/grupo/service principal) via Microsoft Graph — a API do ARM só devolve GUIDs.
3. Coleta os `directory roles` do Entra ID via Microsoft Graph (`/roleManagement/directory/roleAssignments`).
4. Roda esse ciclo em loop, no intervalo definido por `SCAN_INTERVAL_MINUTES` (via `apscheduler`), com a primeira coleta disparada assim que o servidor sobe.
5. Compara com a coleta anterior, calcula os cartões de resumo e, se configurado, notifica o Teams.
6. Expõe tudo isso via FastAPI: o dashboard HTML consome `/api/data` e `/api/status`, e pode disparar uma coleta manual via `/api/refresh`.

## Configuração

Variáveis de ambiente (ver `.env.example`):

| Variável | Obrigatória | Descrição |
|---|---|---|
| `AZURE_TENANT_ID` | sim | Tenant do Entra ID |
| `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | sim | Credenciais do App Registration |
| `SUBSCRIPTION_IDS` | não | Lista de subscriptions a monitorar, separadas por vírgula. Vazio = descobre automaticamente |
| `SCAN_INTERVAL_MINUTES` | não | Intervalo entre varreduras (padrão: 60) |
| `TEAMS_WEBHOOK_URL` | não | Webhook do canal Teams. Vazio = notificações desabilitadas |
| `TEAMS_DASHBOARD_URL` | não | URL pública do dashboard, usada no botão do card do Teams |
| `TEAMS_HEARTBEAT` | não | `true` envia um resumo a cada scan, mesmo sem mudanças |
| `NOTIFY_LEVELS` | não | Níveis de risco que geram notificação (padrão: `CRITICO,ALTO`) |

### Provisionando o App Registration

O script [`setup-sp.ps1`](setup-sp.ps1) cria o App Registration, concede as permissões de aplicativo necessárias no Microsoft Graph (`Directory.Read.All`, `RoleManagement.Read.Directory`) e atribui a role `Reader` em cada subscription monitorada. Requer `az login` com uma conta Global Administrator + Owner nas subscriptions.

Edite `$TenantId` e a lista `$Subscriptions` no início do script antes de rodar:

```powershell
.\setup-sp.ps1
```

## Rodando localmente

```bash
docker compose up --build
```

O `docker-compose.yml` lê as variáveis do `.env` (copie de `.env.example`). O dashboard fica disponível em `http://localhost:8080`.

## Stack

Python 3.12 · FastAPI · APScheduler · azure-identity / azure-mgmt-authorization / azure-mgmt-subscription · httpx · Docker.

## Licença

MIT — veja [LICENSE](LICENSE).
