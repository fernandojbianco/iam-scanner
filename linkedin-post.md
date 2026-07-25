🔐 IAM Scanner — auditoria contínua de acessos privilegiados no Azure

Em ambientes Azure com várias subscriptions, é fácil perder o rastro de quem tem acesso a quê. Permissões críticas (Owner, User Access Administrator, Global Administrator...) são concedidas o tempo todo, e sem um processo contínuo isso só aparece numa auditoria manual, meses depois.

Construí um scanner que varre periodicamente o Azure RBAC (todas as subscriptions) e os Directory Roles do Entra ID, classifica cada atribuição por nível de risco e compara com a coleta anterior. Toda concessão ou revogação de um acesso crítico gera um alerta automático no Microsoft Teams.

O que ele entrega:
🔎 Dashboard com Azure RBAC + Entra ID, busca/filtro e export CSV
🚦 Classificação automática de risco
🔔 Alertas no Teams só quando algo relevante muda
⚙️ 100% app-only, sem depender de ninguém logado

Stack: Python, FastAPI, APScheduler, Azure SDK, Microsoft Graph, Docker.

Deixei uma versão de exemplo (sanitizada, sem dados reais) no meu GitHub — link nos comentários. 👇

#Azure #EntraID #IAM #CloudSecurity #DevSecOps #Python
