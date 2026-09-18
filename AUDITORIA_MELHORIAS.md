# Evolução técnica — PR2, PR3 e PR4

Esta versão consolida três ciclos de evolução sobre o CyberControl preservando Flask + SQLite e a finalidade original do projeto.

## PR2 — Security & Architecture

- Autorização passou a usar o usuário carregado do banco em cada request; o `role` da sessão não é mais fonte de verdade.
- Sessões de usuários removidos são invalidadas automaticamente.
- Mudanças de perfil passam a valer na request seguinte sem depender de novo login.
- Token CSRF deixa de ser reaproveitado após autenticação; a sessão é rotacionada no login.
- Conexão SQLite centralizada no contexto Flask (`g`) e encerrada por `teardown_appcontext`.
- `init_db()` ganhou migrations idempotentes registradas em `schema_migrations`.
- Rate limiting passou de IP isolado para IP + usuário.
- Registros antigos de tentativas de login são limpos automaticamente.
- Testes de regressão ampliados para autorização, sessão e migrations.

## PR3 — Vulnerability Management

- Novos campos: CVE, CWE, origem, remediação, responsável, prazo, `updated_at` e CISA KEV.
- SLA padrão por severidade: Crítica 7d, Alta 15d, Média 30d, Baixa 60d, Nenhuma 90d.
- Classificação operacional de SLA: Dentro do SLA, Próximo do vencimento, Vencido e Resolvida.
- Edição completa da vulnerabilidade, não apenas status.
- Filtros por SLA e CISA KEV.
- Risco contextual incorpora indicação KEV quando o CVE é identificado no cache CISA.
- Relatório PDF atualizado com CVE, risco e SLA.

## PR4 — Dashboard & Analytics

- KPIs: ativos, vulnerabilidades abertas, SLA vencido, KEV abertas e MTTR.
- Ranking de ativos com maior exposição.
- Evolução mensal das vulnerabilidades descobertas.
- Backlog por responsável.
- Threat Intelligence removida do caminho crítico do dashboard.
- Atualização CISA/NVD agora é explícita e sincroniza CVEs locais com o catálogo KEV.
- Dashboard e tabelas mantêm Bootstrap sem adicionar dependência de gráficos.

## Validação executada neste ambiente

- `python -m compileall -q .`: PASSOU.
- `python -m unittest -v tests.test_sla tests.test_risk`: PASSOU (6 testes).
- Suíte completa Flask: não executada localmente porque Flask/Werkzeug não estão instalados no runtime e o ambiente não possui acesso ao PyPI.
- Ruff/Bandit/pip-audit: não disponíveis neste runtime; permanecem configurados no GitHub Actions.

A ausência dessas ferramentas locais não é tratada como aprovação. O CI do repositório deve executar a validação completa após o push.
