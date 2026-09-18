# Auditoria técnica — CyberControl

Base analisada: `CarlosEduardoLemos/CyberControl`, branch `main`, commit `e5ef4264a59195cd20316d129363c19ef799c436`.

## Resumo

A arquitetura Flask + SQLite foi preservada por ser adequada ao escopo. Não foram introduzidos SPA, ORM, microserviços ou infraestrutura sem necessidade. As alterações focam segurança, ciclo de vida de dados, inicialização, testes, responsividade, acessibilidade e documentação.

## Alterações realizadas

### Segurança e autenticação

- Cadastro público permitido somente no bootstrap do primeiro administrador.
- Novos usuários, após o bootstrap, só podem ser criados por administrador e recebem o papel `analista`.
- Senha mínima de 8 caracteres no cadastro.
- Rate limiting de login migrado de memória para a tabela SQLite `login_attempts`.
- O endereço usado no rate limiting vem de `request.remote_addr`, evitando confiar diretamente em `X-Forwarded-For` fornecido pelo cliente.
- `SECRET_KEY` passou a ser obrigatória quando `APP_ENV=production`.
- `SESSION_COOKIE_SECURE` passou a ser configurável e é habilitada por padrão em produção.
- CSRF, `HttpOnly` e `SameSite=Lax` foram preservados.

### Banco e inicialização

- `init_db()` passou a executar na factory `create_app()`, inclusive quando a aplicação é importada por WSGI.
- Adicionada tabela `login_attempts`.
- `DATABASE_PATH` pode ser definido por variável de ambiente.
- Inicialização permanece idempotente.

### Evidências

- Adicionada lista de extensões permitidas para evidências.
- Validação ocorre antes da criação da vulnerabilidade, evitando registros parciais para arquivos rejeitados.
- Exclusão de vulnerabilidade remove seu diretório de evidências.
- Exclusão de ativo remove os diretórios de evidências das vulnerabilidades eliminadas em cascata.
- `secure_filename`, UUID, limite de 10 MB e `send_from_directory` foram preservados.

### Validação e código

- Filtros de severidade/status são validados antes de consultas e relatórios.
- Removida atribuição duplicada de `cursor.lastrowid`.
- Tratamento explícito de recurso inexistente em exclusões.
- Mantidas queries parametrizadas.

### Frontend / UX / acessibilidade

- Navbar responsiva com `navbar-toggler` funcional.
- Tabelas principais envolvidas por `table-responsive`.
- Formulários receberam associação `label`/`id` e atributos de autocomplete apropriados.
- Layout de ações melhorado para telas pequenas.
- Branding padronizado para `CyberControl`.

### CI / DevOps

- Permissões dos workflows explicitadas no princípio de menor privilégio.
- CI consolidado para executar cobertura uma única vez após lint/compile.
- Mantidos Ruff, Bandit, pip-audit e CodeQL.

### Documentação

- README sincronizado com Werkzeug 3.1.8 e o comportamento real da aplicação.
- Adicionado `.env.example` sem segredos.
- Documentado bootstrap, rate limiting, uploads, produção e limitações.

## Testes adicionados/expandidos

- Fechamento do cadastro público após bootstrap.
- Criação de analista por administrador.
- Persistência do bloqueio de login no SQLite.
- Rejeição de extensão de evidência não permitida.
- Remoção do diretório de evidência após exclusão da vulnerabilidade.
- Filtros inválidos de relatório.
- Mantidos testes de CSRF, traversal, status e primeiro administrador.

## Pendências / limitações conscientes

- O upload valida extensão, não assinatura/MIME real ou malware. Para exposição pública em produção, integrar antivírus ou serviço de análise de arquivos.
- SQLite continua sendo escolha consciente para uso leve. Escala concorrente exige outro banco.
- A confiança em IP real atrás de reverse proxy depende da configuração correta da infraestrutura/ProxyFix; não foi ativado automaticamente para evitar confiar em headers de origem desconhecida.
- O frontend utiliza Bootstrap via CDN; ambientes air-gapped precisam empacotar os assets localmente.

## Validação desta entrega

A validação executada no ambiente que gerou este ZIP está registrada também no arquivo `VALIDACAO.txt`. O ambiente não possui Flask/Werkzeug/Ruff/Bandit instalados e não possui acesso de rede ao PyPI, portanto não é correto declarar a suíte completa como executada localmente quando isso não ocorreu.
