# CyberControl — Sistema de Gestão de Vulnerabilidades

Aplicação web server-rendered em Flask para cadastro de ativos, registro e priorização de vulnerabilidades, controle de acesso, auditoria e consulta a fontes públicas de vulnerabilidades. O projeto utiliza SQLite e templates Jinja/Bootstrap, mantendo uma arquitetura simples e compatível com seu objetivo demonstrativo.

## Funcionalidades

- Bootstrap seguro: somente o primeiro usuário pode se cadastrar publicamente e se torna `admin`.
- Após o bootstrap, novas contas são criadas somente por administradores e entram como `analista`.
- Login com senha armazenada por hash do Werkzeug.
- Rate limiting de login persistente em SQLite.
- Gestão de ativos e vulnerabilidades.
- Score CVSS, severidade e score de risco contextual.
- Dashboard com filtros e dados públicos de CISA KEV/NVD.
- Upload protegido de evidências com limite de 10 MB e lista de extensões permitidas.
- Download autenticado de evidências com proteção contra path traversal.
- Exclusão de vulnerabilidades/ativos com limpeza das evidências associadas.
- Relatório PDF.
- Proteção CSRF em todas as operações POST.
- RBAC `admin` / `analista`.
- Auditoria de ações relevantes.
- CI, Ruff, Bandit, pip-audit e CodeQL.

## Stack

- Python 3.10+
- Flask 3.1.3
- Werkzeug 3.1.8
- SQLite
- Jinja2
- Bootstrap 5.3.3
- ReportLab 5.0.1

## Arquitetura

```text
Browser
  ↓
Flask + Jinja2
  ├── auth_routes.py
  ├── asset_routes.py
  ├── vuln_routes.py
  ├── dashboard_routes.py
  ├── user_routes.py
  └── audit_routes.py
  ↓
SQLite

Integrações externas:
  ├── CISA KEV
  └── NVD
```

A aplicação não possui uma API REST separada. O backend Flask renderiza as páginas e processa os formulários diretamente, o que é adequado ao tamanho e finalidade atuais do projeto.

## Estrutura

```text
CyberControl/
├── .github/workflows/
│   ├── ci.yml
│   ├── security.yml
│   └── codeql.yml
├── app_modules/
│   ├── asset_routes.py
│   ├── audit.py
│   ├── audit_routes.py
│   ├── auth_routes.py
│   ├── core.py
│   ├── dashboard_routes.py
│   ├── live_vulns.py
│   ├── risk.py
│   ├── user_routes.py
│   └── vuln_routes.py
├── templates/
├── tests/
├── .env.example
├── cybercontrol.py
├── requirements.txt
└── requirements-dev.txt
```

`database.db` e `uploads/` são criados em runtime e não devem ser versionados.

## Instalação

### Windows PowerShell

```powershell
git clone https://github.com/CarlosEduardoLemos/CyberControl.git
cd CyberControl
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Linux/macOS

```bash
git clone https://github.com/CarlosEduardoLemos/CyberControl.git
cd CyberControl
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Configuração

Use `.env.example` como referência. A aplicação lê as variáveis do ambiente do processo; ela não carrega `.env` automaticamente.

Variáveis suportadas:

| Variável | Padrão | Uso |
|---|---|---|
| `APP_ENV` | `development` | Use `production` em produção. |
| `SECRET_KEY` | chave efêmera em desenvolvimento | Obrigatória se `APP_ENV=production`. |
| `SESSION_COOKIE_SECURE` | ligado automaticamente em produção | Exige HTTPS quando ativado. |
| `DATABASE_PATH` | `database.db` | Caminho alternativo do SQLite. |
| `FLASK_DEBUG` | `0` | Desenvolvimento local apenas. |

Exemplo PowerShell para desenvolvimento:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:APP_ENV = "development"
python cybercontrol.py
```

Exemplo de produção:

```bash
export APP_ENV=production
export SECRET_KEY="uma-chave-forte-gerada-fora-do-repositorio"
export SESSION_COOKIE_SECURE=1
```

Se `APP_ENV=production` for usado sem `SECRET_KEY`, a aplicação falha imediatamente em vez de iniciar com uma chave efêmera.

## Execução

```bash
python cybercontrol.py
```

A aplicação local fica disponível em `http://127.0.0.1:5000`.

A inicialização do banco é idempotente e ocorre também ao importar a aplicação por um servidor WSGI. Em produção, use um servidor WSGI adequado e HTTPS; não publique o servidor de desenvolvimento do Flask.

## Usuários e permissões

1. Em um banco vazio, `/register` fica disponível para criar o administrador inicial.
2. Assim que existe um usuário, o cadastro público é fechado.
3. Administradores podem criar novos analistas pela tela **Usuários**.
4. Alterações de perfil e exclusões administrativas continuam restritas a `admin`.

## Rate limiting de login

As tentativas inválidas são persistidas na tabela `login_attempts` do SQLite. Após 5 falhas pelo mesmo endereço remoto, o login é bloqueado por 5 minutos. A contagem deixa de depender da memória do processo e continua válida após reinicializações.

Se a aplicação ficar atrás de reverse proxy, configure corretamente o middleware de proxy da infraestrutura antes de utilizar cabeçalhos encaminhados como origem do cliente. O código não confia diretamente em `X-Forwarded-For` para a decisão de bloqueio.

## Upload de evidências

- Diretório: `uploads/<vulnerability_id>/`.
- Tamanho máximo da requisição: 10 MB.
- Nomes sanitizados com `secure_filename` e prefixo UUID.
- Extensões permitidas: `csv`, `jpeg`, `jpg`, `json`, `log`, `pdf`, `png`, `txt`.
- Downloads exigem autenticação e usam `send_from_directory`.
- Ao excluir uma vulnerabilidade ou um ativo, as evidências relacionadas também são removidas.

A validação de extensão reduz a superfície de risco, mas não substitui antivírus/antimalware em ambientes que recebam arquivos não confiáveis em escala.

## Banco de dados

Tabelas:

- `users`
- `assets`
- `vulnerabilities`
- `audit_logs`
- `login_attempts`

O banco usa foreign keys, exclusão em cascata de vulnerabilidades quando um ativo é removido e índices para consultas frequentes.

SQLite permanece adequado para demonstração e uso leve. Para concorrência elevada ou múltiplas instâncias, use um banco gerenciado apropriado.

## Testes

Instale também as dependências de desenvolvimento:

```bash
python -m pip install -r requirements-dev.txt
```

Execute:

```bash
python -m unittest discover -v tests
```

Cobertura:

```bash
coverage run -m unittest discover -v tests
coverage report -m
```

Os testes incluem regressões para CSRF, bootstrap do administrador, fechamento do cadastro público, criação administrativa de analistas, rate limiting persistente, traversal, status inválido, extensão de evidência, limpeza de evidências e filtros de relatório.

## Qualidade e segurança

```bash
ruff check .
bandit -r app_modules cybercontrol.py -ll
pip-audit -r requirements.txt
```

O GitHub Actions executa CI em Python 3.10, 3.11 e 3.12 e mantém workflows separados para análise estática e dependências.

## Limitações conhecidas

- SQLite é intencionalmente mantido por simplicidade.
- CISA KEV e NVD são serviços externos; falhas nessas fontes não devem afetar dados locais.
- O score contextual é uma triagem e não substitui análise formal de risco.
- O upload valida extensão, não o conteúdo binário do arquivo.
- Para produção real, recomenda-se WSGI, HTTPS, política de backup, observabilidade e armazenamento de evidências compatível com a escala.
