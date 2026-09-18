# CyberControl — Sistema de Gestão de Vulnerabilidades

Aplicação web em Flask para cadastro de ativos, registro de vulnerabilidades, controle de permissões e monitoramento de risco. O sistema também consome vulnerabilidades públicas de CISA KEV e NVD.

O projeto é voltado a demonstração e estudo de um fluxo de gestão de vulnerabilidades com Flask, SQLite e uma interface administrativa leve.

## Funcionalidades

- Cadastro e login de usuários
- Primeiro usuário criado como `admin`; usuários seguintes como `analista`
- Gestão de ativos de TI
- Registro de vulnerabilidades com score CVSS e cálculo automático de severidade
- Dashboard e filtros
- Consulta a CISA KEV e NVD
- Upload e download protegido de evidências
- Geração de relatório em PDF
- Proteção CSRF nos formulários
- Controle de acesso para operações administrativas
- Registro de auditoria de ações relevantes
- Rate limiting básico para tentativas de login
- Score de risco contextual por ativo e vulnerabilidade
- Integração de severidade CVSS real retornada pelo NVD
- Enriquecimento CISA KEV com ransomware e due date

## Tecnologias

- Python 3.10+
- Flask 3.1.3
- Werkzeug 3.1.6
- SQLite
- Bootstrap 5
- ReportLab

## Estrutura

```text
CyberControl/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── codeql.yml
├── app_modules/
│   ├── auth_routes.py
│   ├── asset_routes.py
│   ├── core.py
│   ├── dashboard_routes.py
│   ├── live_vulns.py
│   ├── audit.py
│   ├── audit_routes.py
│   ├── risk.py
│   ├── user_routes.py
│   └── vuln_routes.py
├── templates/
├── tests/
├── cybercontrol.py
├── requirements.txt
└── README.md
```

`database.db` e `uploads/` são criados em runtime e não devem ser versionados.

## Instalação

### Windows PowerShell

```powershell
git clone https://github.com/CarlosEduardoLemos/CyberControl.git
cd CyberControl
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux/macOS

```bash
git clone https://github.com/CarlosEduardoLemos/CyberControl.git
cd CyberControl
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuração

Defina uma chave de sessão forte antes de executar a aplicação. Ela não deve ser commitada.

PowerShell:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Bash:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Se `SECRET_KEY` não estiver definida, uma chave aleatória é criada para o processo atual. Isso é útil apenas em desenvolvimento porque sessões existentes deixam de ser válidas após reiniciar a aplicação.

## Execução

```bash
python cybercontrol.py
```

A aplicação fica disponível em:

```text
http://127.0.0.1:5000
```

O modo debug fica desativado por padrão. Para desenvolvimento local:

PowerShell:

```powershell
$env:FLASK_DEBUG = "1"
python cybercontrol.py
```

Não exponha o servidor de desenvolvimento do Flask diretamente em produção.

## Upload de evidências

- Evidências são armazenadas em `uploads/<vulnerability_id>/`.
- Nomes são sanitizados antes de serem gravados.
- Downloads usam resolução segura dentro da pasta da vulnerabilidade.
- O limite total da requisição é 10 MB.
- `uploads/` está no `.gitignore`.

## Testes

```bash
python -m unittest discover -v tests
```

Os testes cobrem, entre outros pontos:

- importação/carregamento básico;
- filtros e resumo de vulnerabilidades públicas;
- regressão do cache de consultas externas;
- proteção CSRF;
- criação do primeiro administrador;
- traversal no download de evidências;
- validação de status.

## CI

O workflow `.github/workflows/ci.yml` executa compilação e testes em Python 3.10, 3.11 e 3.12.

## Modelo de dados

- `users` — usuários
- `assets` — ativos
- `vulnerabilities` — vulnerabilidades vinculadas aos ativos
- `audit_logs` — eventos de auditoria e rastreabilidade

## Escala de severidade local

| Score CVSS | Severidade |
|---|---|
| 0.0 | Nenhuma |
| 0.1 – 3.9 | Baixa |
| 4.0 – 6.9 | Média |
| 7.0 – 8.9 | Alta |
| 9.0 – 10.0 | Crítica |

## Risco contextual

O CyberControl calcula um score de triagem combinando CVSS, criticidade do ativo, exposição à Internet e indicação de exploração conhecida (CISA KEV). O score é apresentado como apoio à priorização e não substitui uma avaliação formal de risco.

## Segurança no CI

Além dos testes funcionais, o projeto possui workflows separados para:
- Ruff — lint;
- Bandit — análise de segurança do código Python;
- pip-audit — auditoria de dependências;
- CodeQL — análise estática de segurança.

## Auditoria

Administradores podem consultar os últimos eventos na rota /audit. São registrados, entre outros:
- criação e alteração de usuários;
- alterações de perfil;
- criação e exclusão de ativos;
- criação, alteração de status e exclusão de vulnerabilidades;
- logins bem-sucedidos e bloqueios por excesso de tentativas.

## Limitações

- SQLite é adequado a uso leve e demonstração.
- CISA KEV e NVD são serviços externos; indisponibilidade dessas fontes não deve impedir o uso dos dados locais.
- A classificação exibida para registros externos é uma simplificação de apresentação e não substitui análise de risco contextual.
- Para produção, ainda é recomendável usar um servidor WSGI apropriado, HTTPS, rate limiting, logs de auditoria e banco gerenciado conforme a escala.
