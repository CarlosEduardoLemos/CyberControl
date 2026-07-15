# CyberControl — Sistema de Gestão de Vulnerabilidades

Aplicação web em Flask para cadastro de ativos, registro de vulnerabilidades, controle de permissões e monitoramento de risco. O sistema também consome vulnerabilidades públicas em tempo real de fontes como CISA KEV e NVD.

O projeto é ideal para demonstração de um fluxo de segurança em TI com Flask, SQLite e uma interface administrativa leve.

## Visão geral

- Cadastro e login de usuários
- Perfis de acesso: `admin` e `analista`
- Gestão de ativos de TI
- Registro de vulnerabilidades com score CVSS e cálculo automático de severidade
- Dashboard com indicadores, vulnerabilidades públicas recentes e filtros avançados
- Upload de evidências para vulnerabilidades
- Geração de relatório em PDF

## Tecnologias usadas

- Python 3
- Flask
- SQLite
- Bootstrap 5
- ReportLab
- Werkzeug

## Estrutura do projeto

```text
cybercontrol/
├── cybercontrol.py
├── app_modules/
│   ├── auth_routes.py
│   ├── asset_routes.py
│   ├── core.py
│   ├── dashboard_routes.py
│   ├── live_vulns.py
│   ├── user_routes.py
│   └── vuln_routes.py
├── templates/
├── static/
├── tests/
├── requirements.txt
└── database.db
```

## Requisitos

- Python 3.10 ou superior
- pip

## Instalação

```bash
cd c:\Users\User\Documents\cybercontrol
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Execução

```bash
python cybercontrol.py
```

A aplicação ficará disponível em:

http://127.0.0.1:5000

Na primeira execução, o projeto cria automaticamente o banco de dados SQLite e a pasta `uploads` para armazenar evidências.

## Uso básico

1. Acesse o endereço local na barra de endereços do navegador
2. Cadastre um usuário
3. Faça login
4. Cadastre seus ativos
5. Registre vulnerabilidades para ativos existentes
6. Utilize o dashboard para filtrar e acompanhar métricas

## Testes

```bash
python -m unittest discover tests
```

## Modelo de dados

- `users` — usuários do sistema
- `assets` — ativos de TI
- `vulnerabilities` — registros de vulnerabilidades vinculados a ativos

Estrutura mínima:

```text
users           (id, username, password_hash, role)
assets          (id, name, ip_address, asset_type, owner, created_by, created_at)
vulnerabilities (id, asset_id, title, description, cvss_score, severity, status,
                 discovered_date, resolved_date, created_by, created_at)
```

## Escala de severidade

| Score CVSS | Severidade |
|---|---|
| 0.0 | Nenhuma |
| 0.1 – 3.9 | Baixa |
| 4.0 – 6.9 | Média |
| 7.0 – 8.9 | Alta |
| 9.0 – 10.0 | Crítica |

## Observações

- A importação de vulnerabilidades públicas depende de serviços externos (CISA KEV e NVD).
- Se uma fonte externa estiver indisponível, o sistema continua funcionando com os dados locais.
- O armazenamento de evidências é feito localmente na pasta `uploads`.
- O banco SQLite atende a cenários de uso leve e demonstração.

## Melhoria contínua

- Adicionar proteção CSRF nos formulários
- Implementar logs de auditoria de ações
- Permitir múltiplos anexos por vulnerabilidade
- Adicionar notificações por e-mail para casos críticos
- Ampliar as fontes de inteligência de vulnerabilidades
- Cobrir o projeto com mais testes automatizados
- Preparar deploy em ambiente de produção
