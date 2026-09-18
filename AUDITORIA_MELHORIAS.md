# Alterações da auditoria

Esta cópia foi preparada a partir do repositório `CarlosEduardoLemos/CyberControl`.

## Alterações aplicadas

- `SECRET_KEY` removida do código e substituída por variável de ambiente ou chave efêmera em desenvolvimento.
- Proteção CSRF adicionada a todas as requisições POST.
- Logout alterado de GET para POST.
- Download de evidências migrado para `send_from_directory`.
- Upload com `secure_filename`, UUID e limite de requisição de 10 MB.
- Validação de status, perfil e `asset_id`.
- Debug desativado por padrão.
- Cache das fontes externas corrigido para não armazenar resultado filtrado por uma requisição específica.
- Interpretação de `knownRansomwareCampaignUse` da CISA tornada explícita.
- Flask atualizado para 3.1.3 e Werkzeug para 3.1.6.
- `uploads/` adicionado ao `.gitignore`.
- Testes de regressão e workflow de CI adicionados.
- README atualizado.

Não foram introduzidas novas funcionalidades de produto.

## Validação executada neste ambiente

- `python -m compileall -q .`: **PASSOU**.
- `python -m unittest discover -v tests`: **NÃO EXECUTOU A SUÍTE**, porque o runtime fornecido não possui Flask instalado.
- `python -m pip install -r requirements.txt`: **BLOQUEADO PELO AMBIENTE**, pois a resolução de nomes/acesso ao PyPI não estava disponível.

Portanto, a sintaxe Python foi validada, mas a suíte completa não é declarada como aprovada neste ambiente. O workflow de CI incluído executará instalação, compilação e testes em Python 3.10, 3.11 e 3.12 quando o projeto for enviado ao GitHub.
