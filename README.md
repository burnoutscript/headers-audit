# headers-audit

Auditor de headers de segurança HTTP e cookies, com nota de A+ a F.

Você passa uma URL (ou um dump de headers salvo com `curl`) e ele verifica HSTS, CSP,
proteção contra clickjacking, cookies, CORS e mais, explica cada problema e diz qual header
mandar no lugar.

[![CI](https://github.com/burnoutscript/headers-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/burnoutscript/headers-audit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependências](https://img.shields.io/badge/dependências-zero-success)
![Licença](https://img.shields.io/badge/licença-MIT-lightgrey)

## Por que fiz isso

Headers de segurança custam quase nada. São algumas linhas na config do servidor ou do CDN, e
cada uma fecha uma classe de ataque: HSTS contra SSL stripping, CSP contra XSS que passou da
validação, `frame-ancestors` contra clickjacking. Eles diminuem o estrago quando alguma falha
passa pelo código.

A Prumo, plataforma que fundei com o Marcos Alan, roda atrás do Cloudflare, e eu queria um jeito de conferir
os headers que chegam de fato no navegador sem depender de uma lista de cabeça. Este projeto
escreve no código o critério de cada verificação e testa cada um.

## Instalação

```bash
git clone https://github.com/burnoutscript/headers-audit.git
cd headers-audit
pip install -e .
```

Python 3.10+, sem nenhuma dependência além da biblioteca padrão.

## Uso

```bash
# URL ao vivo (sem esquema, assume https://)
headers-audit https://meusite.com.br

# falhar o CI se a nota ficar abaixo de A
headers-audit https://meusite.com.br --min-grade A

# offline, a partir de um dump (não acessa a rede)
curl -sIL http://meusite.com.br > headers.txt
headers-audit --from-file headers.txt --url http://meusite.com.br/

# Markdown para colar no pull request, ignorando verificações
headers-audit https://meusite.com.br --format markdown --ignore HA008,HA009 -o relatorio.md

# JSON
headers-audit https://meusite.com.br --format json | jq '.summary'
```

No modo ao vivo a ferramenta segue os redirecionamentos um a um (no máximo 10), audita a
resposta final e, se a URL for https, testa também a versão http para ver se ela redireciona.
Também envia um `Origin` inventado (`https://headers-audit-probe.invalid`) para descobrir se o
servidor reflete qualquer origem no CORS.

O `--from-file` aceita a saída de `curl -sI` ou `curl -sIL` (cada bloco `HTTP/` é um salto, o
último é a resposta final) e headers copiados do DevTools. O `--url` diz de onde o dump veio;
com uma URL `http://`, a cadeia de `Location` mostra se houve redirecionamento para https.

Os dois dumps em `samples/` imitam o mesmo app antes e depois da configuração. O fraco:

```
$ headers-audit --from-file samples/site_fraco.txt

  headers-audit · headers de segurança HTTP
  samples/site_fraco.txt · status 200 · 14 headers

  Nota  F   0/100 · 22 achado(s)
  ──────────────────────────────────────────────────────────────────

   ALTO  CSP permite script inline  HA004
  Content-Security-Policy

  script-src tem 'unsafe-inline' sem nonce nem hash. Um XSS refletido como
  <script>...</script> executa normalmente, e a CSP perde quase todo o efeito contra XSS.

  → Trocar 'unsafe-inline' por nonce ('nonce-...') ou hash ('sha256-...'). Com nonce
  presente, navegadores CSP2+ ignoram o 'unsafe-inline'.

   MÉDIO  HSTS com max-age curto  HA002
  Strict-Transport-Security

  max-age 3600s. Abaixo de seis meses a proteção expira entre visitas e o navegador volta
  a aceitar HTTP. max-age=0 apaga o HSTS.

  → Usar max-age de pelo menos 15552000 (seis meses), de preferência 31536000.

  [...]

   MÉDIO  Cookie __Host- fora das regras do prefixo  HA010
  cookie __Host-carrinho

  O prefixo __Host- exige Secure, Path=/ e nenhum Domain. O navegador rejeita o cookie,
  então ele não chega a ser gravado.

  → Definir Secure; Path=/ e remover o atributo Domain.

  [...]

   INFO  X-XSS-Protection ligado  HA013
  X-XSS-Protection

  X-XSS-Protection: 1; mode=block. O filtro XSS foi removido dos navegadores atuais e, nos
  antigos, já foi usado para apagar scripts legítimos da página e vazar dados.

  → Remover o header ou enviar X-XSS-Protection: 0, e confiar na CSP.

  ──────────────────────────────────────────────────────────────────
  nota: Redirecionamento http -> https não testado: o dump não começa numa URL http://
  (informe com --url).
  nota: CORS: um dump não mostra se o servidor reflete o Origin recebido. Isso só é
  testável contra a URL ao vivo.

$ echo $?
1
```

E o mesmo app configurado, com o salto de http para https no dump:

```
$ headers-audit --from-file samples/site_blindado.txt --url http://app.example.com/

  headers-audit · headers de segurança HTTP
  samples/site_blindado.txt · status 200 · 11 headers
  redirecionamentos: http://app.example.com/ → https://app.example.com/

  Nota  A+   100/100 · 0 achado(s)
  ──────────────────────────────────────────────────────────────────

  Nenhum problema encontrado nas verificações ativas.

$ echo $?
0
```

## Verificações

| ID | Verificação | Severidade | O que procura |
|---|---|---|---|
| HA001 | HSTS ausente | Alta | Resposta HTTPS sem `Strict-Transport-Security` |
| HA002 | HSTS fraco | Média / Baixa / Info | `max-age` abaixo de seis meses (ou zero, ou inválido), sem `includeSubDomains`, `preload` sem os requisitos da lista |
| HA003 | CSP ausente | Alta | Sem `Content-Security-Policy`. Só `Report-Only` conta como ausente, porque não bloqueia nada |
| HA004 | CSP fraca | Alta / Média / Baixa / Info | `unsafe-inline` sem nonce ou hash, `unsafe-eval`, `*` ou `https:` em `script-src`, sem `object-src 'none'`, sem `base-uri`, sem `frame-ancestors` |
| HA005 | Clickjacking | Média | Nem `X-Frame-Options: DENY/SAMEORIGIN` nem `frame-ancestors`. `ALLOW-FROM` não conta |
| HA006 | `nosniff` ausente | Média | `X-Content-Type-Options` diferente de `nosniff` |
| HA007 | Referrer-Policy | Média / Baixa | Ausente, `unsafe-url` ou `no-referrer-when-downgrade` |
| HA008 | Permissions-Policy ausente | Baixa | Nenhuma restrição a câmera, microfone, geolocalização |
| HA009 | COOP ausente | Baixa | `Cross-Origin-Opener-Policy` ausente ou `unsafe-none` |
| HA010 | Cookies | Média / Baixa | Sem `Secure`, sessão sem `HttpOnly`, sem `SameSite`, `SameSite=None` sem `Secure`, regras dos prefixos `__Host-` e `__Secure-` |
| HA011 | CORS | Alta / Média / Baixa | Origem refletida (com ou sem credenciais), `*` com `Allow-Credentials: true`, origem `null` |
| HA012 | Versão exposta | Baixa | `Server` ou `X-Powered-By` com número de versão, `X-AspNet-Version` |
| HA013 | X-XSS-Protection ligado | Info | `X-XSS-Protection: 1` |
| HA014 | Sem HTTPS | Alta | Resposta final em HTTP, ou versão http que não redireciona para https |

O CSP é lido por um parser próprio que segue a especificação nos detalhes que mudam o
resultado: diretiva repetida vale a primeira, `script-src` e `object-src` herdam de
`default-src` mas `base-uri` e `frame-ancestors` não, e headers repetidos são políticas
independentes que valem ao mesmo tempo (uma fraqueza só conta se todas as políticas a
permitirem).

Na HA010, "cookie de sessão" é decidido pelo nome (`sess`, `sid`, `auth`, `token`, `jwt`,
`login`...). Tokens de CSRF (`csrftoken`, `XSRF-TOKEN`) ficam de fora porque o padrão double
submit exige que o JavaScript os leia. Cookies sendo apagados (`Max-Age=0`) são ignorados.

## Pontuação

A nota começa em 100 e cada achado desconta conforme a severidade:

| Severidade | Desconto |
|---|---|
| Alta | 20 |
| Média | 10 |
| Baixa | 5 |
| Info | 0 |

Cada verificação desconta no máximo 25 pontos. Sem esse teto, um site com oito cookies sem
`SameSite` perderia mais pontos do que um sem CSP, e oito cookies com o mesmo erro costumam ser
um erro só, na configuração do framework. A pontuação nunca fica negativa.

| Nota | Pontos |
|---|---|
| A+ | 95 a 100 |
| A | 85 a 94 |
| B | 70 a 84 |
| C | 55 a 69 |
| D | 40 a 54 |
| F | abaixo de 40 |

Só falta de CSP já leva um site de 100 para 80 (B). Sem CSP e sem HSTS, 60 (C). Verificações
ignoradas com `--ignore` não entram na conta. O JSON traz o desconto por verificação em
`summary.penalties`, para dar para ver de onde veio a nota.

## Decisão de projeto: `unsafe-inline` com nonce não é achado

A CSP mais recomendada hoje (a "strict CSP" que o Google documenta) tem este formato:

```
script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'
```

Lida ao pé da letra, ela tem `'unsafe-inline'` e `https:` em `script-src`, as duas coisas que
um auditor ingênuo marca como grave. Só que um navegador com CSP nível 2 ou mais, ao ver um
nonce ou hash, ignora o `'unsafe-inline'`. Com `'strict-dynamic'` (nível 3), ignora também
host e esquema, como o `https:`. Esses dois tokens estão ali de propósito, para navegadores
antigos que não entendem nonce continuarem funcionando em vez de quebrar o site inteiro.

Por isso o headers-audit só aponta `'unsafe-inline'` quando não há nonce, hash nem
`'strict-dynamic'` na mesma diretiva, e só aponta `https:` ou `*` quando não há
`'strict-dynamic'`. O dump `site_blindado.txt` usa exatamente essa política e tira A+.

O `'unsafe-eval'` continua sendo apontado em qualquer caso, porque nonce não tem efeito sobre
`eval()`. A mesma lógica faz `frame-ancestors` ausente virar só Info quando já existe um
`X-Frame-Options` válido: a proteção está lá, por outro caminho.

## Arquitetura

```
   URL (ao vivo)                       dump de headers (--from-file)
        │                                         │
        ▼                                         ▼
  ┌───────────┐  GET sem seguir redirect, ┌────────────┐  blocos HTTP/ viram saltos,
  │   fetch   │  salto a salto; testa a   │ parse_dump │  o último é a resposta
  │           │  versão http; Origin falso└─────┬──────┘
  └─────┬─────┘                                 │
        └──────────────────┬────────────────────┘
                           │  Response (headers, status, cadeia, http->https)
                           ▼
                     ┌──────────┐   14 verificações independentes
                     │  checks  │◀── csp.py (parser de política)
                     │          │◀── cookies.py (parser de Set-Cookie)
                     └────┬─────┘
                          │  Finding (severidade, alvo, explicação, correção)
                          ▼
                     ┌──────────┐
                     │ scoring  │   100 menos descontos, teto por verificação
                     └────┬─────┘
                          ▼
                     ┌──────────┐
                     │  report  │   terminal · JSON · Markdown
                     └──────────┘
```

As verificações recebem só o modelo `Response`, sem saber se ele veio da rede ou de um
arquivo. Por isso os testes e o CI rodam tudo offline, e o modo ao vivo é testado contra um
`http.server` local em `127.0.0.1`.

O redirecionamento é seguido na mão (um `HTTPRedirectHandler` que não redireciona) porque o
`urllib` por padrão esconde os saltos, e é no salto que se vê se `http://` leva para
`https://`.

### Código de saída

| Código | Significado |
|---|---|
| `0` | Nota igual ou acima de `--min-grade` (padrão B) |
| `1` | Nota abaixo do mínimo |
| `2` | Erro (URL inacessível, arquivo não existe, dump sem headers, verificação desconhecida) |

No CI, contra o ambiente de staging:

```yaml
- run: |
    pip install git+https://github.com/burnoutscript/headers-audit.git
    headers-audit https://staging.meusite.com.br --min-grade A
```

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest -v        # 123 testes
ruff check src tests
```

Cada verificação tem teste nos dois sentidos: o caso que deve disparar e um parecido que não
deve (`unsafe-inline` com nonce, `Server: cloudflare` sem versão, cookie `csrftoken` sem
`HttpOnly`, `X-XSS-Protection: 0`, origem CORS fixa). O parser de CSP tem testes para
diretiva repetida, maiúsculas, ponto e vírgula sobrando e várias políticas no mesmo header.
Nenhum teste acessa a internet.

## Limitações

- Headers são uma camada. Nota A+ diz que o navegador recebeu as instruções certas, e nada
  sobre o código do servidor, a autenticação ou as dependências.
- Audita uma URL por vez e não navega pelo site. Uma rota de API ou uma página de login com
  headers diferentes da home precisa ser passada separadamente.
- Reflexo de origem no CORS só é detectável ao vivo, com o `Origin` falso. Num dump não tem
  como saber, e o relatório avisa. Mesmo ao vivo, só é testada uma origem: um servidor que
  aceita `*.meusite.com.br` por regex mal escrita passa.
- A CSP é avaliada pela sintaxe. Um host listado em `script-src` que hospeda JSONP ou uma
  versão antiga do Angular permite bypass, e isso não é verificado.
- "Cookie de sessão" é decidido pelo nome. Um cookie de sessão chamado `u` passa sem o alerta
  de `HttpOnly`.
- Se o site está atrás de CDN, a ferramenta vê os headers que o CDN entrega, que é o que
  importa para o navegador, mas não diz qual camada adicionou ou removeu cada um.
- O modo ao vivo faz um `GET` com `Origin` e `User-Agent` próprios. Um WAF pode responder
  diferente para esse cliente do que para um navegador.

## Licença

MIT. Veja [LICENSE](LICENSE).
