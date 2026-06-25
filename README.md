# VulnGate

Vulnerability Scanner CLI powered by [Trivy](https://aquasecurity.github.io/trivy/) + SAST with [OpenGrep](https://opengrep.dev) / [Semgrep](https://semgrep.dev).

## O que é

**VulnGate** combina dois scanners em uma única CLI:

- **Trivy** — detecta vulnerabilidades em dependências, secrets e misconfigurations
- **OpenGrep/Semgrep** — detecta padrões inseguros diretamente no código-fonte (SAST)

```
Trivy: dependências com CVEs conhecidas
SAST: SQL injection, XSS, eval, weak crypto, etc.
```

## Pré-requisitos

- **Go 1.22+** (para compilar)
- **Trivy** — instalado automaticamente via `vg install`
- **OpenGrep** — instalado automaticamente via `vg install`

## Instalação rápida

```bash
# Compilar
go build -o vulngate .

# Instalar tudo (Trivy + OpenGrep + aliases)
vg install

# Ou com force (reinstalar)
vg install --force

# Verificar instalação
vg install --check
```

### O que `vg install` faz

1. Copia `vulngate` para `~/.vulngate/bin/`
2. Cria aliases `vg.bat` (CMD) e `vg.ps1` (PowerShell)
3. Adiciona `function vg` no PowerShell profile
4. Baixa e instala o **Trivy**
5. Baixa e instala o **OpenGrep**
6. Adiciona `~/.vulngate/bin/` ao PATH do usuário

## Comandos

### Scan (Trivy)

```bash
vg scan fs .                          # Scan filesystem
vg scan fs ./my-project               # Scan projeto específico
vg scan repo https://github.com/org/repo  # Scan repositório Git
vg scan fs . --severity HIGH,CRITICAL # Filtrar severidade
vg scan fs . --format sarif --output report.sarif  # Export SARIF
```

### SAST (OpenGrep/Semgrep)

```bash
vg sast fs .                          # Scan com OpenGrep (padrão)
vg sast fs . --engine semgrep         # Scan com Semgrep
vg sast fs . --rules rules/sast       # Regras customizadas
vg sast fs . --fail-on ERROR          # Falhar em ERROR
vg sast fs . --format json --output sast.json
```

### Full Scan (Trivy + SAST)

```bash
vg full                               # Scan completo no diretório atual
vg full .                             # Idem
vg full ./my-project                  # Scan completo em projeto
vg full fs ./my-project               # Subcomando explícito
vg full --engine semgrep              # Usar Semgrep
```

### Outros

```bash
vg version                            # Versão do VulnGate e Trivy
vg install                            # Instalar dependências
vg install --check                    # Verificar instalação
```

## Regras SAST incluídas

### Java
- SQL Injection por concatenação
- TLS inseguro (HostnameVerifier)
- Criptografia fraca (MD5, SHA1, DES, RC4)

### JavaScript/TypeScript
- `eval()`, `new Function()`, `setTimeout` com string
- SQL Injection em queries Node.js

### React
- `dangerouslySetInnerHTML`

### Vue.js
- `v-html`

### Regras customizadas

Coloque suas regras em `rules/sast/custom/`:

```yaml
rules:
  - id: hardcoded-api-key
    pattern: |
      $VAR = "sk-..."
    message: Hardcoded API key detected
    languages: [java, javascript]
    severity: ERROR
```

## GitHub Actions

```yaml
- name: VulnGate Scan
  run: |
    go build -o vulngate .
    ./vulngate install --check
    ./vulngate full fs . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Exit Codes

| Code | Significado |
|------|-------------|
| `0` | Nenhuma vulnerabilidade encontrada |
| `1` | Vulnerabilidades encontradas (conforme `--fail-on`) |
| `2` | Erro de execução ou validação |

## Roadmap

- [ ] Docker image scanning
- [ ] Configuration file `.vulngate.yaml`
- [ ] Vulnerability policy por severidade
- [ ] Ignore list com justificativa e expiração
- [ ] Markdown report generation
- [ ] Slack/Teams integration
- [ ] HTTP API
- [ ] Web dashboard
- [ ] Scan history
- [ ] Dependency-Track integration
- [ ] SBOM generation com Syft
- [ ] OSV-Scanner integration

## Licença

MIT License.
