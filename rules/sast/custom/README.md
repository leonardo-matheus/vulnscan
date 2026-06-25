# Custom SAST Rules

Place your custom rules here. Supported formats:

## OpenGrep/Semgrep YAML Rules

Create `.yaml` files with the following structure:

```yaml
rules:
  - id: custom-rule-id
    pattern: |
      $FUNC($ARG)
    message: >
      Description of the finding
    languages: [java, javascript, typescript]
    severity: ERROR
    metadata:
      category: security
      cwe:
        - id: "CWE-79"
          name: "Cross-site Scripting (XSS)"
```

## Example: Detect hardcoded API key

```yaml
rules:
  - id: hardcoded-api-key
    pattern: |
      $VAR = "sk-..."
    message: >
      Hardcoded API key detected. Use environment variables instead.
    languages: [java, javascript, typescript, python]
    severity: ERROR
    metadata:
      category: security
      cwe:
        - id: "CWE-798"
          name: "Use of Hard-coded Credentials"
```

## Usage

```bash
# Use custom rules only
vulngate sast fs . --rules rules/sast/custom --no-default-rules

# Use custom rules alongside defaults
vulngate sast fs . --rules rules/sast/custom
```
