# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0

- fix(THREAT-002): narrow tampering rule to genuine sinks. The previous rule
  matched `json.Unmarshal` / `io.ReadAll` / `http.Get` / `requests.get` /
  `JSON.parse` / `fetch` — everyday operations — making it pure noise. It now
  flags only unsafe deserializers (`pickle`, unsafe `yaml.load`) and dynamic
  code execution (`eval`, `new Function`).
- feat: per-rule mitigation patterns to suppress known-safe variants RE2
  cannot express via negative lookahead (e.g. `yaml.load(..., Loader=...)`).
- test: add `testdata/clean/` negative fixtures and a false-positive guard
  asserting normal data handling produces zero THREAT-002 findings.

- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

