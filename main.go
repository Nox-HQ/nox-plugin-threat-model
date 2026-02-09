package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// threatRule defines a single STRIDE-based threat detection rule with compiled
// regex patterns keyed by file extension.
type threatRule struct {
	ID         string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	Category   string
	Patterns   map[string][]*regexp.Regexp // extension -> compiled patterns
}

// Compiled regex patterns for each rule, grouped by language extension.
//
// THREAT-001: Spoofing risk — authentication bypass patterns.
// THREAT-002: Tampering risk — missing integrity checks.
// THREAT-003: Repudiation risk — insufficient logging.
// THREAT-004: Information disclosure — sensitive data exposure.
// THREAT-005: Elevation of privilege — privilege escalation patterns.
var rules = []threatRule{
	{
		ID:         "THREAT-001",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Spoofing risk: authentication bypass pattern detected",
		Category:   "spoofing",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]=?\s*["'][^"']{0,4}["']`),
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]=?\s*["'](?:password|admin|root|test|1234|changeme)["']`),
				regexp.MustCompile(`(?i)(?:skipAuth|bypassAuth|noAuth|authDisabled|disableAuth)\s*[:=]=?\s*true`),
				regexp.MustCompile(`(?i)if\s+.*(?:token|jwt|auth)\s*==\s*["']`),
			},
			".py": {
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*=\s*["'][^"']{0,4}["']`),
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*=\s*["'](?:password|admin|root|test|1234|changeme)["']`),
				regexp.MustCompile(`(?i)(?:skip_auth|bypass_auth|no_auth|auth_disabled|disable_auth)\s*=\s*True`),
				regexp.MustCompile(`(?i)if\s+.*(?:token|jwt|auth)\s*==\s*["']`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{0,4}['"]`),
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"](?:password|admin|root|test|1234|changeme)['"]`),
				regexp.MustCompile(`(?i)(?:skipAuth|bypassAuth|noAuth|authDisabled|disableAuth)\s*[:=]\s*true`),
				regexp.MustCompile(`(?i)if\s*\(.*(?:token|jwt|auth)\s*===?\s*['"]`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{0,4}['"]`),
				regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"](?:password|admin|root|test|1234|changeme)['"]`),
				regexp.MustCompile(`(?i)(?:skipAuth|bypassAuth|noAuth|authDisabled|disableAuth)\s*[:=]\s*true`),
				regexp.MustCompile(`(?i)if\s*\(.*(?:token|jwt|auth)\s*===?\s*['"]`),
			},
		},
	},
	{
		ID:         "THREAT-002",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Tampering risk: missing integrity check detected",
		Category:   "tampering",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)(?:http\.Get|http\.Post|http\.Do)\s*\([^)]*\)\s*$`),
				regexp.MustCompile(`(?i)io(?:util)?\.ReadAll\s*\(`),
				regexp.MustCompile(`(?i)json\.(?:Unmarshal|Decode)\s*\(`),
			},
			".py": {
				regexp.MustCompile(`(?i)requests\.(?:get|post|put|delete)\s*\(`),
				regexp.MustCompile(`(?i)json\.loads?\s*\(`),
				regexp.MustCompile(`(?i)pickle\.loads?\s*\(`),
			},
			".js": {
				regexp.MustCompile(`(?i)fetch\s*\(\s*['"]`),
				regexp.MustCompile(`(?i)JSON\.parse\s*\(`),
				regexp.MustCompile(`(?i)eval\s*\(`),
			},
			".ts": {
				regexp.MustCompile(`(?i)fetch\s*\(\s*['"]`),
				regexp.MustCompile(`(?i)JSON\.parse\s*\(`),
				regexp.MustCompile(`(?i)eval\s*\(`),
			},
		},
	},
	{
		ID:         "THREAT-003",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Repudiation risk: security action without audit logging",
		Category:   "repudiation",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)func\s+(?:\w+\s+)?(?:Delete|Remove|Update|Create|Grant|Revoke|Assign)(?:User|Role|Permission|Admin|Access)\s*\(`),
				regexp.MustCompile(`(?i)func\s+(?:\w+\s+)?(?:handle|process)(?:Login|Logout|Auth|Payment|Transfer)\s*\(`),
			},
			".py": {
				regexp.MustCompile(`(?i)def\s+(?:delete|remove|update|create|grant|revoke|assign)_?(?:user|role|permission|admin|access)\s*\(`),
				regexp.MustCompile(`(?i)def\s+(?:handle|process)_?(?:login|logout|auth|payment|transfer)\s*\(`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:async\s+)?function\s+(?:delete|remove|update|create|grant|revoke|assign)(?:User|Role|Permission|Admin|Access)\s*\(`),
				regexp.MustCompile(`(?i)(?:async\s+)?function\s+(?:handle|process)(?:Login|Logout|Auth|Payment|Transfer)\s*\(`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:async\s+)?function\s+(?:delete|remove|update|create|grant|revoke|assign)(?:User|Role|Permission|Admin|Access)\s*\(`),
				regexp.MustCompile(`(?i)(?:async\s+)?function\s+(?:handle|process)(?:Login|Logout|Auth|Payment|Transfer)\s*\(`),
			},
		},
	},
	{
		ID:         "THREAT-004",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Information disclosure: sensitive data exposure pattern detected",
		Category:   "information-disclosure",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)fmt\.(?:Fprintf|Printf|Sprintf)\s*\([^)]*(?:err|error|stack|trace|password|secret|token|key)`),
				regexp.MustCompile(`(?i)http\.Error\s*\(\s*\w+\s*,\s*(?:err|error)\.Error\(\)`),
				regexp.MustCompile(`(?i)debug\.(?:PrintStack|Stack)\s*\(`),
				regexp.MustCompile(`(?i)\.Write\s*\(\s*\[\]byte\s*\(\s*(?:err|error)\.Error\(\)`),
			},
			".py": {
				regexp.MustCompile(`(?i)traceback\.(?:print_exc|format_exc|print_tb)\s*\(`),
				regexp.MustCompile(`(?i)(?:print|logging\.(?:debug|info))\s*\(.*(?:password|secret|token|api_key|private_key)`),
				regexp.MustCompile(`(?i)return\s+.*(?:str\(e\)|repr\(e\)|traceback|stack_trace)`),
				regexp.MustCompile(`(?i)(?:DEBUG|VERBOSE)\s*=\s*True`),
			},
			".js": {
				regexp.MustCompile(`(?i)console\.(?:log|debug|info)\s*\(.*(?:password|secret|token|apiKey|privateKey)`),
				regexp.MustCompile(`(?i)res(?:ponse)?\.(?:send|json)\s*\(\s*\{\s*(?:error|err|message)\s*:\s*(?:err|error)(?:\.message|\.stack)?`),
				regexp.MustCompile(`(?i)(?:err|error)\.stack`),
				regexp.MustCompile(`(?i)res(?:ponse)?\.(?:send|json)\s*\(\s*(?:err|error)\.stack`),
			},
			".ts": {
				regexp.MustCompile(`(?i)console\.(?:log|debug|info)\s*\(.*(?:password|secret|token|apiKey|privateKey)`),
				regexp.MustCompile(`(?i)res(?:ponse)?\.(?:send|json)\s*\(\s*\{\s*(?:error|err|message)\s*:\s*(?:err|error)(?:\.message|\.stack)?`),
				regexp.MustCompile(`(?i)(?:err|error)\.stack`),
				regexp.MustCompile(`(?i)res(?:ponse)?\.(?:send|json)\s*\(\s*(?:err|error)\.stack`),
			},
		},
	},
	{
		ID:         "THREAT-005",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Elevation of privilege: privilege escalation pattern detected",
		Category:   "elevation-of-privilege",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)syscall\.(?:Setuid|Setgid|Seteuid|Setegid)\s*\(`),
				regexp.MustCompile(`(?i)exec\.Command\s*\(\s*["'](?:sudo|su|chmod|chown)["']`),
				regexp.MustCompile(`(?i)(?:role|isAdmin|is_admin)\s*[:=]=?\s*["'](?:admin|root|superuser|superadmin)["']`),
				regexp.MustCompile(`(?i)\.(?:SetRole|setRole|set_role|assignRole|assign_role)\s*\(\s*["'](?:admin|root|superuser)["']`),
			},
			".py": {
				regexp.MustCompile(`(?i)os\.(?:setuid|setgid|seteuid|setegid)\s*\(`),
				regexp.MustCompile(`(?i)subprocess\.(?:call|run|Popen)\s*\(\s*\[?\s*["'](?:sudo|su|chmod|chown)["']`),
				regexp.MustCompile(`(?i)(?:role|is_admin)\s*=\s*["'](?:admin|root|superuser|superadmin)["']`),
				regexp.MustCompile(`(?i)\.(?:set_role|assign_role)\s*\(\s*["'](?:admin|root|superuser)["']`),
			},
			".js": {
				regexp.MustCompile(`(?i)child_process\.(?:exec|spawn|execSync)\s*\(\s*['"](?:sudo|su|chmod|chown)`),
				regexp.MustCompile(`(?i)(?:role|isAdmin)\s*[:=]\s*['"](?:admin|root|superuser|superadmin)['"]`),
				regexp.MustCompile(`(?i)\.(?:setRole|assignRole)\s*\(\s*['"](?:admin|root|superuser)['"]`),
				regexp.MustCompile(`(?i)process\.setuid\s*\(`),
			},
			".ts": {
				regexp.MustCompile(`(?i)child_process\.(?:exec|spawn|execSync)\s*\(\s*['"](?:sudo|su|chmod|chown)`),
				regexp.MustCompile(`(?i)(?:role|isAdmin)\s*[:=]\s*['"](?:admin|root|superuser|superadmin)['"]`),
				regexp.MustCompile(`(?i)\.(?:setRole|assignRole)\s*\(\s*['"](?:admin|root|superuser)['"]`),
				regexp.MustCompile(`(?i)process\.setuid\s*\(`),
			},
		},
	},
}

// sourceExtensions lists file extensions to scan.
var sourceExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs to skip during walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/threat-model", version).
		Capability("threat-model", "STRIDE-based threat pattern detection in source code").
		Tool("scan", "Detect spoofing, tampering, repudiation, information disclosure, and elevation of privilege patterns", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !sourceExtensions[ext] {
			return nil
		}

		return scanFile(ctx, resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// scanFile reads a file and checks each line against all threat rules.
func scanFile(_ context.Context, resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// For THREAT-003 (repudiation), track whether file has logging.
	hasLogging := false
	var lines []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if reLogging.MatchString(line) {
			hasLogging = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for lineNum, line := range lines {
		for i := range rules {
			rule := &rules[i]
			patterns, ok := rule.Patterns[ext]
			if !ok {
				continue
			}

			// For THREAT-003, only flag if the file lacks logging.
			if rule.ID == "THREAT-003" && hasLogging {
				continue
			}

			matched := false
			for _, pattern := range patterns {
				if pattern.MatchString(line) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			resp.Finding(
				rule.ID,
				rule.Severity,
				rule.Confidence,
				fmt.Sprintf("%s: %s", rule.Message, strings.TrimSpace(line)),
			).
				At(filePath, lineNum+1, lineNum+1).
				WithMetadata("category", rule.Category).
				WithMetadata("language", extToLanguage(ext)).
				Done()
		}
	}

	return nil
}

// reLogging matches common logging patterns that indicate audit logging is present.
var reLogging = regexp.MustCompile(`(?i)(?:log\.(?:Info|Warn|Error|Printf|Println|Debug|Audit)|logger\.|logging\.|audit_log|auditLog|console\.(?:log|warn|error))`)

// extToLanguage maps file extensions to human-readable language names.
func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-threat-model: %v\n", err)
		os.Exit(1)
	}
}
