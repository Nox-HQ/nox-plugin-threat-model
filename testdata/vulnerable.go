package vulnerable

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime/debug"
)

// THREAT-001: Spoofing risk — hardcoded credentials.
var adminPassword = "admin"
var skipAuth = true

func checkToken(token string) bool {
	// THREAT-001: Spoofing risk — weak auth check with hardcoded token.
	if token == "hardcoded-secret-token" {
		return true
	}
	return false
}

// THREAT-002: Tampering risk — no integrity check on external data.
func fetchData() {
	resp, _ := http.Get("http://example.com/data")
	_ = resp
}

// THREAT-003: Repudiation risk — security action without audit logging.
func DeleteUser(userID string) error {
	// No logging of this security-critical action.
	return nil
}

func GrantPermission(userID, permission string) error {
	// No audit trail for privilege changes.
	return nil
}

// THREAT-004: Information disclosure — exposing error details.
func handleError(w http.ResponseWriter, err error) {
	// Leaks internal error details to the client.
	http.Error(w, err.Error(), 500)
	debug.PrintStack()
	fmt.Fprintf(w, "Internal error: %v with token %s", err, "secret-token-value")
}

// THREAT-005: Elevation of privilege — privilege escalation patterns.
func escalatePrivilege() {
	exec.Command("sudo", "rm", "-rf", "/")
	role := "admin"
	_ = role
}

func assignAdminRole(userID string) {
	isAdmin := "superadmin"
	_ = isAdmin
}
