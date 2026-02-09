// THREAT-001: Spoofing risk — hardcoded credentials.
const password = "1234";
const bypassAuth = true;

function checkAuth(token) {
  // THREAT-001: Hardcoded token comparison.
  if (token === "static-secret") {
    return true;
  }
  return false;
}

// THREAT-002: Tampering risk — no integrity verification.
async function loadConfig() {
  const data = await fetch("https://example.com/config");
  const config = JSON.parse(await data.text());
  return config;
}

// THREAT-003: Repudiation risk — security actions without logging.
async function deleteUser(userId) {
  // No audit log for user deletion.
  await db.users.delete(userId);
}

async function handleLogin(credentials) {
  // No logging of login attempts.
  return await auth.verify(credentials);
}

// THREAT-004: Information disclosure — leaking sensitive data.
function errorHandler(err, req, res, next) {
  console.log("Error with apiKey:", process.env.API_KEY);
  res.json({ error: err.stack });
}

// THREAT-005: Elevation of privilege — privilege escalation.
const child_process = require('child_process');
function runAsRoot() {
  child_process.exec("sudo apt-get install something");
  const role = "superadmin";
}
