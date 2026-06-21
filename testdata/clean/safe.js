// Normal HTTP + JSON handling. fetch() + JSON.parse() are everyday
// operations, not a tampering risk — THREAT-002 must NOT fire here.
async function loadConfig() {
  const data = await fetch("https://example.com/config");
  return JSON.parse(await data.text());
}

function parsePayload(body) {
  return JSON.parse(body);
}

module.exports = { loadConfig, parsePayload };
