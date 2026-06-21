import json
import requests
import yaml


# Normal HTTP + JSON handling. Fetching a URL and parsing JSON is not a
# tampering risk on its own — THREAT-002 must NOT fire here.
def fetch_remote_data():
    response = requests.get("https://example.com/api/data")
    return json.loads(response.text)


# Safe YAML parsing with an explicit safe loader must NOT be flagged.
def load_settings(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)


def parse_payload(body):
    return json.loads(body)
