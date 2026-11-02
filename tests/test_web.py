import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from ccaudit import web


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def post(base, payload):
    req = urllib.request.Request(base + "/api/scan", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_index_and_meta(server):
    assert b"Cloud Compliance Automator" in urllib.request.urlopen(server + "/").read()
    meta = json.loads(urllib.request.urlopen(server + "/api/meta").read())
    assert "insecure_account.json" in meta["samples"]
    assert {f["id"] for f in meta["frameworks"]} == {"iso27001", "soc2", "dpdp"}


def test_scan_sample(server):
    code, data = post(server, {"sample": "insecure_account.json", "frameworks": ["dpdp"], "allowed_regions": "india"})
    assert code == 200
    assert "India DPDP Act" in data["html"] and "ISO/IEC 27001" not in data["html"]


def test_scan_uploaded_snapshot(server, secure):
    code, data = post(server, {"snapshot": secure, "allowed_regions": "india"})
    assert code == 200 and "100%" in data["html"]


@pytest.mark.parametrize("payload", [
    {"sample": "../pyproject.toml"},
    {"sample": "nope.json"},
    {"snapshot": []},
    {"snapshot": {"s3_buckets": "x"}},
    {"sample": "secure_account.json", "frameworks": ["hipaa"]},
    {"sample": "secure_account.json", "max_key_age": "ninety"},
    {"sample": "secure_account.json", "min_backup_days": -1},
    {"sample": "secure_account.json", "allowed_regions": 5},
])
def test_bad_requests_get_400(server, payload):
    code, data = post(server, payload)
    assert code == 400 and "error" in data


def test_invalid_json_body(server):
    req = urllib.request.Request(server + "/api/scan", data=b"{oops")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 400


def test_unknown_path_404(server):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(server + "/etc/passwd")
    assert e.value.code == 404
