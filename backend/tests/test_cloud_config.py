"""
Cloud Configuration Discovery (Phase 2.5.5) — regression.

Uses the real Damn Vulnerable Bank example that exposed the gap:

    <string name="google_storage_bucket">damn-vulnerable-bank.appspot.com</string>

a bare hostname the http(s):// URL extractor never saw. Asserts that the static
detector finds Firebase/GCS storage buckets and endpoints, de-duplicates the same
bucket written multiple ways, and emits canonical "Cloud Configuration" findings.

Run: ``python -m pytest tests/test_cloud_config.py`` from the backend directory.
"""
from __future__ import annotations

import os
import tempfile

from analyzers import cloud_config


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _tree() -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = tmp.name
    # The motivating example — bare appspot.com hostname in strings.xml.
    _write(root, "res/values/strings.xml",
           '<resources>\n'
           '  <string name="google_storage_bucket">damn-vulnerable-bank.appspot.com</string>\n'
           '  <string name="firebase_database_url">https://dvba.firebaseio.com</string>\n'
           '</resources>\n')
    # Same bucket via gs:// in a config file → must collapse to ONE entry.
    _write(root, "assets/config.json",
           '{"bucket": "gs://damn-vulnerable-bank.appspot.com/uploads"}\n')
    # A Firebase app endpoint + a GCS bucket + a cloud function.
    _write(root, "res/values/extra.xml",
           '<resources>\n'
           '  <string name="hosting">dvba-prod.firebaseapp.com</string>\n'
           '  <string name="cdn">https://storage.googleapis.com/dvba-public-assets/x.png</string>\n'
           '  <string name="fn">https://us-central1-dvba.cloudfunctions.net/processPayment</string>\n'
           '</resources>\n')
    return tmp


def test_scan_finds_appspot_bucket():
    with _tree() as root:
        hits = cloud_config.scan(root)
    buckets = [h for h in hits if h["type"] == "FIREBASE_STORAGE_BUCKET"]
    assert any("damn-vulnerable-bank.appspot.com" in h["value"] for h in buckets), \
        f"appspot bucket not detected; hits={[h['value'] for h in hits]}"
    # firebaseio.com (Realtime DB) is intentionally NOT claimed here (it is a secret).
    assert all("firebaseio.com" not in h["value"] for h in hits)


def test_annotate_dedups_and_emits_findings():
    with _tree() as root:
        hits = cloud_config.scan(root)
    results = {"findings": [], "app_info": {"package": "com.app.dvba"}}
    results["_cloud_config_hits"] = hits
    cloud_config.annotate(results, platform="android")

    cc = results["cloud_config"]
    # The appspot bucket appears once even though it is written two ways (xml + gs://).
    dvb = [e for e in cc if "damn-vulnerable-bank" in e["value"]]
    assert len(dvb) == 1, f"expected one DVB bucket entry, got {[e['value'] for e in dvb]}"
    assert dvb[0]["project_id"] == "damn-vulnerable-bank"
    assert dvb[0]["occurrences"] >= 2  # seen in strings.xml and config.json

    # The other cloud endpoints were detected too.
    types = {e["type"] for e in cc}
    assert "FIREBASE_APP_ENDPOINT" in types
    assert "GCS_BUCKET" in types
    assert "GCP_CLOUD_FUNCTION" in types

    # Each entry produced exactly one canonical "Cloud Configuration" finding.
    cloud_findings = [f for f in results["findings"] if f.get("category") == "Cloud Configuration"]
    assert len(cloud_findings) == len(cc)
    titles = [f["title"] for f in cloud_findings]
    assert len(titles) == len(set(titles)), "duplicate cloud-configuration findings emitted"
    # The transient hits key never survives into the result blob.
    assert "_cloud_config_hits" not in results


def test_no_cloud_config_is_clean():
    with tempfile.TemporaryDirectory() as root:
        _write(root, "res/values/strings.xml", '<resources><string name="x">hello</string></resources>')
        hits = cloud_config.scan(root)
    assert hits == []
    results = {"findings": [], "_cloud_config_hits": hits}
    cloud_config.annotate(results, platform="android")
    assert results["cloud_config"] == []
    assert results["cloud_config_summary"]["total"] == 0
