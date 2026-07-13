"""RUN 17 — a user-input->storage taint flow surfaces at its calibrated severity.

'Promote the privacy taint finding' = make it VISIBLE, not raise its severity. A flow that
persists user-controlled data to SharedPrefs is a real MASVS-STORAGE data-handling signal, so it
is no longer pruned as a low-value taint sink. Logging and Intent sinks with non-PII sources stay
suppressed. The taint SEVERITY calibration is deliberately untouched (the flow stays LOW).
"""
from analyzers.finding_model import _is_low_value_taint


def _taint(sink_cat, source_cat="User Input"):
    return {"source": "TAINT", "taint_flow": {"sink_cat": sink_cat, "source_cat": source_cat}}


def test_storage_sink_taint_now_surfaces():
    # getStringExtra -> SharedPrefs.putString (flow #1). No longer low-value -> surfaces.
    assert _is_low_value_taint(_taint("Storage")) is False


def test_logging_and_intent_sinks_stay_suppressed():
    # Flow #3 (Intent) and any log sink with non-PII input remain noise.
    assert _is_low_value_taint(_taint("Intent")) is True
    assert _is_low_value_taint(_taint("Logging")) is True


def test_high_value_sinks_are_never_low_value():
    for sink in ("WebView", "SQL", "Network"):
        assert _is_low_value_taint(_taint(sink)) is False


def test_a_pii_source_keeps_even_a_logging_sink():
    # The PII-source rescue still works for the sinks that remain low-value.
    assert _is_low_value_taint(_taint("Logging", source_cat="location")) is False
