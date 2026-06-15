"""
Cortex safe JSON utilities.
Ensures results dict is always cleanly JSON-serializable before sending to frontend.
"""
import json
from xml.etree.ElementTree import Element


def make_json_safe(obj, _depth=0):
    """
    Recursively convert any object to JSON-safe primitives.
    Handles: Element, set, bytes, non-serializable objects.
    """
    if _depth > 30:
        return str(obj)[:200]

    if obj is None or isinstance(obj, (bool, int, float)):
        return obj

    if isinstance(obj, str):
        # Ensure valid UTF-8 (some androguard strings can have issues)
        try:
            return obj.encode("utf-8", "replace").decode("utf-8")
        except Exception:
            return ""

    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", "replace")
        except Exception:
            return ""

    if isinstance(obj, Element):
        # XML Element — convert to string representation
        try:
            from xml.etree.ElementTree import tostring
            return tostring(obj, encoding="unicode")
        except Exception:
            return str(obj)

    if isinstance(obj, set):
        return sorted(make_json_safe(v, _depth + 1) for v in obj)

    if isinstance(obj, (list, tuple)):
        return [make_json_safe(v, _depth + 1) for v in obj]

    if isinstance(obj, dict):
        return {
            str(k): make_json_safe(v, _depth + 1)
            for k, v in obj.items()
        }

    # Fallback: try JSON round-trip, else str
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)[:500]


def safe_results(results: dict) -> dict:
    """Clean the full results dict for safe JSON serialization."""
    return make_json_safe(results)
