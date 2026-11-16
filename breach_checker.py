"""
breach_checker.py
------------------
Offline, local-only breach detection.

IMPORTANT: This module never makes a network call. It loads
breach_data.json (a local demo dataset of 10,000+ common leaked-style
passwords) once at startup and performs a simple in-memory lookup.

This is for EDUCATIONAL DEMONSTRATION ONLY - it is not connected to any
real breach intelligence feed such as Have I Been Pwned.
"""
import json
import os

_DATA_PATH = os.path.join(os.path.dirname(__file__), "breach_data.json")

_breach_lookup = {}
_meta = {}


def _load_data():
    global _breach_lookup, _meta
    if _breach_lookup:
        return
    with open(_DATA_PATH, "r") as f:
        data = json.load(f)
    _meta = data.get("meta", {})
    for entry in data.get("breached_passwords", []):
        _breach_lookup[entry["password"].lower()] = entry


def check_breach(password: str) -> dict:
    """
    Look up a password (case-insensitive) in the local offline dataset.

    Returns a dict describing whether it was found, and if so, its risk
    details. Always includes a `disclaimer` field reminding the user this
    is a local, offline demonstration only.
    """
    _load_data()

    disclaimer = (
        "This is only an offline demonstration using a local dataset of "
        "common leaked-style passwords. It is NOT a live breach intelligence "
        "service."
    )

    if not password:
        return {
            "found": False,
            "message": "No known breach found in local dataset.",
            "disclaimer": disclaimer,
        }

    entry = _breach_lookup.get(password.lower())
    if entry:
        return {
            "found": True,
            "message": "Password Found in Breach Dataset",
            "risk_level": entry["risk_level"],
            "breach_year": entry["breach_year"],
            "exposure_count": entry["exposure_count"],
            "source_name": entry["source_name"],
            "disclaimer": disclaimer,
        }

    return {
        "found": False,
        "message": "No known breach found in local dataset.",
        "disclaimer": disclaimer,
    }


def dataset_size() -> int:
    _load_data()
    return len(_breach_lookup)
