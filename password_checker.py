"""
password_checker.py
--------------------
Handles all password STRENGTH analysis:
  - character composition counts
  - entropy
  - dictionary / sequential / keyboard-pattern detection
  - strength score (0-100) and strength label
  - estimated crack time

Uses the `zxcvbn` library (the same strength-estimation library used by
Dropbox) for a realistic crack-time / score baseline, then layers our own
extra composition stats on top so the dashboard has plenty to show.
"""
import re

from zxcvbn import zxcvbn

from utils import (
    calculate_entropy,
    contains_dictionary_word,
    has_sequential_chars,
    has_keyboard_pattern,
    count_repeated_chars,
    format_seconds,
)


STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def _score_to_label(score_0_100: int) -> str:
    if score_0_100 < 20:
        return "Very Weak"
    if score_0_100 < 40:
        return "Weak"
    if score_0_100 < 60:
        return "Fair"
    if score_0_100 < 80:
        return "Strong"
    return "Very Strong"


def analyze_password(password: str) -> dict:
    """
    Run a full analysis on the given password and return a dictionary
    with every field the dashboard needs.
    """
    if password is None:
        password = ""

    # --- zxcvbn baseline (industry-style estimate) -----------------------
    zx = zxcvbn(password) if password else {
        "score": 0,
        "crack_times_seconds": {"offline_slow_hashing_1e4_per_second": 0},
        "feedback": {"suggestions": [], "warning": ""},
    }
    zx_score = zx.get("score", 0)  # 0-4 scale from zxcvbn
    crack_seconds = zx.get("crack_times_seconds", {}).get(
        "offline_slow_hashing_1e4_per_second", 0
    )
    try:
        crack_seconds = float(crack_seconds)
    except (TypeError, ValueError):
        crack_seconds = 0.0

    # --- composition counts ----------------------------------------------
    length = len(password)
    upper_count = sum(1 for c in password if c.isupper())
    lower_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    special_count = sum(1 for c in password if not c.isalnum())
    unique_chars = len(set(password))
    repeated_chars = count_repeated_chars(password)

    entropy = calculate_entropy(password)
    dictionary_hits = contains_dictionary_word(password)
    is_sequential = has_sequential_chars(password)
    is_keyboard_pattern = has_keyboard_pattern(password)

    # --- our own 0-100 composite score -------------------------------------
    # Blend zxcvbn's 0-4 score (scaled to 0-80) with a small bonus/penalty
    # layer so the score visibly reacts to entropy & bad patterns too.
    base_score = zx_score * 20  # 0, 20, 40, 60, 80
    bonus = 0
    bonus += min(entropy / 4, 20)  # up to +20 for high entropy
    penalty = 0
    if dictionary_hits:
        penalty += 15
    if is_sequential:
        penalty += 10
    if is_keyboard_pattern:
        penalty += 10
    if repeated_chars > length / 2 and length > 0:
        penalty += 10
    if length < 8:
        penalty += 15

    composite = base_score + bonus - penalty
    composite = max(0, min(100, round(composite)))

    strength_label = _score_to_label(composite)

    result = {
        "password_length": length,
        "strength_score": composite,
        "strength_label": strength_label,
        "entropy": entropy,
        "uppercase_count": upper_count,
        "lowercase_count": lower_count,
        "number_count": digit_count,
        "special_count": special_count,
        "unique_characters": unique_chars,
        "repeated_characters": repeated_chars,
        "dictionary_words_found": dictionary_hits,
        "is_dictionary_word": len(dictionary_hits) > 0,
        "is_sequential": is_sequential,
        "is_keyboard_pattern": is_keyboard_pattern,
        "crack_time_seconds": crack_seconds,
        "crack_time_display": format_seconds(crack_seconds),
        "zxcvbn_score": zx_score,
    }
    return result


def get_security_suggestions(analysis: dict) -> list:
    """
    Build a dynamic list of suggestions based on the analysis results.
    """
    suggestions = []

    if analysis["password_length"] < 12:
        suggestions.append("Increase password length to at least 12 characters.")
    if analysis["uppercase_count"] == 0:
        suggestions.append("Add uppercase letters.")
    if analysis["lowercase_count"] == 0:
        suggestions.append("Add lowercase letters.")
    if analysis["number_count"] == 0:
        suggestions.append("Add numbers.")
    if analysis["special_count"] == 0:
        suggestions.append("Add special symbols such as ! @ # $ %.")
    if analysis["is_dictionary_word"]:
        suggestions.append("Avoid common dictionary words.")
    if analysis["is_sequential"]:
        suggestions.append("Avoid sequential characters like 'abcd' or '1234'.")
    if analysis["is_keyboard_pattern"]:
        suggestions.append("Avoid keyboard patterns such as 'qwerty' or 'asdf'.")
    if analysis["repeated_characters"] > 3:
        suggestions.append("Avoid repeated characters.")

    # Always-relevant general advice
    suggestions.append("Avoid using personal information (name, birthdate).")
    suggestions.append("Never reuse the same password across multiple sites.")
    suggestions.append("Use Multi-Factor Authentication (MFA) wherever possible.")
    suggestions.append("Use a trusted password manager to store your passwords.")

    return suggestions
