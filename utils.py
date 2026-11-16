"""
utils.py
--------
Small shared helper functions used across the project.
Kept deliberately simple and beginner-friendly for viva explanation.
"""
import math
import re


# A short list of keyboard rows used for keyboard-walk pattern detection.
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# A compact list of dictionary words used ONLY for the "dictionary word
# detection" feature shown on the dashboard (kept small on purpose - this
# is a teaching demo, not a full dictionary attack tool).
COMMON_DICTIONARY_WORDS = [
    "password", "welcome", "login", "admin", "letmein", "dragon", "monkey",
    "football", "baseball", "master", "superman", "batman", "sunshine",
    "princess", "iloveyou", "trustno1", "shadow", "hunter", "summer",
    "winter", "spring", "autumn", "computer", "internet", "security",
    "freedom", "family", "friend", "money", "happy", "love", "hate",
    "flower", "tiger", "eagle", "cricket", "hockey", "college", "school",
]


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon-style password entropy in bits.

    entropy = length * log2(pool_size)

    pool_size grows depending on which character categories are used
    (lowercase, uppercase, digits, symbols). This is the standard,
    simple way entropy is taught in security courses.
    """
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32  # approx count of common symbols

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def contains_dictionary_word(password: str) -> list:
    """Return the list of common dictionary words found inside the password."""
    lowered = password.lower()
    found = [w for w in COMMON_DICTIONARY_WORDS if w in lowered]
    return found


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """
    Detect simple ascending/descending sequences like 'abcd', '1234', 'dcba'.
    """
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        if len(chunk) < run_length:
            continue
        ascending = all(
            ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)
        )
        descending = all(
            ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)
        )
        if ascending or descending:
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 3) -> bool:
    """Detect keyboard-walk patterns like 'qwerty', 'asdf', '1234' using row scans."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lowered:
                return True
            if chunk[::-1] in lowered:
                return True
    return False


def count_repeated_chars(password: str) -> int:
    """Count how many characters appear more than once in the password."""
    seen = {}
    for ch in password:
        seen[ch] = seen.get(ch, 0) + 1
    return sum(1 for v in seen.values() if v > 1)


def format_seconds(seconds: float) -> str:
    """Turn a raw number of seconds into a friendly human string."""
    if seconds < 1:
        return "Less than 1 second"

    minute = 60
    hour = minute * 60
    day = hour * 24
    month = day * 30
    year = day * 365

    if seconds < minute:
        return f"{int(seconds)} seconds"
    if seconds < hour:
        return f"{int(seconds // minute)} minutes"
    if seconds < day:
        return f"{int(seconds // hour)} hours"
    if seconds < month:
        return f"{int(seconds // day)} days"
    if seconds < year:
        return f"{int(seconds // month)} months"

    years = seconds / year
    if years < 1000:
        return f"{int(years)} years"
    if years < 1_000_000:
        return f"{round(years / 1000, 1)} thousand years"
    if years < 1_000_000_000:
        return f"{round(years / 1_000_000, 1)} million years"
    return f"{round(years / 1_000_000_000, 1)} billion years"
