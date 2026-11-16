"""
password_generator.py
----------------------
Generates cryptographically secure random passwords using Python's
`secrets` module (never `random`, which is not safe for security purposes).
"""
import secrets
import string

# Characters that are visually similar and easy to confuse (l, 1, I, O, 0...)
SIMILAR_CHARS = "il1LoO0"
# Symbols some sites consider "ambiguous" / awkward to type
AMBIGUOUS_SYMBOLS = "{}[]()/\\'\"`~,;:.<>"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_numbers: bool = True,
    use_symbols: bool = True,
    exclude_similar: bool = False,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Build a character pool from the requested options, then generate a
    password using `secrets.choice`, guaranteeing at least one character
    from every selected category.
    """
    upper_pool = string.ascii_uppercase
    lower_pool = string.ascii_lowercase
    number_pool = string.digits
    symbol_pool = "!@#$%^&*_+-=?"

    if exclude_similar:
        upper_pool = "".join(c for c in upper_pool if c not in SIMILAR_CHARS)
        lower_pool = "".join(c for c in lower_pool if c not in SIMILAR_CHARS)
        number_pool = "".join(c for c in number_pool if c not in SIMILAR_CHARS)

    if exclude_ambiguous:
        symbol_pool = "".join(c for c in symbol_pool if c not in AMBIGUOUS_SYMBOLS)

    categories = []
    full_pool = ""

    if use_upper and upper_pool:
        categories.append(upper_pool)
        full_pool += upper_pool
    if use_lower and lower_pool:
        categories.append(lower_pool)
        full_pool += lower_pool
    if use_numbers and number_pool:
        categories.append(number_pool)
        full_pool += number_pool
    if use_symbols and symbol_pool:
        categories.append(symbol_pool)
        full_pool += symbol_pool

    if not full_pool:
        # Safety fallback: if the user disabled everything, default to
        # lowercase + numbers so we never crash.
        full_pool = string.ascii_lowercase + string.digits
        categories = [string.ascii_lowercase, string.digits]

    length = max(4, min(64, int(length)))

    # Guarantee at least one char from each selected category
    password_chars = [secrets.choice(cat) for cat in categories]

    while len(password_chars) < length:
        password_chars.append(secrets.choice(full_pool))

    # Shuffle securely so the guaranteed chars aren't always at the front
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars[:length])
