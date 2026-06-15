"""Password screening (NIST SP 800-63B aligned).

Modern guidance (NIST 800-63B §5.1.1) is *not* composition rules (forced
upper/lower/digit/symbol) — those push users to predictable patterns. It is:
a length floor, a generous length ceiling, and **screening against known-bad
passwords** (common/breached strings and context-specific words). That's what
this module does, with a bundled offline list (no network dependency at
sign-up time).

`validate_password` raises `ValueError(reason)` with a user-facing message; the
callers turn that into an HTTP 400. The bundled list catches the genuinely
common exact strings — operators wanting full breach-corpus screening can grow
`COMMON_PASSWORDS` or wire a k-anonymity HIBP check behind the same function.
"""

MIN_LENGTH = 8
# PBKDF2 hashes the whole input; an unbounded password is a cheap DoS lever
# (and nothing legitimate needs hundreds of characters). NIST allows >=64.
MAX_LENGTH = 256

# The most common passwords seen across public breach-frequency corpora
# (rockyou / SecLists top entries). Compared case-insensitively as *exact*
# strings — screening, not a substring blocklist, so strong passphrases that
# merely contain a common word still pass.
COMMON_PASSWORDS = frozenset({
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123", "password1",
    "password123", "password12", "passwords", "admin", "administrator",
    "root", "toor", "letmein", "letmein1", "welcome", "welcome1", "welcome123",
    "monkey", "dragon", "sunshine", "iloveyou", "iloveyou1", "princess",
    "princess1", "football", "football1", "baseball", "baseball1", "master",
    "login", "passw0rd", "p@ssw0rd", "p@ssword", "1q2w3e4r", "1qaz2wsx",
    "zaq12wsx", "qazwsx", "trustno1", "superman", "batman", "michael",
    "jordan", "harley", "hunter", "hunter2", "ranger", "soccer", "hockey",
    "killer", "george", "andrew", "charlie", "robert", "thomas", "hello",
    "hello123", "freedom", "whatever", "shadow", "ashley", "bailey",
    "jennifer", "hannah", "michelle", "daniel", "jessica", "computer",
    "internet", "samsung", "google", "starwars", "cheese", "summer",
    "winter", "autumn", "spring", "ginger", "maggie", "mustang", "access",
    "flower", "qwe123", "asd123", "zxcvbn", "zxcvbnm", "asdfgh", "asdfghjkl",
    "000000", "111111", "222222", "333333", "444444", "555555", "666666",
    "777777", "888888", "999999", "654321", "123123", "121212", "112233",
    "159753", "147258369", "abcd1234", "a1b2c3d4", "changeme", "default",
    "guest", "test", "test123", "demo", "temp", "secret", "secret1",
    "admin123", "root123", "system", "manager", "qwerty1", "loveme",
    "iloveu", "password!", "p@ssw0rd!", "passw0rd1",
})


def validate_password(password: str, *, email: str | None = None,
                      name: str | None = None) -> None:
    """Raise ValueError(reason) if `password` fails policy; return None if it's
    acceptable. Screens length, the common-password list, and trivial
    self-references (the password being your own email or name)."""
    pw = password or ""
    if len(pw) < MIN_LENGTH:
        raise ValueError(f"Password must be at least {MIN_LENGTH} characters")
    if len(pw) > MAX_LENGTH:
        raise ValueError(f"Password must be {MAX_LENGTH} characters or fewer")
    low = pw.lower()
    if low in COMMON_PASSWORDS:
        raise ValueError("This password is too common — choose something less guessable")
    # Context-specific screening: the password must not simply *be* the account
    # identity (a frequent, trivially-guessable choice).
    refs = set()
    if email:
        e = email.strip().lower()
        refs.add(e)
        refs.add(e.split("@", 1)[0])
    if name:
        refs.add(name.strip().lower())
    refs.discard("")
    if low in refs:
        raise ValueError("Password must not be your name or email address")
