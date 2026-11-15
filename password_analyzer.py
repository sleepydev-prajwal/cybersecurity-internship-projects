"""
Password Strength Analyzer
Task 1 - checks length, complexity, common passwords, entropy,
and suggests a stronger alternative.
"""

import math
import re
import secrets
import string

# Small list of very common passwords (real tools use big lists like rockyou)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1",
    "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon",
    "india123", "admin123", "qwerty123", "111111", "123456789",
}


def calculate_entropy(password):
    """Entropy = length * log2(size of character pool). Higher = harder to crack."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool), 2)


def analyze(password):
    score = 0
    feedback = []

    # 1. Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ is better).")

    # 2. Complexity
    checks = [
        (r"[a-z]", "Add lowercase letters."),
        (r"[A-Z]", "Add uppercase letters."),
        (r"\d", "Add numbers."),
        (r"[^A-Za-z0-9]", "Add special characters (!@#$%)."),
    ]
    for pattern, tip in checks:
        if re.search(pattern, password):
            score += 1
        else:
            feedback.append(tip)

    # 3. Uniqueness / common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is a very common password. Never use it.")

    # 4. Repeated characters like aaa or 111
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times.")

    entropy = calculate_entropy(password)

    if score <= 2:
        label = "WEAK"
    elif score <= 4:
        label = "MEDIUM"
    else:
        label = "STRONG"

    return label, score, entropy, feedback


def suggest_strong_password(length=16):
    """Uses the secrets module (cryptographically secure, unlike random)."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*" for c in pwd)):
            return pwd


if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    label, score, entropy, feedback = analyze(pwd)

    print(f"\nStrength : {label}")
    print(f"Score    : {score}/6")
    print(f"Entropy  : {entropy} bits")

    if feedback:
        print("\nHow to improve:")
        for tip in feedback:
            print(f" - {tip}")

    if label != "STRONG":
        print(f"\nSuggested stronger password: {suggest_strong_password()}")
