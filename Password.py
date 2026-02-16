import streamlit as st
import re
import random
import string
import math
from collections import Counter
import hashlib
import requests



COMMON_PASSWORDS = [
    "123456", "12345678", "123456789", "password", "password123",
    "qwerty", "qwerty123", "admin", "admin123", "welcome",
    "iloveyou", "letmein", "india123", "abcd1234", "123123",
    "000000", "111111", "abc123", "football", "monkey"
]


def detect_patterns(password):
    warnings = []

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        warnings.append("🚨 This is a very common password.")

    # Only digits check
    if password.isdigit():
        warnings.append("🚨 Password contains only numbers.")

    # Only letters check
    if password.isalpha():
        warnings.append("🚨 Password contains only letters.")

    # Repeated character check
    if len(set(password)) <= 2:
        warnings.append("🚨 Too many repeated characters.")

    # Sequential pattern check
    if "1234" in password or "abcd" in password.lower() or "qwerty" in password.lower():
        warnings.append("🚨 Contains common sequential pattern (1234 / abcd / qwerty).")

    # Same character repeated many times
    if re.search(r"(.)\1\1\1", password):
        warnings.append("🚨 Contains repeated characters like 'aaaa' or '1111'.")

    return warnings



def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5 = sha1_password[:5]
    tail = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    if response.status_code != 200:
        return -1  # error

    hashes = response.text.splitlines()

    for h in hashes:
        hash_suffix, count = h.split(":")
        if hash_suffix == tail:
            return int(count)

    return 0



def calculate_entropy(password):
    if len(password) == 0:
        return 0

    # 1️⃣ Charset-based entropy
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>/\[\]\-_+=;:]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    charset_entropy = len(password) * math.log2(charset_size)

    # 2️⃣ Shannon entropy (detect repetition)
    counts = Counter(password)
    shannon_entropy = 0
    for char in counts:
        p = counts[char] / len(password)
        shannon_entropy -= p * math.log2(p)

    shannon_total = shannon_entropy * len(password)

    # 3️⃣ Take minimum (best security estimate)
    final_entropy = min(charset_entropy, shannon_total)

    return round(final_entropy, 2)


def generate_password(length=12, use_upper=True, use_digits=True, use_special=True):
    chars = string.ascii_lowercase

    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += "!@#$%^&*()_+-={}[]|:;<>,.?/"

    if chars == string.ascii_lowercase:
        return "Please select at least one option!"

    password = "".join(random.choice(chars) for _ in range(length))
    return password


def check_password_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 10
    else:
        suggestions.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 10

    if re.search(r"[A-Z]", password):
        score += 20
    else:
        suggestions.append("Add at least one uppercase letter (A-Z).")

    if re.search(r"[a-z]", password):
        score += 20
    else:
        suggestions.append("Add at least one lowercase letter (a-z).")

    if re.search(r"[0-9]", password):
        score += 20
    else:
        suggestions.append("Add at least one number (0-9).")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 20
    else:
        suggestions.append("Add at least one special character (!@#$...).")

    if score >= 90:
        strength = "Very Strong 💪"
        color = "green"
    elif score >= 80:
        strength = "Strong 🎉"
        color = "yellow"
    elif score >= 60:
        strength = "Medium 😐"
        color = "orange"
    else:
        strength = "Weak ❌"
        color = "red"

    return score, strength, suggestions, color


st.set_page_config(page_title="Password Strength Checker", page_icon="🔐", layout="centered")





# FOR UI PRERSENTATION
st.title("🔐 Password Strength Checker")
st.write("Check how secure your password is and get suggestions to improve it.")
st.text("Developed By Shreya Patra :)")

# FOR PASSWORD SUGGETION

st.subheader("🎲 Generate Strong Password")

length = st.slider("Select Password Length", 6, 20, 12)

use_upper = st.checkbox("Include Uppercase Letters (A-Z)", value=True)
use_digits = st.checkbox("Include Digits (0-9)", value=True)
use_special = st.checkbox("Include Special Characters (!@#$)", value=True)

if st.button("Generate Password 🔥"):
    generated = generate_password(length, use_upper, use_digits, use_special)
    st.code(generated)

st.info("💡 Tip: Avoid names, birthdays, and predictable keyboard patterns.")
password = st.text_input("Enter your password", type="password")

if password:
    # ---------------- SCORE ----------------
    score, strength, suggestions, color = check_password_strength(password)

    st.subheader("📊 Strength Result")
    st.markdown(f"### **Strength: :{color}[{strength}]**")
    st.progress(score / 100)
    st.write(f"✅ Score: **{score}/100**")

    if suggestions:
        st.subheader("💡 Suggestions to Improve")
        for s in suggestions:
            st.write("🔸", s)
    else:
        st.success("🎉 Great! Your password is very strong!")

    # ---------------- ENTROPY ----------------
    entropy = calculate_entropy(password)

    st.subheader("🔐 Password Entropy")
    st.write(f"📌 Entropy: **{entropy} bits**")

    if entropy < 25:
        st.error("❌ Very Weak")
    elif entropy < 40:
        st.warning("⚠️ Medium")
    elif entropy < 55:
        st.success("✅ Strong")
    else:
        st.success("💪 Very Strong")

    # ---------------- BREACH CHECK ----------------
    st.subheader("🌐 Breach Check (Leaked Password Test)")

    breach_count = check_pwned_password(password)

    if breach_count == -1:
        st.warning("⚠️ Unable to connect to breach database right now.")
    elif breach_count == 0:
        st.success("✅ Good news! This password was NOT found in any known data breach.")
    else:
        st.error(f"🚨 WARNING! This password was found in **{breach_count} breaches**. Do NOT use it!")

    # ---------------- PATTERN DETECTION ----------------
    st.subheader("🛑 Common Pattern Detection")

    pattern_warnings = detect_patterns(password)

    if pattern_warnings:
        for w in pattern_warnings:
            st.error(w)
    else:
        st.success("✅ No common patterns detected.")


else:
    st.info("👆 Enter a password above to check its strength.")
