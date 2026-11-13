
import math
import re

print("=" * 45)
print("       PASSWORD STRENGTH ANALYZER")
print("=" * 45)

password = input("Enter your password: ")

score = 0
pool = 0
suggestions = []

# Password length
length = len(password)

if length >= 8:
    score += 20
else:
    suggestions.append("Use at least 8 characters")

if length >= 12:
    score += 20

# Character checks
if re.search(r"[A-Z]", password):
    score += 15
    pool += 26
else:
    suggestions.append("Add uppercase letters")

if re.search(r"[a-z]", password):
    score += 15
    pool += 26
else:
    suggestions.append("Add lowercase letters")

if re.search(r"[0-9]", password):
    score += 15
    pool += 10
else:
    suggestions.append("Add numbers")

if re.search(r"[^A-Za-z0-9]", password):
    score += 15
    pool += 32
else:
    suggestions.append("Add special characters")

# Entropy calculation
entropy = length * math.log2(pool) if pool > 0 else 0

# Strength level
if score >= 90 and entropy >= 60:
    strength = "VERY STRONG"
elif score >= 70 and entropy >= 40:
    strength = "STRONG"
elif score >= 40:
    strength = "MEDIUM"
else:
    strength = "WEAK"

# Display results
print("\n" + "=" * 45)
print("             ANALYSIS RESULT")
print("=" * 45)

print(f"Password Length : {length} characters")
print(f"Security Score  : {score}/100")
print(f"Entropy         : {entropy:.2f} bits")
print(f"Strength        : {strength}")

print("=" * 45)

if suggestions:
    print("\nSuggestions:")
    for item in suggestions:
        print("-", item)
else:
    print("\nAll basic password checks passed!")

print("=" * 45)
