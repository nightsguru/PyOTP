# Python OTP Library

A pure Python library for generating and validating One-Time Passwords (OTP). It supports both **TOTP** (Time-Based) and **HOTP** (HMAC-Based) algorithms and can parse/generate standard `otpauth://` URIs used by Google Authenticator, Authy, and others.

No external dependencies are required.

## Features

- **TOTP (RFC 6238)**: Time-based tokens.
- **HOTP (RFC 4226)**: Counter-based tokens.
- **URI parsing & generation**: Seamlessly parse or export `otpauth://` URIs.
- **No external dependencies**: Uses only the Python Standard Library (`hmac`, `hashlib`, `urllib`, etc.).
- **Window Validation**: Configurable window sizes for mitigating time drift on TOTP.

## Usage

### Generating and Validating TOTP (Time-Based)

```python
# Assuming you named the module `otpauth.py`
from otpauth import TOTP

# Initialize a TOTP object
totp = TOTP(secret="JBSWY3DPEHPK3PXP", issuer="MyService", label="user@example.com")

# Generate the current 6-digit code
current_code = totp.generate()
print(f"Current OTP: {current_code}")

# Validate a given code
# window=1 allows accepting codes that were valid 1 period ago or will be in the next period.
is_valid = totp.validate(current_code, window=1)
if is_valid is not None:
    print("Code is valid!")
else:
    print("Invalid code.")

# Generate an otpauth:// URI for QR code generation
uri = totp.to_uri()
print(f"Google Authenticator URI: {uri}")
```

### Working with HOTP (Counter-Based)

```python
from otpauth import HOTP

# Initialize an HOTP object with an initial counter
hotp = HOTP(secret="JBSWY3DPEHPK3PXP", counter=0)

# Generate a code for the current counter
code = hotp.generate()
print(f"Code for counter {hotp.counter}: {code}")

# Validate a given code
# By default, window=1 checks the immediate surroundings of the counter.
valid_delta = hotp.validate(code, window=5)
if valid_delta is not None:
    print(f"Code is valid! Delta: {valid_delta}")
    # Update counter after successful validation
    hotp.counter += valid_delta + 1
```

### Parsing existing URIs

You can easily instantiate objects from an existing `otpauth://` link.

```python
from otpauth import parse_uri

uri = "otpauth://totp/MyService:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyService&algorithm=SHA1&digits=6&period=30"

# parse_uri returns either a TOTP or HOTP instance
otp_instance = parse_uri(uri)

print(f"Issuer: {otp_instance.issuer}")
print(f"Current Code: {otp_instance.generate()}")
```

## License
MIT
