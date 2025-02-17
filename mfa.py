# mfa.py
import pyotp

def generate_mfa_secret():
    return pyotp.random_base32()

def verify_mfa_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def provisioning_uri(secret: str, email: str, issuer="TicketBookingPlatform"):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)
