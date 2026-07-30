"""
Block Bord AI — Two-Factor Authentication Service
Generates TOTP secrets, QR code URIs, and verifies TOTP codes.
"""
import logging

logger = logging.getLogger("blockbord.totp")

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False
    logger.warning("pyotp not installed. 2FA will not function. Run: pip install pyotp")

try:
    import qrcode
    import io
    import base64
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
    logger.warning("qrcode not installed. QR code generation will not function. Run: pip install qrcode[pil]")


def generate_totp_secret() -> str:
    """Generate a new random TOTP secret."""
    if not PYOTP_AVAILABLE:
        raise RuntimeError("pyotp is not installed")
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "Block Bord AI") -> str:
    """Generate the otpauth:// URI for authenticator apps."""
    if not PYOTP_AVAILABLE:
        raise RuntimeError("pyotp is not installed")
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_base64(uri: str) -> str:
    """Generate a QR code image as a base64-encoded PNG string."""
    if not QRCODE_AVAILABLE:
        return ""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against the stored secret."""
    if not PYOTP_AVAILABLE:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
