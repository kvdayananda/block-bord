from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class URLScanResult(BaseModel):
    url: str
    malicious: bool
    verdict: str
    risk_score: int
    category: str
    details: Dict[str, Any] = {}

class DomainInfo(BaseModel):
    domain: str
    registered: bool
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    whois_raw: Optional[str] = None
    dnssec: Optional[bool] = None

class IPReputation(BaseModel):
    ip: str
    country: Optional[str] = None
    org: Optional[str] = None
    is_malicious: bool
    abuse_score: int
    threat_types: List[str] = []

class EmailBreachInfo(BaseModel):
    email: str
    breached: bool
    breach_count: int
    breaches: List[Dict[str, Any]] = []

class SSLReport(BaseModel):
    hostname: str
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_left: Optional[int] = None
    cipher_suite: Optional[str] = None
    raw_info: Dict[str, Any] = {}

class DNSRecords(BaseModel):
    hostname: str
    records: Dict[str, List[str]] = {}  # A, AAAA, MX, TXT, NS, CNAME

class PasswordBreachInfo(BaseModel):
    password: str
    breached: bool
    pwned_count: int
    strength: str
    feedback: List[str] = []

class QRInfo(BaseModel):
    contains_url: bool
    decoded_text: str
    risk_score: int
    risk_level: str

class FakeShoppingResult(BaseModel):
    url: str
    trust_score: int
    risk_level: str
    reasons: List[str]
    details: Dict[str, Any]

class BrowserFingerprint(BaseModel):
    canvas_hash: Optional[str] = None
    webgl_vendor: Optional[str] = None
    user_agent: Optional[str] = None
    languages: Optional[str] = None
    color_depth: Optional[int] = None
    screen_resolution: Optional[str] = None
    hardware_concurrency: Optional[int] = None
    device_memory: Optional[int] = None
    tracking_score: int
    privacy_level: str

class MetadataResult(BaseModel):
    target: str
    target_type: str
    metadata: Dict[str, Any]
    risk_score: int
    warnings: List[str]

class SecurityHeadersResult(BaseModel):
    url: str
    grade: str
    score: int
    headers: Dict[str, Any]
    missing: List[str]
    warnings: List[str]
