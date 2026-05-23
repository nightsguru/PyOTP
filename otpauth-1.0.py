import base64
import hashlib
import hmac
import struct
import time
import urllib.parse
from typing import Optional, Union


class Secret:
    """Wrapper for handling base32 secrets."""
    def __init__(self, secret: str):
        # Remove spaces and add '=' padding to a multiple of 8
        secret = secret.replace(' ', '').upper()
        secret += '=' * ((8 - len(secret) % 8) % 8)
        self.b32_str = secret
        self.bytes = base64.b32decode(secret, casefold=True)


class HOTP:
    """Implementation of HMAC-Based One-Time Password (RFC 4226)"""
    def __init__(self, secret: Union[str, Secret], digits: int = 6, algorithm: str = 'SHA1', 
                 counter: int = 0, issuer: str = '', label: str = ''):
        self.secret = secret if isinstance(secret, Secret) else Secret(secret)
        self.digits = digits
        self.algorithm = algorithm.upper()
        self.counter = counter
        self.issuer = issuer
        self.label = label
        
    def _get_digest(self):
        alg = self.algorithm.lower()
        if alg == 'sha1': return hashlib.sha1
        if alg == 'sha256': return hashlib.sha256
        if alg == 'sha512': return hashlib.sha512
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate(self, counter: Optional[int] = None) -> str:
        c = counter if counter is not None else self.counter
        msg = struct.pack(">Q", c)
        h = hmac.new(self.secret.bytes, msg, self._get_digest()).digest()
        
        offset = h[-1] & 0x0f
        binary = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
        return f"{binary % (10 ** self.digits):0{self.digits}}"

    def validate(self, token: str, window: int = 1) -> Optional[int]:
        """Validates the token within a given window. Returns the counter delta or None."""
        for i in range(self.counter - window, self.counter + window + 1):
            if i < 0: continue
            if hmac.compare_digest(self.generate(i), token):
                return i - self.counter
        return None

    def to_uri(self) -> str:
        """Generates an otpauth:// URI"""
        params = {
            'secret': self.secret.b32_str.rstrip('='),
            'algorithm': self.algorithm,
            'digits': self.digits,
            'counter': self.counter
        }
        if self.issuer: params['issuer'] = self.issuer
        
        label = f"{self.issuer}:{self.label}" if self.issuer and self.label else self.label or self.issuer or "HOTP"
        label = urllib.parse.quote(label)
        query = urllib.parse.urlencode(params)
        return f"otpauth://hotp/{label}?{query}"


class TOTP:
    """Implementation of Time-Based One-Time Password (RFC 6238)"""
    def __init__(self, secret: Union[str, Secret], digits: int = 6, algorithm: str = 'SHA1', 
                 period: int = 30, issuer: str = '', label: str = ''):
        self.secret = secret if isinstance(secret, Secret) else Secret(secret)
        self.digits = digits
        self.algorithm = algorithm.upper()
        self.period = period
        self.issuer = issuer
        self.label = label
        
    def _get_digest(self):
        alg = self.algorithm.lower()
        if alg == 'sha1': return hashlib.sha1
        if alg == 'sha256': return hashlib.sha256
        if alg == 'sha512': return hashlib.sha512
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate(self, timestamp: Optional[float] = None) -> str:
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp / self.period)
        
        msg = struct.pack(">Q", counter)
        h = hmac.new(self.secret.bytes, msg, self._get_digest()).digest()
        
        offset = h[-1] & 0x0f
        binary = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
        return f"{binary % (10 ** self.digits):0{self.digits}}"

    def validate(self, token: str, window: int = 1, timestamp: Optional[float] = None) -> Optional[int]:
        """Validates the token within a given window (in periods). Returns the period delta or None."""
        if timestamp is None:
            timestamp = time.time()
        current_counter = int(timestamp / self.period)
        
        for i in range(current_counter - window, current_counter + window + 1):
            msg = struct.pack(">Q", i)
            h = hmac.new(self.secret.bytes, msg, self._get_digest()).digest()
            offset = h[-1] & 0x0f
            binary = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
            generated_token = f"{binary % (10 ** self.digits):0{self.digits}}"
            
            if hmac.compare_digest(generated_token, token):
                return i - current_counter
        return None

    def to_uri(self) -> str:
        """Generates an otpauth:// URI"""
        params = {
            'secret': self.secret.b32_str.rstrip('='),
            'algorithm': self.algorithm,
            'digits': self.digits,
            'period': self.period
        }
        if self.issuer: params['issuer'] = self.issuer
        
        label = f"{self.issuer}:{self.label}" if self.issuer and self.label else self.label or self.issuer or "TOTP"
        label = urllib.parse.quote(label)
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{label}?{query}"


def parse_uri(uri: str) -> Union[HOTP, TOTP]:
    """Parses an otpauth:// URI and returns an HOTP or TOTP object"""
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != 'otpauth':
        raise ValueError("Invalid scheme")
    
    type_ = parsed.netloc.lower()
    if type_ not in ('hotp', 'totp'):
        raise ValueError("Invalid type")
        
    path = urllib.parse.unquote(parsed.path.lstrip('/'))
    label_parts = path.split(':', 1)
    if len(label_parts) == 2:
        issuer = label_parts[0]
        label = label_parts[1].lstrip()
    else:
        issuer = ''
        label = label_parts[0]
        
    params = dict(urllib.parse.parse_qsl(parsed.query))
    secret = params.get('secret')
    if not secret:
        raise ValueError("Missing secret")
        
    algorithm = params.get('algorithm', 'SHA1')
    digits = int(params.get('digits', 6))
    
    if 'issuer' in params and not issuer:
        issuer = params['issuer']

    if type_ == 'totp':
        period = int(params.get('period', 30))
        return TOTP(secret, digits=digits, algorithm=algorithm, period=period, issuer=issuer, label=label)
    else:
        counter = int(params.get('counter', 0))
        return HOTP(secret, digits=digits, algorithm=algorithm, counter=counter, issuer=issuer, label=label)

