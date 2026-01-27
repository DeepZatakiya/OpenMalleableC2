"""
Malleable - Python Server Implementation

Framework-agnostic HTTP transformation library implementing Cobalt Strike's
Malleable C2 profile format for security research and testing.
"""

import re
import base64
import struct
from typing import Optional, Dict, List, Tuple, Any
import binascii
from dataclasses import dataclass
from enum import Enum


def _strip_comments(content: str) -> str:
    result = []
    in_string = False
    i = 0
    while i < len(content):
        ch = content[i]
        if in_string:
            if ch == '\\' and i + 1 < len(content):
                result.append(ch)
                result.append(content[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            result.append(ch)
        else:
            if ch == '"':
                in_string = True
                result.append(ch)
            elif ch == '#':
                while i < len(content) and content[i] != '\n':
                    i += 1
                result.append('\n' if i < len(content) and content[i] == '\n' else '')
            else:
                result.append(ch)
        i += 1
    return ''.join(result)


def _decode_string_str(s: str) -> str:
    return TransformEngine._decode_string(s).decode('utf-8', errors='replace')


# =========================================================================
#                           DATA STRUCTURES
# =========================================================================

class TransformType(Enum):
    """Transform types supported in malleable profiles"""
    BASE64 = "base64"
    BASE64URL = "base64url"
    NETBIOS = "netbios"
    NETBIOSU = "netbiosu"
    MASK = "mask"
    PREPEND = "prepend"
    APPEND = "append"


class TerminationType(Enum):
    """Termination statement types"""
    HEADER = "header"
    PARAMETER = "parameter"
    PRINT = "print"
    URI_APPEND = "uri-append"


@dataclass
class Transform:
    """A single transform step"""
    type: TransformType
    argument: Optional[str] = None


@dataclass
class Termination:
    """Termination statement"""
    type: TerminationType
    target: Optional[str] = None


@dataclass
class TransformChain:
    """Complete data transformation pipeline"""
    transforms: List[Transform]
    termination: Termination


@dataclass
class HttpConfig:
    """HTTP transaction configuration"""
    headers: Dict[str, str]
    parameters: Dict[str, str]
    metadata: Optional[TransformChain] = None
    id: Optional[TransformChain] = None
    output: Optional[TransformChain] = None


@dataclass
class HttpTransaction:
    """Complete HTTP transaction definition"""
    variant: str
    method: str  # GET or POST
    uris: List[str]
    client: HttpConfig
    server: HttpConfig


@dataclass
class HttpRequest:
    """HTTP request structure"""
    method: str
    uri: str
    path: str
    query: Dict[str, str]
    headers: Dict[str, str]
    body: bytes


@dataclass
class HttpResponse:
    """HTTP response structure"""
    status_code: int
    headers: Dict[str, str]
    body: bytes


class ProfileMismatchError(Exception):
    """Raised when a request does not match the profile or transforms fail."""

    def __init__(self, reason: str, details: str):
        super().__init__(f"{reason}: {details}")
        self.reason = reason
        self.details = details


class MalleableProfile:
    """
    Malleable C2 profile
    
    This class parses profiles from memory (string). If you need to load from a file,
    read it into a string first and pass it to this constructor.
    
    Example - Embedded profile:
        profile_str = 'set sample_name "test"; ...'
        profile = MalleableProfile(profile_str)
    
    Example - Load from file (user-managed):
        with open('config.profile', 'r') as f:
            profile = MalleableProfile(f.read())
    """
    
    def __init__(self, profile_content: str):
        """
        Initialize malleable profile from string
        
        Args:
            profile_content: Profile content as string
        """
        self.profile_name: Optional[str] = None
        self.useragent: Optional[str] = None
        self.headers_remove: List[str] = []
        self.http_get_transactions: Dict[str, HttpTransaction] = {}
        self.http_post_transactions: Dict[str, HttpTransaction] = {}
        
        self._parse(profile_content)
    
    def _parse(self, content: str):
        """Parse malleable profile content"""
        # Remove comments
        original_len = len(content)
        hash_in_quotes = 0
        in_string = False
        i = 0
        while i < len(content):
            ch = content[i]
            if in_string:
                if ch == '\\' and i + 1 < len(content):
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                elif ch == '#':
                    hash_in_quotes += 1
            else:
                if ch == '"':
                    in_string = True
            i += 1
        content = _strip_comments(content)
        
        # Extract profile name
        match = re.search(r'set\s+sample_name\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            self.profile_name = _decode_string_str(match.group(1))
        
        # Extract useragent
        match = re.search(r'set\s+useragent\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            self.useragent = _decode_string_str(match.group(1))
        
        match = re.search(r'set\s+headers_remove\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            raw_headers = _decode_string_str(match.group(1))
            self.headers_remove = [h.strip() for h in raw_headers.split(',') if h.strip()]
        
        # Parse http-get blocks
        for variant, block_content in self._find_named_blocks(content, "http-get"):
            transaction = self._parse_http_transaction("GET", variant, block_content)
            if transaction:
                self.http_get_transactions[variant] = transaction
        
        # Parse http-post blocks
        for variant, block_content in self._find_named_blocks(content, "http-post"):
            transaction = self._parse_http_transaction("POST", variant, block_content)
            if transaction:
                self.http_post_transactions[variant] = transaction
    
    def _parse_http_transaction(self, method: str, variant: str, content: str) -> Optional[HttpTransaction]:
        """Parse a single HTTP transaction block"""
        uris = []
        verb = method
        client_config = HttpConfig(headers={}, parameters={})
        server_config = HttpConfig(headers={}, parameters={})
        
        # Extract URIs
        match = re.search(r'set\s+uri\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            uri_str = _decode_string_str(match.group(1))
            uris = uri_str.split()
        
        match = re.search(r'set\s+verb\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            verb = _decode_string_str(match.group(1)).upper()
        
        # Parse client block
        client_content = self._extract_block_content(content, "client")
        if client_content is not None:
            self._parse_config_block(client_content, client_config)
        
        # Parse server block
        server_content = self._extract_block_content(content, "server")
        if server_content is not None:
            self._parse_config_block(server_content, server_config)
        
        return HttpTransaction(
            variant=variant,
            method=verb,
            uris=uris,
            client=client_config,
            server=server_config
        )
    
    def _parse_config_block(self, content: str, config: HttpConfig):
        """Parse client or server configuration block"""
        # Parse headers
        header_matches = list(re.finditer(r'header\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"', content))
        for match in header_matches:
            name = _decode_string_str(match.group(1))
            value = _decode_string_str(match.group(2))
            config.headers[name] = value
        
        # Parse parameters
        param_matches = list(re.finditer(r'parameter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"', content))
        for match in param_matches:
            key = _decode_string_str(match.group(1))
            value = _decode_string_str(match.group(2))
            config.parameters[key] = value
        
        # Parse metadata block
        metadata_content = self._extract_block_content(content, "metadata")
        if metadata_content is not None:
            config.metadata = self._parse_transform_chain(metadata_content)
        
        # Parse id block
        id_content = self._extract_block_content(content, "id")
        if id_content is not None:
            config.id = self._parse_transform_chain(id_content)
        
        # Parse output block
        output_content = self._extract_block_content(content, "output")
        if output_content is not None:
            config.output = self._parse_transform_chain(output_content)

    def _find_named_blocks(self, content: str, keyword: str) -> List[Tuple[str, str]]:
        """Find blocks like 'http-get \"variant\" { ... }' with brace matching."""
        results = []
        idx = 0
        while True:
            pos = content.find(keyword, idx)
            if pos == -1:
                break
            if pos > 0 and content[pos - 1].isalnum():
                idx = pos + len(keyword)
                continue
            i = pos + len(keyword)
            while i < len(content) and content[i].isspace():
                i += 1
            variant = "default"
            if i < len(content) and content[i] == '"':
                i += 1
                start = i
                while i < len(content) and content[i] != '"':
                    if content[i] == '\\' and i + 1 < len(content):
                        i += 2
                        continue
                    i += 1
                variant = content[start:i]
                i += 1
            while i < len(content) and content[i].isspace():
                i += 1
            if i >= len(content) or content[i] != '{':
                idx = pos + len(keyword)
                continue
            block_content, end_pos = self._extract_braced_content(content, i)
            if block_content is not None:
                results.append((variant, block_content))
                idx = end_pos
            else:
                idx = pos + len(keyword)
        return results

    def _extract_block_content(self, content: str, keyword: str) -> Optional[str]:
        """Extract first block content for a given keyword, using brace matching."""
        pos = content.find(keyword)
        if pos == -1:
            return None
        i = pos + len(keyword)
        while i < len(content) and content[i].isspace():
            i += 1
        if i >= len(content) or content[i] != '{':
            return None
        block_content, _ = self._extract_braced_content(content, i)
        return block_content

    def _extract_braced_content(self, content: str, brace_pos: int) -> Tuple[Optional[str], int]:
        """Extract content inside braces starting at brace_pos (which must be '{')."""
        depth = 0
        i = brace_pos
        start = brace_pos + 1
        in_string = False
        while i < len(content):
            ch = content[i]
            if in_string:
                if ch == '\\' and i + 1 < len(content):
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return content[start:i], i + 1
            i += 1
        return None, len(content)
    
    def _parse_transform_chain(self, content: str) -> TransformChain:
        """Parse a transformation chain"""
        transforms = []
        termination = None
        transform_arg_has_backslash = False
        termination_target_has_backslash = False
        
        # Split into statements, ignoring semicolons inside quotes
        statements = self._split_statements(content)
        
        for stmt in statements:
            stmt = stmt.strip()
            if not stmt:
                continue
            
            # Check for termination statements
            if stmt.startswith('header'):
                match = re.match(r'header\s+"((?:[^"\\]|\\.)*)"', stmt)
                if match:
                    termination_target_has_backslash = "\\" in match.group(1)
                    termination = Termination(TerminationType.HEADER, _decode_string_str(match.group(1)))
                    break
            elif stmt.startswith('parameter'):
                match = re.match(r'parameter\s+"((?:[^"\\]|\\.)*)"', stmt)
                if match:
                    termination_target_has_backslash = "\\" in match.group(1)
                    termination = Termination(TerminationType.PARAMETER, _decode_string_str(match.group(1)))
                    break
            elif stmt == 'print':
                termination = Termination(TerminationType.PRINT)
                break
            elif stmt == 'uri-append':
                termination = Termination(TerminationType.URI_APPEND)
                break
            
            # Check for transform statements
            elif stmt.startswith('prepend'):
                match = re.match(r'prepend\s+"((?:[^"\\]|\\.)*)"', stmt)
                if match:
                    transform_arg_has_backslash = transform_arg_has_backslash or ("\\" in match.group(1))
                    transforms.append(Transform(TransformType.PREPEND, match.group(1)))
            elif stmt.startswith('append'):
                match = re.match(r'append\s+"((?:[^"\\]|\\.)*)"', stmt)
                if match:
                    transform_arg_has_backslash = transform_arg_has_backslash or ("\\" in match.group(1))
                    transforms.append(Transform(TransformType.APPEND, match.group(1)))
            elif stmt == 'base64':
                transforms.append(Transform(TransformType.BASE64))
            elif stmt == 'base64url':
                transforms.append(Transform(TransformType.BASE64URL))
            elif stmt == 'netbios':
                transforms.append(Transform(TransformType.NETBIOS))
            elif stmt == 'netbiosu':
                transforms.append(Transform(TransformType.NETBIOSU))
            elif stmt == 'mask':
                transforms.append(Transform(TransformType.MASK))
        
        return TransformChain(transforms=transforms, termination=termination or Termination(TerminationType.PRINT))


    def _split_statements(self, content: str) -> List[str]:
        """Split semicolon-delimited statements, respecting quoted strings."""
        statements = []
        buf = []
        in_string = False
        i = 0
        while i < len(content):
            ch = content[i]
            if in_string:
                if ch == '\\' and i + 1 < len(content):
                    buf.append(ch)
                    buf.append(content[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                buf.append(ch)
            else:
                if ch == '"':
                    in_string = True
                    buf.append(ch)
                elif ch == ';':
                    stmt = ''.join(buf).strip()
                    if stmt:
                        statements.append(stmt)
                    buf = []
                else:
                    buf.append(ch)
            i += 1
        tail = ''.join(buf).strip()
        if tail:
            statements.append(tail)
        return statements


# =========================================================================
#                        TRANSFORMATION FUNCTIONS
# =========================================================================

class TransformEngine:
    """Handles data transformation according to malleable profiles"""
    
    @staticmethod
    def apply_transform(data: bytes, transform: Transform) -> bytes:
        """Apply a single transform (forward direction)"""
        if transform.type == TransformType.BASE64:
            return base64.b64encode(data)
        
        elif transform.type == TransformType.BASE64URL:
            return base64.urlsafe_b64encode(data).rstrip(b'=')
        
        elif transform.type == TransformType.NETBIOS:
            return TransformEngine._netbios_encode(data, b'a')
        
        elif transform.type == TransformType.NETBIOSU:
            return TransformEngine._netbios_encode(data, b'A')
        
        elif transform.type == TransformType.MASK:
            return TransformEngine._mask_encode(data)
        
        elif transform.type == TransformType.PREPEND:
            if transform.argument:
                arg = TransformEngine._decode_string(transform.argument)
                return arg + data
            return data
        
        elif transform.type == TransformType.APPEND:
            if transform.argument:
                arg = TransformEngine._decode_string(transform.argument)
                return data + arg
            return data
        
        return data
    
    @staticmethod
    def reverse_transform(data: bytes, transform: Transform) -> bytes:
        """Reverse a single transform (backward direction)"""
        if transform.type == TransformType.BASE64:
            try:
                return base64.b64decode(data)
            except binascii.Error as exc:
                raise ProfileMismatchError("transform", f"base64 decode failed: {exc}") from exc
        
        elif transform.type == TransformType.BASE64URL:
            # Add padding if needed
            padding = (4 - len(data) % 4) % 4
            data = data + b'=' * padding
            try:
                return base64.urlsafe_b64decode(data)
            except binascii.Error as exc:
                raise ProfileMismatchError("transform", f"base64url decode failed: {exc}") from exc
        
        elif transform.type == TransformType.NETBIOS:
            return TransformEngine._netbios_decode(data, b'a')
        
        elif transform.type == TransformType.NETBIOSU:
            return TransformEngine._netbios_decode(data, b'A')
        
        elif transform.type == TransformType.MASK:
            return TransformEngine._mask_decode(data)
        
        elif transform.type == TransformType.PREPEND:
            if transform.argument:
                arg = TransformEngine._decode_string(transform.argument)
                if data.startswith(arg):
                    return data[len(arg):]
                raise ProfileMismatchError("transform", "prepend mismatch")
            return data
        
        elif transform.type == TransformType.APPEND:
            if transform.argument:
                arg = TransformEngine._decode_string(transform.argument)
                if data.endswith(arg):
                    return data[:-len(arg)]
                raise ProfileMismatchError("transform", "append mismatch")
            return data
        
        return data
    
    @staticmethod
    def apply_chain(data: bytes, chain: TransformChain) -> bytes:
        """Apply complete transformation chain (forward)"""
        result = data
        for transform in chain.transforms:
            result = TransformEngine.apply_transform(result, transform)
        return result
    
    @staticmethod
    def reverse_chain(data: bytes, chain: TransformChain) -> bytes:
        """Reverse complete transformation chain (backward)"""
        result = data
        # Apply transforms in REVERSE order
        for transform in reversed(chain.transforms):
            result = TransformEngine.reverse_transform(result, transform)
        return result
    
    @staticmethod
    def _netbios_encode(data: bytes, base: bytes) -> bytes:
        """NetBIOS encoding"""
        base_char = base[0]
        result = bytearray()
        for byte in data:
            result.append(base_char + (byte >> 4))
            result.append(base_char + (byte & 0x0F))
        return bytes(result)
    
    @staticmethod
    def _netbios_decode(data: bytes, base: bytes) -> bytes:
        """NetBIOS decoding"""
        base_char = base[0]
        result = bytearray()
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                high = data[i] - base_char
                low = data[i + 1] - base_char
                result.append((high << 4) | low)
        return bytes(result)
    
    @staticmethod
    def _mask_encode(data: bytes) -> bytes:
        """XOR mask encoding with random key"""
        import os
        key = os.urandom(4)
        masked = bytearray()
        for i, byte in enumerate(data):
            masked.append(byte ^ key[i % 4])
        return key + bytes(masked)
    
    @staticmethod
    def _mask_decode(data: bytes) -> bytes:
        """XOR mask decoding"""
        if len(data) < 4:
            raise ProfileMismatchError("transform", "mask decode expects 4-byte key")
        key = data[:4]
        masked = data[4:]
        result = bytearray()
        for i, byte in enumerate(masked):
            result.append(byte ^ key[i % 4])
        return bytes(result)
    
    @staticmethod
    def _decode_string(s: str) -> bytes:
        """Decode string with escape sequences"""
        result = bytearray()
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                next_char = s[i + 1]
                if next_char == 'n':
                    result.append(ord('\n'))
                    i += 2
                elif next_char == 'r':
                    result.append(ord('\r'))
                    i += 2
                elif next_char == 't':
                    result.append(ord('\t'))
                    i += 2
                elif next_char == '\\':
                    result.append(ord('\\'))
                    i += 2
                elif next_char == 'x' and i + 3 < len(s):
                    hex_str = s[i+2:i+4]
                    result.append(int(hex_str, 16))
                    i += 4
                elif next_char == 'u' and i + 5 < len(s):
                    hex_str = s[i+2:i+6]
                    codepoint = int(hex_str, 16)
                    result.extend(chr(codepoint).encode('utf-8'))
                    i += 6
                else:
                    result.append(ord(next_char))
                    i += 2
            else:
                result.append(ord(s[i]))
                i += 1
        return bytes(result)


# =========================================================================
#                        SERVER EXTRACTION FUNCTIONS
# =========================================================================

class MalleableServer:
    """Server-side extraction and response building"""
    
    def __init__(self, profile: MalleableProfile):
        self.profile = profile
        self.engine = TransformEngine()
    
    def extract_metadata(self, request: HttpRequest, variant: str = "default") -> bytes:
        """Extract metadata from HTTP GET request"""
        transaction = self.profile.http_get_transactions.get(variant)
        if not transaction or not transaction.client.metadata:
            raise ValueError(f"No metadata chain for variant {variant}")

        if not any(request.path.startswith(uri) for uri in transaction.uris):
            raise ProfileMismatchError(
                "uri",
                f"request path '{request.path}' does not match any http-get uri"
            )
        
        chain = transaction.client.metadata
        data = self._extract_from_request(request, chain.termination, transaction.uris)
        return self.engine.reverse_chain(data, chain)
    
    def extract_session_id(self, request: HttpRequest, variant: str = "default") -> bytes:
        """Extract session ID from HTTP POST request"""
        transaction = self.profile.http_post_transactions.get(variant)
        if not transaction or not transaction.client.id:
            raise ValueError(f"No id chain for variant {variant}")

        if not any(request.path.startswith(uri) for uri in transaction.uris):
            raise ProfileMismatchError(
                "uri",
                f"request path '{request.path}' does not match any http-post uri"
            )
        
        chain = transaction.client.id
        data = self._extract_from_request(request, chain.termination, transaction.uris)
        return self.engine.reverse_chain(data, chain)
    
    def extract_output(self, request: HttpRequest, variant: str = "default") -> bytes:
        """Extract output from HTTP POST request"""
        transaction = self.profile.http_post_transactions.get(variant)
        if not transaction or not transaction.client.output:
            raise ValueError(f"No output chain for variant {variant}")

        if not any(request.path.startswith(uri) for uri in transaction.uris):
            raise ProfileMismatchError(
                "uri",
                f"request path '{request.path}' does not match any http-post uri"
            )
        
        chain = transaction.client.output
        data = self._extract_from_request(request, chain.termination, transaction.uris)
        return self.engine.reverse_chain(data, chain)
    
    def build_get_response(self, data: bytes, variant: str = "default") -> HttpResponse:
        """Build HTTP response with tasks (response to GET)"""
        transaction = self.profile.http_get_transactions.get(variant)
        if not transaction:
            raise ValueError(f"No transaction for variant {variant}")
        
        headers = dict(transaction.server.headers)
        body = b''
        
        if transaction.server.output:
            transformed = self.engine.apply_chain(data, transaction.server.output)
            if transaction.server.output.termination.type == TerminationType.PRINT:
                body = transformed
            elif transaction.server.output.termination.type == TerminationType.HEADER:
                headers[transaction.server.output.termination.target] = transformed.decode('utf-8', errors='ignore')
        
        return HttpResponse(status_code=200, headers=headers, body=body)
    
    def build_post_response(self, data: bytes = b'', variant: str = "default") -> HttpResponse:
        """Build HTTP response for POST"""
        transaction = self.profile.http_post_transactions.get(variant)
        if not transaction:
            raise ValueError(f"No transaction for variant {variant}")
        
        headers = dict(transaction.server.headers)
        body = b''
        
        if transaction.server.output and data:
            transformed = self.engine.apply_chain(data, transaction.server.output)
            if transaction.server.output.termination.type == TerminationType.PRINT:
                body = transformed
        
        return HttpResponse(status_code=200, headers=headers, body=body)
    
    def _extract_from_request(
        self,
        request: HttpRequest,
        termination: Termination,
        uris: Optional[List[str]] = None
    ) -> bytes:
        """Extract data from HTTP request based on termination type"""
        if termination.type == TerminationType.HEADER:
            value = request.headers.get(termination.target, '')
            return value.encode('utf-8')
        
        elif termination.type == TerminationType.PARAMETER:
            value = request.query.get(termination.target, '')
            return value.encode('utf-8')
        
        elif termination.type == TerminationType.PRINT:
            return request.body
        
        elif termination.type == TerminationType.URI_APPEND:
            if not uris:
                raise ProfileMismatchError("uri", "uri-append used but no uris configured")
            for base in uris:
                if request.path.startswith(base):
                    suffix = request.path[len(base):]
                    return suffix.encode('utf-8')
            raise ProfileMismatchError(
                "uri",
                f"request path '{request.path}' does not match any uri-append base"
            )
        
        return b''


# =========================================================================
#                              HELPER FUNCTIONS
# =========================================================================

def parse_http_request(raw_request: str) -> HttpRequest:
    """Parse raw HTTP request string"""
    lines = raw_request.split('\r\n')
    if not lines:
        raise ValueError("Empty request")
    
    # Parse request line
    request_line = lines[0].split(' ')
    if len(request_line) < 3:
        raise ValueError("Invalid request line")
    
    method = request_line[0]
    full_uri = request_line[1]
    
    # Parse URI and query string
    if '?' in full_uri:
        path, query_string = full_uri.split('?', 1)
        query = dict(param.split('=', 1) for param in query_string.split('&') if '=' in param)
    else:
        path = full_uri
        query = {}
    
    # Parse headers
    headers = {}
    i = 1
    while i < len(lines) and lines[i]:
        if ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            headers[key.strip()] = value.strip()
        i += 1
    
    # Body is everything after blank line
    body = b''
    if i < len(lines):
        body = '\r\n'.join(lines[i+1:]).encode('utf-8')
    
    return HttpRequest(
        method=method,
        uri=full_uri,
        path=path,
        query=query,
        headers=headers,
        body=body
    )


if __name__ == '__main__':
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python openmalleable.py <profile_path>")
        sys.exit(1)
    
    # User handles file I/O, library only accepts string
    with open(sys.argv[1], 'r') as f:
        profile_content = f.read()
    
    profile = MalleableProfile(profile_content)
    print(f"Loaded profile: {profile.profile_name}")
    print(f"HTTP-GET transactions: {list(profile.http_get_transactions.keys())}")
    print(f"HTTP-POST transactions: {list(profile.http_post_transactions.keys())}")
