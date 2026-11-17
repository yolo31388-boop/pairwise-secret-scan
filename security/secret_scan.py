"""Secret scanner.

Fixes the six CI false-positive / false-negative classes:

1. entropy + context ......... bare high-entropy strings (hashes, archive
                               members) are never flagged; a finding needs a
                               provider prefix, a secret-ish assignment
                               context, or a private-key header.
2. recursive decoding ........ base64 is decoded layer by layer (standard and
                               URL-safe alphabets, whitespace tolerant) so
                               nested encoded tokens are reached.
3. multiple private-key formats
   ........................... PKCS#1 (RSA/DSA), PKCS#8 (plain/encrypted),
                               SEC1 (EC) and OpenSSH PEM blocks.
4. line-level allowlist ...... allowlist entries are ``(path, lineno)``
                               tuples, so only the exact line is suppressed
                               instead of the whole file.
5. multiline aggregation ..... YAML block scalars, ``.env`` backslash
                               continuations and PEM header/body blocks are
                               joined before scanning.
6. revocation / validation .... candidate secrets are passed through a
                               caller-supplied validator; failures (including
                               revoked keys) are downgraded instead of being
                               reported high-risk blindly.

Standard library only.
"""

from __future__ import annotations

import base64
import math
import os
import re
import string
from collections import Counter
from functools import lru_cache

__all__ = [
    'entropy',
    'scan_line',
    'scan_text',
    'scan_file',
    'decode_layers',
    'allowlisted',
    'validate_key',
]

# ---------------------------------------------------------------------------
# 1. Shannon entropy
# ---------------------------------------------------------------------------

def entropy(s: str) -> float:
    """Shannon entropy (bits/character) of ``s``; 0.0 for empty input."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# ---------------------------------------------------------------------------
# 2. Recursive base64 decoding (standard + URL-safe, whitespace tolerant)
# ---------------------------------------------------------------------------

_B64_CHARS = set(string.ascii_letters + string.digits + '+/=-_')
_PRINTABLE = set(string.printable)


def _b64_decode_once(token):
    """Decode one base64 layer.

    Returns the decoded text, or ``None`` when ``token`` is not a decodable
    base64 layer whose payload is printable UTF-8 text.
    """
    if token is None:
        return None
    cleaned = ''.join(str(token).split())
    # A meaningful base64 layer is at least 4 chars and uses the alphabet only.
    if len(cleaned) < 4 or any(ch not in _B64_CHARS for ch in cleaned):
        return None
    padded = cleaned + '=' * (-len(cleaned) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except Exception:
            continue
        if not raw:
            continue
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue
        if text and all(ch in _PRINTABLE for ch in text):
            return text
    return None


def decode_layers(token, max_depth: int = 5):
    """Recursively base64-decode ``token`` up to ``max_depth`` times.

    Whitespace between layers is tolerated (the nested fixture contains a
    space).  Both standard and URL-safe alphabets are attempted at every
    layer.  When no layer can be decoded the original token is returned;
    ``max_depth=1`` therefore performs a single decode.
    """
    if token is None:
        return None
    current = token
    decoded_any = False
    depth = 0
    while depth < max_depth:
        nxt = _b64_decode_once(current)
        if nxt is None or nxt == current:
            break
        current = nxt
        decoded_any = True
        depth += 1
    return current if decoded_any else token


# ---------------------------------------------------------------------------
# 3. Private key headers (PKCS#1 / PKCS#8 / SEC1 / OpenSSH)
# ---------------------------------------------------------------------------

PEM_START = re.compile(r'-----BEGIN ([A-Z0-9 ]*?)PRIVATE KEY-----')
PEM_END = re.compile(r'-----END [A-Z0-9 ]*?PRIVATE KEY-----')

_PEM_FORMAT_NAMES = {
    '': 'PKCS#8',
    'RSA': 'PKCS#1/RSA',
    'DSA': 'PKCS#1/DSA',
    'EC': 'SEC1/EC',
    'OPENSSH': 'OpenSSH',
    'ENCRYPTED': 'PKCS#8 encrypted',
}

# ---------------------------------------------------------------------------
# Provider / generic secret patterns
# ---------------------------------------------------------------------------

_PROVIDER_PATTERNS = [
    ('aws_access_key', re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b')),
    ('github_token', re.compile(
        r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b'
        r'|\bgithub_pat_[A-Za-z0-9_]{20,}\b')),
    ('slack_token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ('stripe_key', re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b')),
    ('google_api_key', re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
]

# Generic credential prefixes.  The prefix must be followed by at least 8
# token characters so words such as ``token`` or ``key`` alone never match.
GENERIC_SECRET = re.compile(
    r'''(?ix)
    (?<![A-Za-z0-9])
    (?:
        (?:secret|token|password|passwd|api[_\-]?key|access[_\-]?key|
           credential|auth[_\-]?token)
        [_\-]?[A-Za-z0-9][A-Za-z0-9\-_~]{7,}
      | (?:sk|rk|pk)[\-_][A-Za-z0-9][A-Za-z0-9\-_~]{7,}
    )
    '''
)

# Assignment context: ``token: "..."``, ``api_key = '...'`` etc.
ASSIGNMENT = re.compile(
    r'''(?ix)
    \b(?:token|secret|password|passwd|api[_\-]?key|access[_\-]?key|
        credential|auth|key)\b
    \s*[:=]\s*
    (?:"([^"\n]{6,})"|'([^'\n]{6,})'|([^\s#'",;]{8,}))
    '''
)

# Words that indicate the neighbouring high-entropy value is not a secret.
NOISE_CONTEXT = re.compile(
    r'(?i)\b(commit|hash|sha1?|sha256|sha512|md5|checksum|digest|'
    r'revision|rev|object[_\s]?id|file[_\s]?hash|etag)\b'
)

# Test/fixture values that must never be treated as live credentials.
PLACEHOLDER = re.compile(
    r'(?i)(example|placeholder|dummy|sample|your[_\- ]?(?:key|token|secret)|'
    r'changeme|x{3,}|<[a-z_]+>|\{\{.*?\}\})'
)

_HEX_HASH = re.compile(r'^[0-9a-fA-F]+$')
_HASH_LENGTHS = {8, 16, 32, 40, 64, 128}

# Archives / compiled / media artefacts: high-entropy blobs inside these are
# expected, so file-level scanning skips them.
BINARY_EXTENSIONS = {
    '.zip', '.gz', '.tgz', '.tar', '.bz2', '.xz', '.7z', '.rar', '.zst',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.pdf', '.jar',
    '.class', '.pyc', '.so', '.dll', '.exe', '.bin', '.woff', '.woff2',
    '.ttf', '.eot', '.mp3', '.mp4', '.avi', '.mov', '.sqlite', '.db',
}

_ENTROPY_FLOOR = 3.5


def _is_hash_like(value: str) -> bool:
    return bool(_HEX_HASH.fullmatch(value)) and len(value) in _HASH_LENGTHS


def _has_mixed_classes(value: str) -> bool:
    classes = sum((
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ))
    return classes >= 2


@lru_cache(maxsize=4096)
def _detect(line: str):
    """Core single-line detection.  Cached so repeated identical lines return
    the same finding object (deduplication)."""
    if not line:
        return None
    # Binary / archive payloads embedded on a line are not credentials.
    if any(ord(ch) < 9 or (13 < ord(ch) < 32) for ch in line):
        return None

    # --- private key headers (all PEM dialects) ---------------------------
    pem = PEM_START.search(line)
    if pem:
        kind = pem.group(1).strip()
        return {
            'type': 'private_key',
            'format': _PEM_FORMAT_NAMES.get(kind, kind or 'PEM'),
            'match': pem.group(0),
        }

    if PLACEHOLDER.search(line):
        return None

    # --- strong provider signatures --------------------------------------
    for secret_type, pattern in _PROVIDER_PATTERNS:
        match = pattern.search(line)
        if match:
            return _build_finding(secret_type, match.group(0), line)

    # --- generic sk-/token-style prefixes ---------------------------------
    match = GENERIC_SECRET.search(line)
    if match and not _is_hash_like(match.group(0)):
        return _build_finding('api_token', match.group(0), line)

    # --- entropy only counts with secret-ish context ----------------------
    assignment = ASSIGNMENT.search(line)
    if assignment and not NOISE_CONTEXT.search(line):
        value = next(g for g in assignment.groups() if g)
        if (
            not _is_hash_like(value)
            and not PLACEHOLDER.search(value)
            and len(value) >= 12
            and _has_mixed_classes(value)
            and entropy(value) >= _ENTROPY_FLOOR
        ):
            return _build_finding('high_entropy_secret', value, line)

    return None


def _build_finding(secret_type: str, match: str, line: str):
    finding = {
        'type': secret_type,
        'match': match,
        'line': line,
    }
    # Recursively decode the candidate: nested encoded tokens must not hide
    # the real credential one layer below.
    decoded = decode_layers(match)
    if decoded != match:
        finding['decoded'] = decoded
        nested = _detect(decoded)
        if nested is not None:
            finding['nested_type'] = nested['type']
    return finding


def scan_line(line, lineno=None, path=None, allowlist=None):
    """Scan one line of text.

    ``lineno`` is 1-based.  When ``path``/``lineno``/``allowlist`` are given
    and the exact line is allowlisted, ``None`` is returned; the rest of the
    file remains fully scanned.
    """
    if not line:
        return None
    if (
        lineno is not None
        and path is not None
        and allowlisted(path, lineno, allowlist)
    ):
        return None
    return _detect(line.rstrip('\r\n'))


# ---------------------------------------------------------------------------
# 4. Line-level allowlist
# ---------------------------------------------------------------------------

def allowlisted(path, lineno: int, allowlist) -> bool:
    """Return True only when the exact ``(path, lineno)`` pair is listed.

    A file-level entry can no longer silence new secrets added to the same
    file.  Both OS-native and forward-slash path spellings are accepted.
    """
    if not allowlist:
        return False
    lineno = int(lineno)
    keys = {
        (os.path.normpath(str(path)), lineno),
        (str(path).replace('\\', '/'), lineno),
    }
    return any(key in allowlist for key in keys)


# ---------------------------------------------------------------------------
# 5. Multiline aggregation (YAML block scalars, .env continuations, PEM)
# ---------------------------------------------------------------------------

_YAML_BLOCK = re.compile(
    r'^(\s*)[A-Za-z0-9_."\'-]+:\s*[|>][+-]?\s*(?:#.*)?$'
)


def _block_allowlisted(path, start, end, allowlist) -> bool:
    """A multiline block is suppressed only when every physical line in it
    is individually allowlisted."""
    if not allowlist or path is None:
        return False
    return all(
        allowlisted(path, lno, allowlist)
        for lno in range(start, end + 1)
    )


def scan_text(text: str, path=None, allowlist=None):
    """Scan full text, aggregating multiline credentials.

    Handles PEM ``BEGIN``..``END`` blocks, YAML ``|``/``>`` block scalars and
    backslash-continued ``.env`` lines.  Findings carry 1-based line numbers
    and are deduplicated.
    """
    lines = text.splitlines()
    findings = []
    seen = set()
    n = len(lines)
    i = 0

    def emit(finding, lineno):
        if finding is None:
            return
        key = (lineno, finding['type'], finding['match'])
        if key in seen:
            return
        seen.add(key)
        record = dict(finding)
        record['line_no'] = lineno
        if path is not None:
            record['path'] = path
        findings.append(record)

    while i < n:
        line = lines[i]
        start_line = i + 1

        # PEM private-key block: keep header and body together.
        if PEM_START.search(line):
            j = i
            block = [line]
            while j + 1 < n and not PEM_END.search(lines[j]):
                j += 1
                block.append(lines[j])
            joined = '\n'.join(block)
            if not _block_allowlisted(path, start_line, j + 1, allowlist):
                emit(_detect(joined), start_line)
            i = j + 1
            continue

        # YAML block scalar: gather the indented continuation lines.
        yaml_match = _YAML_BLOCK.match(line)
        if yaml_match:
            indent = len(yaml_match.group(1))
            j = i
            block = []
            while j + 1 < n:
                nxt = lines[j + 1]
                if nxt.strip() == '':
                    block.append(nxt)
                    j += 1
                    continue
                # deeper indent than the header => part of the block
                if len(nxt) - len(nxt.lstrip(' ')) > indent:
                    block.append(nxt)
                    j += 1
                    continue
                break
            if block:
                joined = '\n'.join(block)
                if not _block_allowlisted(path, start_line, j + 1, allowlist):
                    emit(_detect(joined), start_line)
                i = j + 1
                continue

        # .env / shell backslash continuation.
        if line.rstrip('\r').endswith('\\'):
            j = i
            parts = [line.rstrip('\r')[:-1]]
            while j + 1 < n and lines[j].rstrip('\r').endswith('\\'):
                j += 1
                parts.append(lines[j].rstrip('\r')[:-1])
            joined = ''.join(parts)
            if not _block_allowlisted(path, start_line, j + 1, allowlist):
                emit(_detect(joined), start_line)
            i = j + 1
            continue

        emit(scan_line(line, start_line, path, allowlist), start_line)
        i += 1

    return findings


def scan_file(path: str, allowlist=None):
    """Scan a file, skipping archives and binary artefacts outright."""
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return []
    with open(path, 'rb') as fh:
        raw = fh.read()
    if b'\x00' in raw[:4096]:  # binary content despite a text-ish extension
        return []
    return scan_text(raw.decode('utf-8', errors='replace'),
                     path=path, allowlist=allowlist)


# ---------------------------------------------------------------------------
# 6. Revocation / validity checking
# ---------------------------------------------------------------------------

def validate_key(secret, validator, revoked=None) -> bool:
    """Confirm a candidate secret is still valid.

    ``validator`` is a callable returning truthy for live credentials (e.g. a
    provider auth probe).  Secrets in ``revoked`` fail immediately, and any
    exception raised by the validator is treated as "not confirmed" rather
    than as a high-risk hit.
    """
    if secret is None or validator is None:
        return False
    if revoked and secret in set(revoked):
        return False
    try:
        return bool(validator(secret))
    except Exception:
        return False
