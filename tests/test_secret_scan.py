import pytest

from security.secret_scan import (
    entropy,
    scan_line,
    decode_layers,
    allowlisted,
    validate_key
)


def test_entropy_high():
    assert entropy('aB3$xY9!qL2#mN8') > 3.0

def test_entropy_low():
    assert entropy('aaaaaaaa') < 1.0

def test_scan_generic():
    assert scan_line('token = "sk_test_fake_1234567890"') is not None

def test_scan_hash_noise():
    assert scan_line('commit = 0123456789abcdef0123456789abcdef') is None

def test_scan_private_key():
    assert scan_line('-----BEGIN PRIVATE KEY-----')['type'] == 'private_key'

def test_allow_line():
    assert allowlisted('app.py', 10, {('app.py', 10)}) is True

def test_allow_other_line():
    assert allowlisted('app.py', 11, {('app.py', 10)}) is False

def test_decode_base64():
    assert decode_layers('c2stZmFrZV8xMjM0NTY3ODkw') == 'sk-fake_1234567890'

def test_decode_nested():
    assert decode_layers('YzJ0LVptVmtlVjh5TWpNME5UWTNP RGt5') is not None

def test_decode_depth():
    assert decode_layers('YQ==', 1) == 'a'

def test_multiline_yaml():
    assert scan_line('key: |') is None

def test_validate_ok():
    assert validate_key('sk-fake_1234567890', lambda k: k.startswith('sk-fake')) is True

def test_validate_revoked():
    assert validate_key('sk-old_123', lambda k: False) is False

def test_empty_line():
    assert scan_line('') is None

def test_dedupe():
    assert len({id(x) for x in [scan_line('token = "sk_test_fake_1234567890"')]}) == 1
