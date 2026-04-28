import pytest
from backend.ml.feature_engineering import (
    extract_url_features,
    _calculate_entropy,
    _calculate_char_continuation,
    _tld_legit_score,
    _calculate_similarity
)

def test_extract_url_features():
    url = "http://www.google.com/login"
    features = extract_url_features(url)
    assert isinstance(features, dict)
    assert features['URLLength'] == len(url)
    assert features['DomainLength'] > 0
    assert 'NoOfDotsInURL' in features
    assert features['IsBrandInDomain'] == 1
    assert features['HasHTTPS'] == 0

def test_calculate_entropy():
    # A string with same characters has entropy 0
    assert _calculate_entropy("aaaaaa") == 0.0
    # A string with mixed characters has > 0 entropy
    assert _calculate_entropy("abcdef") > 0.0

def test_calculate_char_continuation():
    # 'a' repeated 4 times out of 10 chars is 0.4
    cont = _calculate_char_continuation("xaaaaxxxxx")
    assert pytest.approx(cont) == 0.4

def test_tld_legit_score():
    assert _tld_legit_score("com") == 1.0
    assert _tld_legit_score("xyz") == 0.2
    assert _tld_legit_score("unknown") == 0.5

def test_calculate_similarity():
    # basic similarity adds score
    assert _calculate_similarity("login.secure.com", "secure.com") > 0.0
