import pytest
from unittest.mock import patch, MagicMock
from backend.app.services.ml_engine import MLEngine

@pytest.fixture
def mock_ml_engine():
    with patch('backend.app.services.ml_engine.joblib.load') as mock_load:
        with patch('backend.app.services.ml_engine.os.path.exists', return_value=True):
            # Create a mock model
            mock_model = MagicMock()
            mock_model.predict_proba.return_value = [[0.2, 0.8]]
            # Ensure get_booster() returns None so it uses feature_names_in_
            mock_model.get_booster.return_value = None
            mock_model.feature_names_in_ = ['URLLength', 'DomainLength', 'IsBrandInDomain']
            mock_load.return_value = mock_model
            
            engine = MLEngine()
            yield engine, mock_model

def test_ml_engine_load_success(mock_ml_engine):
    engine, mock_model = mock_ml_engine
    assert engine.model is not None
    assert engine.feature_names == ['URLLength', 'DomainLength', 'IsBrandInDomain']

def test_ml_engine_predict(mock_ml_engine):
    engine, mock_model = mock_ml_engine
    prob = engine.predict("http://fake-paypal-login.com")
    assert prob == 0.8
    mock_model.predict_proba.assert_called_once()

@patch('backend.app.services.ml_engine.os.path.exists', return_value=False)
def test_ml_engine_missing_model(mock_exists):
    engine = MLEngine()
    assert engine.model is None
    prob = engine.predict("http://example.com")
    assert prob == 0.0
