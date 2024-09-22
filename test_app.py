import pytest
import base64
from flask import json
from main import app, keys, expiredKeys, currentKeyID  # <-- Import from main.py
from datetime import datetime  # <-- Ensure datetime is imported


@pytest.fixture
def client():
    """Fixture to initialize the test client"""
    with app.test_client() as client:
        yield client


def test_jwks(client):
    """Test the /jwks endpoint"""
    # Send GET request to the /.well-known/jwks.json endpoint
    response = client.get('/.well-known/jwks.json')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Check that 'keys' are present and non-empty
    assert 'keys' in data
    assert len(data['keys']) > 0

    # Check structure of the first key
    key = data['keys'][0]
    assert 'kid' in key
    assert 'kty' in key
    assert 'alg' in key
    assert 'use' in key
    assert 'n' in key
    assert 'e' in key


def test_auth_token_generation(client):
    """Test the /auth endpoint for generating JWT"""
    response = client.post('/auth')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Check if token is returned
    assert 'token' in data
    token = data['token']
    
    # Decode and validate the JWT structure
    segments = token.split('.')
    assert len(segments) == 3  # JWT should have 3 segments


def test_auth_with_expired_key(client):
    """Test the /auth endpoint with an expired key"""
    response = client.post('/auth?expired=true')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Check if token is returned
    assert 'token' in data
    token = data['token']
    
    # Decode and validate the JWT structure
    segments = token.split('.')
    assert len(segments) == 3  # JWT should have 3 segments

    # Ensure the key used for signing is expired
    header = json.loads(base64.urlsafe_b64decode(segments[0] + '=='))
    assert header['kid'] in expiredKeys


def test_key_expiry(client):
    """Test that expired keys are correctly identified"""
    response = client.get('/.well-known/jwks.json')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    now = datetime.utcnow().replace(tzinfo=None)
    for key in data['keys']:
        expiry = next((key_info['metadata']['expiry'] for kid, key_info in keys.items() if kid == key['kid']), None)
        if expiry:
            expiry_date = datetime.fromisoformat(expiry.replace('Z', '+00:00')).replace(tzinfo=None)
            assert now < expiry_date


def test_404_for_invalid_key(client):
    """Test handling of missing/invalid keys"""
    global keys
    saved_keys = keys.copy()
    keys = {}
    
    response = client.post('/auth')
    assert response.status_code == 404  # Key should not be found
    
    # Restore keys
    keys = saved_keys
