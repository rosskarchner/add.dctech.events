from chalice.test import Client
from app import app
import json
from unittest.mock import patch, MagicMock
import pytest
import os

@pytest.fixture
def test_client():
    with Client(app) as client:
        yield client

@patch('requests.post')
def test_oauth_callback_success(mock_post, test_client):
    """Test successful OAuth callback flow"""
    # Mock the GitHub token exchange response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'access_token': 'test_access_token_123',
        'token_type': 'bearer'
    }
    mock_post.return_value = mock_response
    
    # Set environment variables
    with patch.dict(os.environ, {
        'GITHUB_CLIENT_ID': 'test_client_id',
        'GITHUB_CLIENT_SECRET': 'test_client_secret'
    }):
        response = test_client.http.get('/oauth/callback?code=test_code&state=test_state')
        
        assert response.status_code == 302
        assert 'Location' in response.headers
        assert 'access_token=test_access_token_123' in response.headers['Location']
        assert 'https://dctech.events/submit/' in response.headers['Location']
        
        # Verify the request to GitHub was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == 'https://github.com/login/oauth/access_token'
        assert call_args[1]['json']['client_id'] == 'test_client_id'
        assert call_args[1]['json']['client_secret'] == 'test_client_secret'
        assert call_args[1]['json']['code'] == 'test_code'

def test_oauth_callback_missing_code(test_client):
    """Test OAuth callback with missing code parameter"""
    response = test_client.http.get('/oauth/callback')
    
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert 'error=missing_code' in response.headers['Location']

def test_oauth_callback_error_param(test_client):
    """Test OAuth callback with error parameter"""
    response = test_client.http.get('/oauth/callback?error=access_denied')
    
    assert response.status_code == 302
    assert 'Location' in response.headers
    assert 'error=access_denied' in response.headers['Location']

def test_oauth_callback_missing_credentials(test_client):
    """Test OAuth callback when OAuth credentials are not configured"""
    with patch.dict(os.environ, {}, clear=True):
        response = test_client.http.get('/oauth/callback?code=test_code')
        
        assert response.status_code == 302
        assert 'error=oauth_not_configured' in response.headers['Location']

@patch('requests.post')
def test_oauth_callback_github_error(mock_post, test_client):
    """Test OAuth callback when GitHub returns an error"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'error': 'bad_verification_code',
        'error_description': 'The code passed is incorrect or expired.'
    }
    mock_post.return_value = mock_response
    
    with patch.dict(os.environ, {
        'GITHUB_CLIENT_ID': 'test_client_id',
        'GITHUB_CLIENT_SECRET': 'test_client_secret'
    }):
        response = test_client.http.get('/oauth/callback?code=bad_code')
        
        assert response.status_code == 302
        assert 'error=bad_verification_code' in response.headers['Location']

@patch('requests.post')
def test_oauth_callback_no_access_token(mock_post, test_client):
    """Test OAuth callback when no access token is returned"""
    mock_response = MagicMock()
    mock_response.json.return_value = {}
    mock_post.return_value = mock_response
    
    with patch.dict(os.environ, {
        'GITHUB_CLIENT_ID': 'test_client_id',
        'GITHUB_CLIENT_SECRET': 'test_client_secret'
    }):
        response = test_client.http.get('/oauth/callback?code=test_code')
        
        assert response.status_code == 302
        assert 'error=no_token' in response.headers['Location']

@patch('requests.post')
def test_oauth_callback_exception(mock_post, test_client):
    """Test OAuth callback when an exception occurs"""
    mock_post.side_effect = Exception('Network error')
    
    with patch.dict(os.environ, {
        'GITHUB_CLIENT_ID': 'test_client_id',
        'GITHUB_CLIENT_SECRET': 'test_client_secret'
    }):
        response = test_client.http.get('/oauth/callback?code=test_code')
        
        assert response.status_code == 302
        assert 'error=exchange_failed' in response.headers['Location']