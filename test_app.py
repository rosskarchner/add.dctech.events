from chalice.test import Client
from app import app
import json
from unittest.mock import patch, MagicMock
import pytest
from datetime import date
import os
from chalice.config import Config
from chalice.deploy.packager import LambdaDeploymentPackager
from botocore.exceptions import ClientError

@pytest.fixture
def test_client():
    with Client(app) as client:
        yield client

def test_index_returns_form(test_client):
    response = test_client.http.get('/')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    assert '<form id="eventForm"' in response.body
    assert 'id="errorContainer"' in response.body
    assert 'id="successContainer"' in response.body
    assert 'id="formContainer"' in response.body
    assert 'csrf_token' in response.body  # Verify CSRF token is included

@patch('os.path.exists')
@patch('os.getcwd')
def test_template_loading_in_lambda(mock_getcwd, mock_exists, test_client):
    # Simulate Lambda environment where os.getcwd()/templates doesn't exist
    mock_exists.side_effect = lambda path: '/var/task/chalicelib' in path
    mock_getcwd.return_value = '/var/task'
    
    response = test_client.http.get('/')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    assert '<form id="eventForm"' in response.body
    
    # Verify it tried the Lambda path
    mock_exists.assert_any_call('/var/task/chalicelib/templates')

def test_submit_event_invalid_request(test_client):
    # Test missing Content-Type header
    response = test_client.http.post(
        '/submit',
        body=json.dumps({
            'email': 'test@example.com',
            'events': []
        })
    )
    assert response.status_code == 415
    assert 'Content-Type must be application/json' in response.json_body['message']

    # Test invalid JSON
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body='{"invalid json'
    )
    assert response.status_code == 400
    assert 'Invalid JSON in request body' in response.json_body['message']

    # Test missing CSRF token
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({
            'email': 'test@example.com',
            'events': []
        })
    )
    assert response.status_code == 403
    assert 'Invalid or missing CSRF token' in response.json_body['error']

def test_submit_event_invalid_data(test_client):
    # Test with invalid email
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({
            'submitted_by': 'Test User',
            'submitter_link': 'https://example.com/user',
            'email': 'invalid-email',  # Invalid email format
            'events': [{
                'title': 'Test Event',
                'date': '2024-01-01',
                'time': '10:00',
                'url': 'https://example.com/test',
                'location': 'Test Location'
            }]
        })
    )
    assert response.status_code == 400
    assert 'error' in response.json_body
    assert 'errors' in response.json_body
    assert 'email' in response.json_body['errors']

    # Test with invalid URL
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({
            'submitted_by': 'Test User',
            'submitter_link': 'https://example.com/user',
            'email': 'test@example.com',
            'events': [{
                'title': 'Test Event',
                'date': '2024-01-01',
                'time': '10:00',
                'url': 'not-a-url',  # Invalid URL format
                'location': 'Test Location'
            }]
        })
    )
    assert response.status_code == 400
    assert 'error' in response.json_body
    assert 'errors' in response.json_body
    assert 'url' in response.json_body['errors']

    # Test with no events
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({
            'submitted_by': 'Test User',
            'submitter_link': 'https://example.com/user',
            'email': 'test@example.com',
            'events': []  # Empty events list
        })
    )
    assert response.status_code == 400
    assert 'error' in response.json_body
    assert 'At least one event is required' in response.json_body['error']

@patch('app.submissions_table')
@patch('app.ses')
def test_submit_event_success(mock_ses, mock_table, test_client):
    # Mock DynamoDB put_item
    mock_table.put_item = MagicMock()
    
    # Mock SES send_email
    mock_ses.send_email = MagicMock()
    
    # Get CSRF token from index page
    index_response = test_client.http.get('/')
    csrf_token = index_response.body.split('csrf_token: \'')[1].split('\'')[0]
    
    # Test with all optional fields omitted and single event
    test_data = {
        'email': 'test@example.com',
        'csrf_token': csrf_token,
        'events': [{
            'title': 'Test Event',
            'date': '2024-01-01',
            'time': '10:00',
            'url': 'https://example.com/test'
        }]
    }
    
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps(test_data)
    )
    
    assert response.status_code == 200
    assert 'message' in response.json_body
    assert 'Please check your email' in response.json_body['message']
    
    # Verify DynamoDB was called with default values
    mock_table.put_item.assert_called_once()
    call_args = mock_table.put_item.call_args[1]
    assert 'anonymous' == call_args['Item']['data']['submitted_by']
    
    # Reset mocks for next test
    mock_table.put_item.reset_mock()
    mock_ses.send_email.reset_mock()
    
    # Test with all fields provided and multiple events
    test_data_full = {
        'submitted_by': 'Test User',
        'submitter_link': 'https://example.com/user',
        'email': 'test@example.com',
        'events': [
            {
                'title': 'Test Event 1',
                'date': '2024-01-01',
                'time': '10:00',
                'url': 'https://example.com/test1',
                'location': 'Test Location 1'
            },
            {
                'title': 'Test Event 2',
                'date': '2024-01-02',
                'time': '14:00',
                'url': 'https://example.com/test2',
                'location': 'Test Location 2'
            }
        ]
    }
    
    response = test_client.http.post(
        '/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps(test_data_full)
    )
    
    assert response.status_code == 200
    assert 'message' in response.json_body
    assert 'Please check your email' in response.json_body['message']
    
    # Verify DynamoDB was called
    mock_table.put_item.assert_called_once()
    call_args = mock_table.put_item.call_args[1]
    assert len(call_args['Item']['data']['events']) == 2
    
    # Verify SES was called
    mock_ses.send_email.assert_called_once()
    email_args = mock_ses.send_email.call_args[1]
    assert '(2 events)' in email_args['Message']['Body']['Text']['Data']
    
    # Verify confirmation URL format
    email_body = email_args['Message']['Body']['Text']['Data']
    assert 'http://localhost:8000/confirm/' in email_body  # Default local URL
    
    # Test with custom domain
    mock_ses.send_email.reset_mock()
    with patch.dict(os.environ, {'DOMAIN_NAME': 'custom.example.com'}):
        response = test_client.http.post(
            '/submit',
            headers={'Content-Type': 'application/json'},
            body=json.dumps(test_data_full)
        )
        assert response.status_code == 200
        email_args = mock_ses.send_email.call_args[1]
        email_body = email_args['Message']['Body']['Text']['Data']
        assert 'https://custom.example.com/confirm/' in email_body

@patch('app.submissions_table')
@patch('app.Github')
@patch('app.ses')
@patch('app.secrets')
def test_confirm_submission_flow(mock_secrets, mock_ses, mock_github, mock_table, test_client):
    # Mock DynamoDB get_item
    mock_table.get_item.return_value = {
        'Item': {
            'submission_id': 'test-id',
            'status': 'pending',
            'email': 'test@example.com',
            'data': {
                'submitted_by': 'Test User',
                'submitter_link': 'https://example.com/user',
                'events': [
                    {
                        'title': 'Test Event 1',
                        'date': '2024-01-01',
                        'time': '10:00',
                        'url': 'https://example.com/test1',
                        'location': 'Test Location 1'
                    },
                    {
                        'title': 'Test Event 2',
                        'date': '2024-01-02',
                        'time': '14:00',
                        'url': 'https://example.com/test2',
                        'location': 'Test Location 2'
                    }
                ]
            }
        }
    }
    
    # Test preview page
    response = test_client.http.get('/confirm/test-id')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    assert 'Confirm Event Submission' in response.body
    assert 'Test Event 1' in response.body
    assert 'Test Event 2' in response.body
    assert 'csrf_token' in response.body  # Verify CSRF token is included
    
    # Get CSRF token from preview page
    csrf_token = response.body.split('csrf_token: \'')[1].split('\'')[0]
    
    # Mock Secrets Manager for actual submission
    mock_secrets.get_secret_value.return_value = {
        'SecretString': 'test-github-token'
    }
    
    # Mock GitHub operations
    mock_repo = MagicMock()
    mock_repo.default_branch = 'main'
    mock_repo.get_git_ref.return_value = MagicMock(object=MagicMock(sha='test-sha'))
    mock_github.return_value.get_repo.return_value = mock_repo
    
    # Mock PR creation
    mock_pr = MagicMock()
    mock_pr.html_url = 'https://github.com/test/pr/1'
    mock_repo.create_pull.return_value = mock_pr
    
    # Test actual submission with JSON
    response = test_client.http.post(
        '/confirm/test-id/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({'csrf_token': csrf_token})
    )
    assert response.status_code == 200
    
    # Test actual submission with form-encoded data
    response = test_client.http.post(
        '/confirm/test-id/submit',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        body=f'csrf_token={csrf_token}'
    )
    assert response.status_code == 200
    
    # Test submission with invalid content type
    response = test_client.http.post('/confirm/test-id/submit', headers={'Content-Type': 'text/plain'})
    assert response.status_code == 415
    assert 'Content-Type must be application/json or application/x-www-form-urlencoded' in response.json_body['error']
    
    # Test submission without CSRF token
    response = test_client.http.post(
        '/confirm/test-id/submit',
        headers={'Content-Type': 'application/json'},
        body=json.dumps({})
    )
    assert response.status_code == 403
    assert 'Invalid or missing CSRF token' in response.json_body['error']
    assert 'text/html' in response.headers['Content-Type']
    assert 'Event Submission Complete' in response.body
    assert mock_pr.html_url in response.body
    
    # Verify Secrets Manager was called
    mock_secrets.get_secret_value.assert_called_once()
    
    # Verify GitHub operations
    mock_repo.create_git_ref.assert_called_once()
    assert mock_repo.create_file.call_count == 2  # One call per event
    mock_repo.create_pull.assert_called_once()
    
    # Verify PR title format for multiple events
    pr_call_args = mock_repo.create_pull.call_args[1]
    assert pr_call_args['title'] == 'Event Submission: Multiple'
    assert 'Test Event 1' in pr_call_args['body']
    assert 'Test Event 2' in pr_call_args['body']
    
    # Test single event PR title
    mock_table.get_item.return_value['Item']['data']['events'] = [
        {
            'title': 'Single Test Event',
            'date': '2024-01-01',
            'time': '10:00',
            'url': 'https://example.com/test1',
            'location': 'Test Location 1'
        }
    ]
    
    response = test_client.http.post('/confirm/test-id/submit')
    pr_call_args = mock_repo.create_pull.call_args[1]
    assert pr_call_args['title'] == 'Event Submission: Single Test Event'
    
    # Verify email was sent with event list
    mock_ses.send_email.assert_called()
    email_args = mock_ses.send_email.call_args[1]
    assert 'Single Test Event' in email_args['Message']['Body']['Text']['Data']

@patch('app.secrets')
def test_get_secret(mock_secrets):
    # Test successful secret retrieval
    mock_secrets.get_secret_value.return_value = {
        'SecretString': 'test-secret-value'
    }
    
    secret = app.get_secret('test-secret-name')
    assert secret == 'test-secret-value'
    mock_secrets.get_secret_value.assert_called_once_with(SecretId='test-secret-name')
    
    # Test error handling for general exception
    mock_secrets.get_secret_value.reset_mock()
    mock_secrets.get_secret_value.side_effect = Exception('Test error')
    
    with pytest.raises(Exception) as exc_info:
        app.get_secret('test-secret-name')
    assert 'Test error' in str(exc_info.value)
    
    # Test error handling for access denied
    mock_secrets.get_secret_value.reset_mock()
    mock_secrets.get_secret_value.side_effect = ClientError(
        {'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
        'GetSecretValue'
    )
    
    with pytest.raises(ClientError) as exc_info:
        app.get_secret('test-secret-name')
    assert 'AccessDeniedException' in str(exc_info.value)

@patch('app.secrets')
def test_get_csrf_secret(mock_secrets):
    # Test successful secret retrieval with string value
    mock_secrets.get_secret_value.return_value = {
        'SecretString': 'test-csrf-secret'
    }
    
    with patch('app.get_secret') as mock_get_secret:
        mock_get_secret.return_value = 'test-csrf-secret'
        secret = app.get_csrf_secret()
        assert secret == 'test-csrf-secret'
        mock_get_secret.assert_called_once_with('dctech-events/csrf-secret')
    
    # Test successful secret retrieval with JSON value
    mock_secrets.get_secret_value.return_value = {
        'SecretString': '{"CSRF_SECRET_KEY": "test-csrf-secret-json"}'
    }
    
    with patch('app.get_secret') as mock_get_secret:
        mock_get_secret.return_value = '{"CSRF_SECRET_KEY": "test-csrf-secret-json"}'
        secret = app.get_csrf_secret()
        assert secret == 'test-csrf-secret-json'
    
    # Test error handling with debug mode
    with patch('app.get_secret') as mock_get_secret:
        mock_get_secret.side_effect = Exception('Test error')
        with patch('app.app.debug', True):
            secret = app.get_csrf_secret()
            assert secret == 'debug-only-csrf-secret-key'
    
    # Test error handling without debug mode
    with patch('app.get_secret') as mock_get_secret:
        mock_get_secret.side_effect = Exception('Test error')
        with patch('app.app.debug', False):
            with pytest.raises(Exception) as exc_info:
                app.get_csrf_secret()
            assert 'Test error' in str(exc_info.value)


def test_templates_included_in_deployment():
    # Create a temporary config object
    config = Config.create(
        project_dir=os.path.dirname(os.path.abspath(__file__)),
        config_from_disk={
            "version": "2.0",
            "app_name": "dctech-events-submit",
            "lambda_functions": {
                "api_handler": {
                    "include_files": {
                        "chalicelib/templates/": "chalicelib/templates/"
                    }
                }
            }
        }
    )
    
    # Create a packager instance
    packager = LambdaDeploymentPackager()
    
    # Get the deployment package
    deployment_package = packager.deployment_package_filename(
        'api_handler', config.lambda_python_version)
    
    # Create the deployment package
    packager.create_deployment_package(config.project_dir, config.lambda_python_version)
    
    # Verify the package exists
    assert os.path.exists(deployment_package)
    
    # Clean up
    if os.path.exists(deployment_package):
        os.remove(deployment_package)