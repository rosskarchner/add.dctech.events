from chalice import Chalice, Response
import os
import requests
import boto3
import json

app = Chalice(app_name='dctech-events-submit')
app.debug = False

# GitHub OAuth Client ID (public, can be hardcoded)
GITHUB_CLIENT_ID = 'Ov23liSTVbSKSvkYW6yg'

# AWS Secrets Manager client (lazy initialization)
_secrets_client = None

def get_secrets_client():
    """Get or create AWS Secrets Manager client."""
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client('secretsmanager')
    return _secrets_client

def get_github_secret():
    """
    Retrieve GitHub OAuth client secret from AWS Secrets Manager.
    Secret is expected to be stored at: dctech-events/github-oauth-secret
    """
    try:
        client = get_secrets_client()
        response = client.get_secret_value(SecretId='dctech-events/github-oauth-secret')

        # Secret can be stored as plain text or JSON
        if 'SecretString' in response:
            secret_value = response['SecretString']
            # Try to parse as JSON first
            try:
                secret_json = json.loads(secret_value)
                return secret_json.get('client_secret') or secret_json.get('secret')
            except (json.JSONDecodeError, TypeError):
                # If not JSON, treat as plain text
                return secret_value
        else:
            # Binary secret
            return response['SecretBinary']
    except Exception as e:
        print(f"Error retrieving GitHub secret from Secrets Manager: {str(e)}")
        return None

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    """
    Handle GitHub OAuth callback
    Exchange authorization code for access token
    """
    # Get authorization code from query params
    code = app.current_request.query_params.get('code') if app.current_request.query_params else None
    state = app.current_request.query_params.get('state') if app.current_request.query_params else None
    error = app.current_request.query_params.get('error') if app.current_request.query_params else None

    # Handle errors
    if error:
        return Response(
            body='',
            status_code=302,
            headers={
                'Location': f'https://dctech.events/submit/?error={error}'
            }
        )

    if not code:
        return Response(
            body='',
            status_code=302,
            headers={
                'Location': 'https://dctech.events/submit/?error=missing_code'
            }
        )

    # Get OAuth credentials
    client_id = GITHUB_CLIENT_ID
    client_secret = get_github_secret()

    if not client_id or not client_secret:
        return Response(
            body='',
            status_code=302,
            headers={
                'Location': 'https://dctech.events/submit/?error=oauth_not_configured'
            }
        )

    # Exchange code for access token
    try:
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            json={
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code,
                'state': state
            }
        )

        token_data = token_response.json()

        if 'error' in token_data:
            return Response(
                body='',
                status_code=302,
                headers={
                    'Location': f'https://dctech.events/submit/?error={token_data["error"]}'
                }
            )

        access_token = token_data.get('access_token')

        if not access_token:
            return Response(
                body='',
                status_code=302,
                headers={
                    'Location': 'https://dctech.events/submit/?error=no_token'
                }
            )

        # Redirect back to dctech.events with the access token
        return Response(
            body='',
            status_code=302,
            headers={
                'Location': f'https://dctech.events/submit/?access_token={access_token}'
            }
        )

    except Exception as e:
        print(f"OAuth error: {str(e)}")
        return Response(
            body='',
            status_code=302,
            headers={
                'Location': 'https://dctech.events/submit/?error=exchange_failed'
            }
        )

