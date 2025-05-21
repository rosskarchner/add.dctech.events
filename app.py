from chalice import Chalice, Response
from chalice.app import Request
import boto3
from botocore.exceptions import ClientError
import os
import json
import yaml
from datetime import datetime
import uuid
from github import Github
import base64
from jinja2 import Environment, FileSystemLoader
from wtforms import Form, StringField, DateField, TimeField, URLField, TextAreaField, EmailField, validators
from chalicelib.csrf import generate_csrf_token, validate_csrf_token

class EventForm(Form):
    title = StringField('Event Title', [validators.DataRequired(), validators.Length(min=3, max=200)])
    date = DateField('Date', [validators.DataRequired()])
    time = StringField('Time', [validators.DataRequired()])  # Changed to StringField to handle custom time format
    url = URLField('Event URL', [validators.DataRequired(), validators.URL()])
    location = StringField('Location')  # Made optional by removing validators

class EventSubmissionForm(Form):
    submitted_by = StringField('Your Name', [validators.Length(min=2)])  # Will default to "anonymous" if empty
    submitter_link = URLField('Your Website/Social Media Link', [validators.Optional(), validators.URL()])  # Made optional
    email = EmailField('Your Email', [validators.DataRequired(), validators.Email()])
    events = None  # Will be set dynamically

app = Chalice(app_name='dctech-events-submit')
app.debug = True

# Initialize services
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')
secrets = boto3.client('secretsmanager')
submissions_table = dynamodb.Table(os.environ.get('SUBMISSIONS_TABLE', 'DCTechEventsSubmissions'))

# CSRF secret key from AWS Secrets Manager
def get_csrf_secret():
    """Get CSRF secret key from AWS Secrets Manager."""
    try:
        secret_name = os.environ.get('CSRF_SECRET_NAME', 'dctech-events/csrf-secret')
        secret = get_secret(secret_name)
        if isinstance(secret, str):
            return secret
        # If secret is JSON string, parse it and get the key
        secret_dict = json.loads(secret)
        return secret_dict.get('CSRF_SECRET_KEY')
    except Exception as e:
        if app.debug:
            return 'debug-only-csrf-secret-key'
        raise

CSRF_SECRET_KEY = get_csrf_secret()

def get_secret(secret_name):
    """Fetch a secret from AWS Secrets Manager."""
    try:
        response = secrets.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            return response['SecretString']
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'AccessDeniedException':
            print(f"Access denied to secret {secret_name}. Please check IAM permissions.")
        else:
            print(f"Error fetching secret {secret_name}: {str(e)}")
        raise
    except Exception as e:
        print(f"Error fetching secret {secret_name}: {str(e)}")
        raise

# Configure Jinja2
template_dir = os.path.join(os.getcwd(), 'chalicelib', 'templates')
if not os.path.exists(template_dir):
    # Fallback for AWS Lambda environment
    template_dir = os.path.join('/var/task', 'chalicelib', 'templates')
env = Environment(loader=FileSystemLoader(template_dir))

@app.route('/')
def index():
    """Render the submission form."""
    csrf_token, _ = generate_csrf_token(CSRF_SECRET_KEY)
    template = env.get_template('form.html')
    return Response(
        body=template.render(csrf_token=csrf_token),
        headers={'Content-Type': 'text/html'}
    )

@app.route('/submit', methods=['POST'])
def submit_event():
    """Handle event submission."""
    request: Request = app.current_request
    
    # Check Content-Type header
    content_type = request.headers.get('content-type', '').lower()
    if not content_type.startswith('application/json'):
        return Response(
            body={'message': 'Content-Type must be application/json'},
            status_code=415
        )
    
    # Safely parse JSON body
    try:
        data = request.json_body
    except ValueError as e:
        return Response(
            body={'message': 'Invalid JSON in request body'},
            status_code=400
        )
    
    # Validate CSRF token
    csrf_token = data.get('csrf_token')
    if not csrf_token or not validate_csrf_token(csrf_token, CSRF_SECRET_KEY):
        return Response(
            body={'error': 'Invalid or missing CSRF token'},
            status_code=403
        )
    
    # Validate user information using WTForms
    form = EventSubmissionForm(data={
        'submitted_by': data.get('submitted_by'),
        'submitter_link': data.get('submitter_link'),
        'email': data.get('email')
    })
    
    if not form.validate():
        return Response(
            body={'error': 'Validation failed', 'errors': form.errors},
            status_code=400
        )
    
    # Validate each event
    events = data.get('events', [])
    if not events:
        return Response(
            body={'error': 'At least one event is required'},
            status_code=400
        )
    
    event_forms = []
    for event_data in events:
        event_form = EventForm(data=event_data)
        if not event_form.validate():
            return Response(
                body={'error': 'Event validation failed', 'errors': event_form.errors},
                status_code=400
            )
        event_forms.append(event_form)
    
    # Generate unique submission ID
    submission_id = str(uuid.uuid4())
    
    # Store submission in DynamoDB
    submissions_table.put_item(
        Item={
            'submission_id': submission_id,
            'status': 'pending',
            'email': data['email'],
            'data': {
                'submitted_by': data.get('submitted_by', 'anonymous'),
                'submitter_link': data.get('submitter_link'),
                'events': events
            },
            'created_at': datetime.utcnow().isoformat(),
            'confirmation_sent': False
        }
    )
    
    # Generate confirmation link
    domain_name = app.current_request.context.get('domainName')
    if not domain_name:
        # When running locally with chalice local, use localhost:8000
        domain_name = os.environ.get('DOMAIN_NAME', 'localhost:8000')
    confirmation_url = f"http{'s' if domain_name != 'localhost:8000' else ''}://{domain_name}/confirm/{submission_id}"
    
    # Send confirmation email
    ses.send_email(
        Source=os.environ.get('SENDER_EMAIL', 'outgoing@dctech.events'),
        Destination={'ToAddresses': [data['email']]},
        Message={
            'Subject': {
                'Data': 'Confirm your DC Tech Events submissions'
            },
            'Body': {
                'Text': {
                    'Data': f'Please confirm your event submissions ({len(events)} events) by clicking this link: {confirmation_url}'
                }
            }
        }
    )
    
    return {'message': 'Submissions received. Please check your email for confirmation.'}

@app.route('/confirm/{submission_id}')
def preview_confirmation(submission_id):
    """Show confirmation preview page."""
    # Get submission from DynamoDB
    submission = submissions_table.get_item(
        Key={'submission_id': submission_id}
    ).get('Item')
    
    if not submission:
        return Response(
            body={'error': 'Submission not found'},
            status_code=404
        )
    
    if submission['status'] != 'pending':
        return Response(
            body={'error': 'Submission already processed'},
            status_code=400
        )
    
    csrf_token, _ = generate_csrf_token(CSRF_SECRET_KEY)
    template = env.get_template('confirm.html')
    return Response(
        body=template.render(submission=submission, csrf_token=csrf_token),
        headers={'Content-Type': 'text/html'}
    )

@app.route('/confirm/{submission_id}/submit', methods=['POST'])
def confirm_submission(submission_id):
    """Handle submission confirmation and create GitHub PR."""
    request: Request = app.current_request
    
    # Accept both application/json and application/x-www-form-urlencoded
    content_type = request.headers.get('content-type', '').lower()
    if not (content_type.startswith('application/json') or content_type.startswith('application/x-www-form-urlencoded')):
        return Response(
            body={'error': 'Content-Type must be application/json or application/x-www-form-urlencoded'},
            status_code=415
        )
    
    # Get CSRF token from request body
    if content_type.startswith('application/json'):
        try:
            data = request.json_body or {}
        except ValueError:
            data = {}
    else:
        data = request.form_params or {}
    
    csrf_token = data.get('csrf_token')
    if not csrf_token or not validate_csrf_token(csrf_token, CSRF_SECRET_KEY):
        return Response(
            body={'error': 'Invalid or missing CSRF token'},
            status_code=403
        )
    
    # Get submission from DynamoDB
    submission = submissions_table.get_item(
        Key={'submission_id': submission_id}
    ).get('Item')
    
    if not submission:
        return Response(
            body={'error': 'Submission not found'},
            status_code=404
        )
    
    if submission['status'] != 'pending':
        return Response(
            body={'error': 'Submission already processed'},
            status_code=400
        )
    
    # Create GitHub PR
    github_token = get_secret(os.environ.get('GITHUB_TOKEN_SECRET_NAME', 'dctech-events/github-token'))
    g = Github(github_token)
    repo = g.get_repo('rosskarchner/dctech.events')
    
    # Create branch name
    branch_name = f'event-submission-{submission_id[:8]}'
    
    # Get default branch as base
    base_branch = repo.default_branch
    base_ref = repo.get_git_ref(f'heads/{base_branch}')
    
    # Create new branch
    repo.create_git_ref(f'refs/heads/{branch_name}', base_ref.object.sha)
    
    # Create a file for each event
    events = submission['data']['events']
    file_paths = []
    
    for event in events:
        # Prepare event YAML content
        event_data = {
            'title': event['title'],
            'date': event['date'],
            'time': event['time'],
            'url': event['url'],
            'location': event.get('location', ''),
            'submitted_by': submission['data']['submitted_by'],
            'submitter_link': submission['data'].get('submitter_link', '')
        }
        event_yaml = yaml.dump(event_data, default_flow_style=False)
        
        # Create file name based on title and date
        safe_title = event['title'].lower().replace(' ', '-')
        file_name = f"_single_events/{event['date']}-{safe_title}.yaml"
        
        # Create file in the new branch
        repo.create_file(
            path=file_name,
            message=f"Add event: {event['title']}",
            content=event_yaml,
            branch=branch_name
        )
        file_paths.append(file_name)
    
    # Create pull request with appropriate title
    pr_title = "Event Submission: Multiple" if len(events) > 1 else f"Event Submission: {events[0]['title']}"
    pr_body = "Submitted by: {}\nSubmitted via web form\n\nEvents:\n{}".format(
        submission['data']['submitted_by'],
        "\n".join(f"- {event['title']} ({event['date']})" for event in events)
    )
    
    pr = repo.create_pull(
        title=pr_title,
        body=pr_body,
        head=branch_name,
        base=base_branch
    )
    
    # Update submission status and store PR URL
    submissions_table.update_item(
        Key={'submission_id': submission_id},
        UpdateExpression='SET #status = :status, pr_url = :pr_url',
        ExpressionAttributeNames={'#status': 'status'},
        ExpressionAttributeValues={
            ':status': 'confirmed',
            ':pr_url': pr.html_url
        }
    )
    
    # Send email with PR link
    ses.send_email(
        Source=os.environ.get('SENDER_EMAIL', 'outgoing@dctech.events'),
        Destination={'ToAddresses': [submission['email']]},
        Message={
            'Subject': {
                'Data': 'Your DC Tech Events submissions are ready for review'
            },
            'Body': {
                'Text': {
                    'Data': f'Your event submissions have been processed. You can view the pull request here: {pr.html_url}\n\nSubmitted events:\n' + 
                           "\n".join(f"- {event['title']} ({event['date']})" for event in events)
                }
            }
        }
    )
    
    # Render success page
    template = env.get_template('success.html')
    return Response(
        body=template.render(pr_url=pr.html_url, events=events),
        headers={'Content-Type': 'text/html'}
    )