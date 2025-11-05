import os
import sys
from pathlib import Path

# Vercel-specific setup
if os.environ.get('VERCEL'):
    # Add current directory to Python path
    sys.path.append(str(Path(__file__).parent))
    
    # Set Flask environment
    os.environ['FLASK_ENV'] = 'production'
from flask import Flask, request, redirect, url_for, flash, render_template_string, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os
import json
import base64
from urllib.parse import urlencode
from datetime import datetime, timedelta
import logging
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBc4XCu2aOs6eKJqu1AXJ2Vwa5qK1bamB8")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-123")

app.secret_key = SECRET_KEY

# OAuth Scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]

# AI Functions
def setup_gemini():
    """Setup Gemini AI"""
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        return genai.GenerativeModel('gemini-pro')
    except Exception as e:
        logger.error(f"Gemini setup error: {str(e)}")
        return None

def summarize_email(subject, body, snippet):
    """Generate AI summary for email"""
    try:
        model = setup_gemini()
        if not model:
            return "AI summarization unavailable"
        
        prompt = f"""
        Please provide a concise summary of this email in 2-3 bullet points:
        
        Subject: {subject}
        Content: {body if body else snippet}
        
        Focus on:
        - Main purpose of the email
        - Key action items required
        - Important details or deadlines
        
        Format as bullet points.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Summarization error: {str(e)}")
        return "Unable to generate summary"

def generate_smart_reply(subject, body, sender):
    """Generate smart AI reply"""
    try:
        model = setup_gemini()
        if not model:
            return "AI reply generation unavailable"
        
        prompt = f"""
        Generate a professional email reply for this message:
        
        From: {sender}
        Subject: {subject}
        Content: {body}
        
        Provide 3 different reply options:
        1. Professional and formal
        2. Casual and friendly  
        3. Quick acknowledgment
        
        Format each option clearly.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Smart reply error: {str(e)}")
        return "Unable to generate smart replies"

def generate_ai_composed_email(context, recipient, purpose, tone="professional"):
    """Generate AI-composed email from scratch"""
    try:
        model = setup_gemini()
        if not model:
            return "AI composition unavailable"
        
        prompt = f"""
        Compose an email with the following details:
        
        Recipient: {recipient}
        Purpose: {purpose}
        Context: {context}
        Tone: {tone}
        
        Please generate a complete email with:
        - Appropriate subject line
        - Professional greeting
        - Clear and concise body content
        - Professional closing
        
        Make sure the email is well-structured and appropriate for the given context and tone.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"AI composition error: {str(e)}")
        return "Unable to generate email content"

def get_ai_labels(subject, content, sender):
    """Get AI-generated labels for email"""
    try:
        model = setup_gemini()
        if not model:
            return ["general"]
        
        prompt = f"""
        Analyze this email and assign relevant labels from these categories:
        - work
        - personal  
        - urgent
        - follow-up
        - meeting
        - project
        - finance
        - travel
        - social
        - newsletter
        - promotion
        - notification
        
        Email:
        Subject: {subject}
        From: {sender}
        Content: {content[:1000]}
        
        Return only the most relevant 2-3 labels as a comma-separated list.
        """
        
        response = model.generate_content(prompt)
        labels = [label.strip().lower() for label in response.text.split(',')]
        return labels[:3]
    except Exception as e:
        logger.error(f"AI labeling error: {str(e)}")
        return ["general"]

def analyze_and_label_emails(emails):
    """Analyze emails and assign smart labels"""
    try:
        model = setup_gemini()
        if not model:
            return emails
            
        for email in emails:
            ai_labels = get_ai_labels(email['subject'], email.get('body', email['snippet']), email['sender'])
            email['ai_labels'] = ai_labels
            email['summary'] = summarize_email(email['subject'], email.get('body', email['snippet']), email['snippet'])
            
        return emails
    except Exception as e:
        logger.error(f"Smart labeling error: {str(e)}")
        return emails

# Email Sending Function
def send_email(credentials, to, subject, body, cc=None, bcc=None):
    """Send an email using Gmail API"""
    try:
        service = build('gmail', 'v1', credentials=credentials)
        
        # Create message
        message = MIMEMultipart()
        message['to'] = to
        message['subject'] = subject
        
        if cc:
            message['cc'] = cc
        if bcc:
            message['bcc'] = bcc
            
        # Add HTML body
        html_part = MIMEText(body, 'html')
        message.attach(html_part)
        
        # Encode message
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        
        # Send message
        sent_message = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        
        logger.info(f"Email sent successfully. Message ID: {sent_message['id']}")
        return {'success': True, 'message_id': sent_message['id']}
        
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return {'success': False, 'error': str(e)}

# Voice Assistant Functions (Deployment-safe version)
def text_to_speech(text):
    """Convert text to speech - disabled in deployment"""
    logger.info(f"[TTS] Text-to-speech would say: {text}")
    # No-op in production - voice features not available
    return None

def speech_to_text():
    """Convert speech to text - disabled in deployment"""
    logger.info("[STT] Speech recognition attempted but unavailable in deployment")
    return "Voice input is not available in this environment. Please type your message instead."

# Base HTML Template
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gmail AI Assistant</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { 
            background-color: #1a202c;
            color: #e2e8f0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0;
            padding: 0;
        }
        .sidebar { 
            width: 250px;
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            background: #2d3748;
            padding: 20px;
            border-right: 1px solid #4a5568;
            overflow-y: auto;
            z-index: 1000;
        }
        .main-content { 
            margin-left: 250px;
            padding: 20px;
            min-height: 100vh;
        }
        .sidebar-link {
            display: block;
            padding: 10px 15px;
            color: #cbd5e0;
            text-decoration: none;
            border-radius: 5px;
            margin: 5px 0;
            transition: all 0.3s ease;
        }
        .sidebar-link:hover {
            background-color: #4a5568;
            color: white;
            transform: translateX(5px);
        }
        .sidebar-link.active {
            background-color: #4299e1;
            color: white;
        }
        .email-item {
            padding: 15px;
            border-bottom: 1px solid #4a5568;
            cursor: pointer;
            transition: all 0.3s ease;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .email-item:hover {
            background-color: #2d3748;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        .btn-primary {
            background-color: #2563eb;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
        }
        .btn-primary:hover {
            background-color: #1d4ed8;
            transform: translateY(-2px);
        }
        .login-btn {
            background: white;
            color: #333;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .login-btn:hover {
            background: #f8f9fa;
            color: #333;
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.2);
        }
        .priority-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }
        .priority-work { background: #dc3545; }
        .priority-medium { background: #ffc107; color: #000; }
        .priority-low { background: #6c757d; }
        .priority-promotions { background: #17a2b8; }
        .priority-spam { background: #6f42c1; }
        .stats-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            padding: 20px;
            color: white;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }
        .stats-card:hover {
            transform: translateY(-5px);
        }
        .ai-insight {
            background: #2d3748;
            border-left: 4px solid #4299e1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 8px 8px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transition: all 0.3s ease;
        }
        .card:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.2);
        }
        .alert {
            border-radius: 8px;
            border: none;
        }
        .email-subject {
            color: #ffffff;
            font-weight: 600;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        .email-body-content {
            background-color: #2d3748;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #4a5568;
            line-height: 1.6;
            color: #e2e8f0;
            margin-top: 1rem;
        }
        .email-body-content pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #e2e8f0;
            background: transparent;
            border: none;
            font-family: inherit;
        }
        .email-body-content * {
            color: #e2e8f0 !important;
        }
        .email-body-content a {
            color: #63b3ed !important;
            text-decoration: underline !important;
        }
        .email-body-content img {
            max-width: 100%;
            height: auto;
        }
        .email-body-content table {
            width: 100%;
            border-collapse: collapse;
        }
        .email-body-content table, 
        .email-body-content th, 
        .email-body-content td {
            border: 1px solid #4a5568;
        }
        .email-body-content th, 
        .email-body-content td {
            padding: 8px 12px;
            text-align: left;
        }
        .label-badge {
            background: #4299e1;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            margin: 2px;
            display: inline-block;
        }
        .compose-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: bold;
            margin: 10px 0;
            display: block;
            text-align: center;
            text-decoration: none;
            transition: all 0.3s ease;
        }
        .compose-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.2);
            color: white;
        }
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
            }
            .main-content {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="sidebar">
                <div class="text-center mb-4">
                    <h4><i class="fas fa-robot me-2"></i>Gmail AI</h4>
                    <small class="text-muted">Smart Email Management</small>
                </div>
                
                <div id="userInfo" style="display: none;">
                    <div class="mb-3 p-2 bg-dark rounded">
                        <small class="text-muted">Signed in as:</small>
                        <br>
                        <strong id="userEmail"></strong>
                    </div>
                </div>
                
                <a href="/" class="sidebar-link"><i class="fas fa-home me-2"></i>Home</a>
                <a href="/inbox" class="sidebar-link"><i class="fas fa-inbox me-2"></i>Inbox</a>
                <a href="/compose" class="sidebar-link"><i class="fas fa-edit me-2"></i>Compose Email</a>
                <a href="/ai-compose" class="sidebar-link"><i class="fas fa-robot me-2"></i>AI Compose</a>
                <a href="/dashboard" class="sidebar-link"><i class="fas fa-chart-bar me-2"></i>Analytics</a>
                <a href="/priority" class="sidebar-link"><i class="fas fa-bullseye me-2"></i>Priority Inbox</a>
                <a href="/compose-voice" class="sidebar-link"><i class="fas fa-microphone me-2"></i>Voice Compose</a>
                <a href="/smart-labels" class="sidebar-link"><i class="fas fa-tags me-2"></i>Smart Labels</a>
                <a href="/calendar" class="sidebar-link"><i class="fas fa-calendar-alt me-2"></i>Calendar</a>
                
                <div class="mt-4">
                    <h6 class="text-muted mb-3"><i class="fas fa-filter me-2"></i>Priority Filters</h6>
                    <div class="priority-filter" data-priority="work">
                        <div class="priority-color work-priority" style="width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 8px; background-color: #dc3545;"></div>
                        <span>Work Priority</span>
                    </div>
                    <div class="priority-filter" data-priority="medium">
                        <div class="priority-color medium-priority" style="width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 8px; background-color: #ffc107;"></div>
                        <span>Medium Priority</span>
                    </div>
                    <div class="priority-filter" data-priority="low">
                        <div class="priority-color low-priority" style="width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 8px; background-color: #6c757d;"></div>
                        <span>Low Priority</span>
                    </div>
                </div>
                
                <div id="logoutBtn" style="display: none;" class="mt-3">
                    <button onclick="logout()" class="btn btn-warning btn-sm w-100"><i class="fas fa-sign-out-alt me-2"></i>Sign Out</button>
                </div>
            </div>

            <!-- Main Content -->
            <div class="main-content">
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <div class="alert alert-info alert-dismissible fade show">
                                <i class="fas fa-info-circle me-2"></i>{{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}

                {{ content|safe }}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function checkAuth() {
            const user = localStorage.getItem('user_email');
            const tokens = localStorage.getItem('gmail_tokens');
            
            if (user && tokens) {
                document.getElementById('userInfo').style.display = 'block';
                document.getElementById('userEmail').textContent = user;
                document.getElementById('logoutBtn').style.display = 'block';
                return true;
            }
            return false;
        }

        function logout() {
            localStorage.removeItem('user_email');
            localStorage.removeItem('gmail_tokens');
            localStorage.removeItem('user_name');
            window.location.href = '/';
        }

        function updateUI() {
            const user = localStorage.getItem('user_email');
            if (user) {
                document.getElementById('signedOutView').style.display = 'none';
                document.getElementById('signedInView').style.display = 'block';
                document.getElementById('welcomeEmail').textContent = user;
            } else {
                document.getElementById('signedOutView').style.display = 'block';
                document.getElementById('signedInView').style.display = 'none';
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Check auth on page load
        document.addEventListener('DOMContentLoaded', function() {
            checkAuth();
            updateUI();
            
            // Set active sidebar link
            const currentPath = window.location.pathname;
            document.querySelectorAll('.sidebar-link').forEach(link => {
                if (link.getAttribute('href') === currentPath) {
                    link.classList.add('active');
                }
            });
        });
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    content = '''
    <div class="text-center mt-5">
        <h1><i class="fas fa-robot me-3"></i>Gmail AI Assistant</h1>
        <p class="text-muted mb-4">AI-powered email management with smart categorization and insights</p>
        
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div id="signedOutView">
                    <div class="card bg-dark border-secondary">
                        <div class="card-body py-5">
                            <h5><i class="fas fa-lock me-2"></i>Sign In with Google</h5>
                            <p class="text-muted">Access your Gmail with AI-powered features</p>
                            <div class="d-flex justify-content-center my-4">
                                <a href="/auth" class="login-btn">
                                    <i class="fab fa-google me-2"></i>Sign In with Google
                                </a>
                            </div>
                            <small class="text-muted">Your data is securely processed and never stored on our servers</small>
                        </div>
                    </div>
                </div>

                <div id="signedInView" style="display: none;">
                    <div class="card bg-dark border-success">
                        <div class="card-body py-5">
                            <h5><i class="fas fa-check-circle me-2"></i>Welcome back!</h5>
                            <p>You are signed in as <strong id="welcomeEmail"></strong></p>
                            <div class="d-flex gap-2 justify-content-center flex-wrap">
                                <a href="/inbox" class="btn btn-primary"><i class="fas fa-inbox me-2"></i>Go to Inbox</a>
                                <a href="/compose" class="btn btn-success"><i class="fas fa-edit me-2"></i>Compose Email</a>
                                <a href="/ai-compose" class="btn btn-info"><i class="fas fa-robot me-2"></i>AI Compose</a>
                                <a href="/dashboard" class="btn btn-outline-light"><i class="fas fa-chart-bar me-2"></i>View Analytics</a>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="mt-5">
                    <div class="row text-start">
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-robot me-2"></i>AI Categorization</h6>
                                    <small class="text-muted">Automatically categorize emails by priority using advanced AI</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-chart-bar me-2"></i>Smart Insights</h6>
                                    <small class="text-muted">Get analytics on your email habits and productivity patterns</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-microphone me-2"></i>Voice Assistant</h6>
                                    <small class="text-muted">Compose emails using voice commands with speech recognition</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-reply me-2"></i>Smart Replies</h6>
                                    <small class="text-muted">AI-generated contextual responses for quick email replies</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-paper-plane me-2"></i>AI Email Composition</h6>
                                    <small class="text-muted">Generate complete emails with AI based on your requirements</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-4">
                            <div class="card bg-dark h-100">
                                <div class="card-body">
                                    <h6><i class="fas fa-shield-alt me-2"></i>Privacy First</h6>
                                    <small class="text-muted">Your data stays secure and is processed locally when possible</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/auth')
def auth():
    """Start the OAuth flow"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            flash("OAuth configuration missing. Please check environment variables.")
            return redirect('/')
            
        domain = request.host_url.rstrip('/')
        redirect_uri = f"{domain}/oauth_callback"
        
        logger.info(f"Starting OAuth flow with redirect_uri: {redirect_uri}")
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true'
        )
        
        logger.info(f"Generated auth URL with {len(SCOPES)} scopes")
        return redirect(authorization_url)
        
    except Exception as e:
        error_msg = f'OAuth setup failed: {str(e)}'
        logger.error(f"OAuth Error: {error_msg}")
        flash(error_msg)
        return redirect('/')

@app.route('/oauth_callback')
def oauth_callback():
    """OAuth callback handler"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            flash("OAuth configuration missing.")
            return redirect('/')
            
        domain = request.host_url.rstrip('/')
        redirect_uri = f"{domain}/oauth_callback"
        
        logger.info(f"Handling OAuth callback with redirect_uri: {redirect_uri}")
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            state=request.args.get('state')
        )
        
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        logger.info(f"Token fetched successfully! Granted {len(credentials.scopes)} scopes")
        
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        credentials_data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'expiry': credentials.expiry.isoformat() if credentials.expiry else None
        }
        
        content = f'''
        <div class="text-center mt-5">
            <div class="card bg-dark border-success mx-auto" style="max-width: 500px;">
                <div class="card-body py-5">
                    <div class="mb-4">
                        <i class="fas fa-check-circle text-success" style="font-size: 3rem;"></i>
                    </div>
                    <h3>Successfully Signed In!</h3>
                    <p>Welcome <strong>{user_info.get('name', 'User')}</strong>!</p>
                    <p>Completing authentication...</p>
                    <div class="spinner-border text-primary mt-3"></div>
                </div>
            </div>
        </div>
        
        <script>
            localStorage.setItem('gmail_tokens', '{json.dumps(credentials_data).replace("'", "\\'")}');
            localStorage.setItem('user_email', '{user_info["email"]}');
            localStorage.setItem('user_name', '{user_info.get("name", "").replace("'", "\\'")}');
            
            setTimeout(function() {{
                window.location.href = '/inbox';
            }}, 2000);
        </script>
        '''
        return render_template_string(BASE_TEMPLATE, content=content)
        
    except Exception as e:
        error_msg = f'Sign in failed: {str(e)}'
        logger.error(f"OAuth Callback Error: {error_msg}")
        flash(error_msg)
        return redirect('/')

# New Compose Email Route
@app.route('/compose')
def compose_email():
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-edit me-2"></i>Compose Email</h3>
        <button class="btn btn-secondary" onclick="window.history.back()">
            <i class="fas fa-arrow-left me-2"></i>Back
        </button>
    </div>

    <div class="card bg-dark">
        <div class="card-body">
            <form id="composeForm">
                <div class="mb-3">
                    <label for="to" class="form-label">To:</label>
                    <input type="email" class="form-control bg-dark text-light" id="to" required multiple>
                    <small class="text-muted">For multiple recipients, separate emails with commas</small>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label for="cc" class="form-label">CC:</label>
                        <input type="email" class="form-control bg-dark text-light" id="cc">
                    </div>
                    <div class="col-md-6">
                        <label for="bcc" class="form-label">BCC:</label>
                        <input type="email" class="form-control bg-dark text-light" id="bcc">
                    </div>
                </div>
                
                <div class="mb-3">
                    <label for="subject" class="form-label">Subject:</label>
                    <input type="text" class="form-control bg-dark text-light" id="subject" required>
                </div>
                
                <div class="mb-3">
                    <label for="body" class="form-label">Message:</label>
                    <textarea class="form-control bg-dark text-light" id="body" rows="10" required></textarea>
                </div>
                
                <div class="d-flex gap-2">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-paper-plane me-2"></i>Send Email
                    </button>
                    <button type="button" class="btn btn-outline-secondary" onclick="saveDraft()">
                        <i class="fas fa-save me-2"></i>Save Draft
                    </button>
                    <button type="button" class="btn btn-outline-info" onclick="aiEnhance()">
                        <i class="fas fa-robot me-2"></i>AI Enhance
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        document.getElementById('composeForm').addEventListener('submit', function(e) {
            e.preventDefault();
            sendEmail();
        });

        async function sendEmail() {
            if (!checkAuth()) {
                alert('Please sign in first');
                return;
            }

            const to = document.getElementById('to').value;
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;
            const cc = document.getElementById('cc').value;
            const bcc = document.getElementById('bcc').value;

            if (!to || !subject || !body) {
                alert('Please fill in all required fields');
                return;
            }

            const tokens = JSON.parse(localStorage.getItem('gmail_tokens'));

            try {
                const response = await fetch('/api/send-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        tokens: tokens,
                        to: to,
                        subject: subject,
                        body: body,
                        cc: cc || null,
                        bcc: bcc || null
                    })
                });

                const data = await response.json();
                
                if (data.success) {
                    alert('Email sent successfully!');
                    window.location.href = '/inbox';
                } else {
                    alert('Failed to send email: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }

        function saveDraft() {
            alert('Draft saved functionality would be implemented here');
            // In a full implementation, this would save to Gmail drafts
        }

        async function aiEnhance() {
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;

            if (!body) {
                alert('Please enter some content to enhance');
                return;
            }

            try {
                const response = await fetch('/api/ai-enhance-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        subject: subject,
                        body: body
                    })
                });

                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('body').value = data.enhanced_body;
                    alert('Email enhanced with AI!');
                } else {
                    alert('AI enhancement failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }

        function checkAuth() {
            const tokens = localStorage.getItem('gmail_tokens');
            return !!tokens;
        }

        document.addEventListener('DOMContentLoaded', function() {
            if (!checkAuth()) {
                alert('Please sign in to compose emails');
                window.location.href = '/auth';
            }
        });
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

# New AI Compose Route
@app.route('/ai-compose')
def ai_compose():
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-robot me-2"></i>AI Email Composer</h3>
        <button class="btn btn-secondary" onclick="window.history.back()">
            <i class="fas fa-arrow-left me-2"></i>Back
        </button>
    </div>

    <div class="card bg-dark">
        <div class="card-body">
            <form id="aiComposeForm">
                <div class="mb-3">
                    <label for="recipient" class="form-label">Recipient:</label>
                    <input type="text" class="form-control bg-dark text-light" id="recipient" required 
                           placeholder="e.g., john@company.com or John Smith">
                </div>
                
                <div class="mb-3">
                    <label for="purpose" class="form-label">Email Purpose:</label>
                    <input type="text" class="form-control bg-dark text-light" id="purpose" required 
                           placeholder="e.g., Meeting request, Project update, Job inquiry">
                </div>
                
                <div class="mb-3">
                    <label for="context" class="form-label">Additional Context:</label>
                    <textarea class="form-control bg-dark text-light" id="context" rows="4" 
                              placeholder="Provide any additional details, key points to include, or specific requirements..."></textarea>
                </div>
                
                <div class="mb-3">
                    <label for="tone" class="form-label">Tone:</label>
                    <select class="form-control bg-dark text-light" id="tone">
                        <option value="professional">Professional</option>
                        <option value="casual">Casual</option>
                        <option value="friendly">Friendly</option>
                        <option value="formal">Formal</option>
                        <option value="urgent">Urgent</option>
                    </select>
                </div>
                
                <div class="d-flex gap-2">
                    <button type="button" class="btn btn-primary" onclick="generateEmail()">
                        <i class="fas fa-robot me-2"></i>Generate Email
                    </button>
                    <button type="button" class="btn btn-outline-secondary" onclick="clearForm()">
                        <i class="fas fa-trash me-2"></i>Clear
                    </button>
                </div>
            </form>
            
            <div id="generatedEmail" class="mt-4" style="display: none;">
                <h5>Generated Email:</h5>
                <div class="card bg-secondary">
                    <div class="card-body">
                        <div id="emailPreview" class="email-body-content"></div>
                    </div>
                </div>
                
                <div class="mt-3 d-flex gap-2">
                    <button class="btn btn-success" onclick="useGeneratedEmail()">
                        <i class="fas fa-check me-2"></i>Use This Email
                    </button>
                    <button class="btn btn-outline-warning" onclick="regenerateEmail()">
                        <i class="fas fa-redo me-2"></i>Regenerate
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function generateEmail() {
            const recipient = document.getElementById('recipient').value;
            const purpose = document.getElementById('purpose').value;
            const context = document.getElementById('context').value;
            const tone = document.getElementById('tone').value;

            if (!recipient || !purpose) {
                alert('Please fill in recipient and purpose fields');
                return;
            }

            try {
                const response = await fetch('/api/ai-compose-email', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        recipient: recipient,
                        purpose: purpose,
                        context: context,
                        tone: tone
                    })
                });

                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('emailPreview').innerHTML = data.email_content.replace(/\\n/g, '<br>');
                    document.getElementById('generatedEmail').style.display = 'block';
                    
                    // Scroll to generated email
                    document.getElementById('generatedEmail').scrollIntoView({ behavior: 'smooth' });
                } else {
                    alert('AI composition failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            }
        }

        function useGeneratedEmail() {
            const emailContent = document.getElementById('emailPreview').textContent;
            // Store in localStorage and redirect to compose page
            localStorage.setItem('ai_generated_email', emailContent);
            window.location.href = '/compose';
        }

        function regenerateEmail() {
            generateEmail();
        }

        function clearForm() {
            document.getElementById('aiComposeForm').reset();
            document.getElementById('generatedEmail').style.display = 'none';
        }

        // Check if we have a generated email to pre-fill
        document.addEventListener('DOMContentLoaded', function() {
            const generatedEmail = localStorage.getItem('ai_generated_email');
            if (generatedEmail) {
                localStorage.removeItem('ai_generated_email');
                // You could pre-fill the compose form here if needed
            }
        });
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/inbox')
def inbox():
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-inbox me-2"></i>Smart Inbox</h3>
        <div>
            <a href="/compose" class="btn btn-success me-2">
                <i class="fas fa-edit me-2"></i>Compose
            </a>
            <button class="btn btn-primary" onclick="loadEmails()">
                <i class="fas fa-sync-alt me-2"></i>Refresh
            </button>
            <button class="btn btn-outline-info" onclick="analyzeAllEmails()">
                <i class="fas fa-robot me-2"></i>AI Analyze All
            </button>
        </div>
    </div>

    <div id="userStatus" class="mb-3">
        <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle me-2"></i><strong>Please sign in to view your emails</strong>
        </div>
    </div>

    <div class="row mb-4" id="statsSection" style="display: none;">
        <div class="col-md-3 mb-3">
            <div class="stats-card">
                <h4 id="totalEmails">0</h4>
                <p>Total Emails</p>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="stats-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <h4 id="workEmails">0</h4>
                <p>Work Priority</p>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="stats-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <h4 id="promoEmails">0</h4>
                <p>Promotions</p>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="stats-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                <h4 id="lowEmails">0</h4>
                <p>Low Priority</p>
            </div>
        </div>
    </div>

    <div id="aiInsights" class="mb-4" style="display: none;">
        <h5><i class="fas fa-robot me-2"></i>AI Insights</h5>
        <div class="ai-insight">
            <p id="insightText">Analyzing your email patterns...</p>
        </div>
    </div>

    <div id="emailList">
        <div class="text-center text-muted py-5">
            <i class="fas fa-inbox" style="font-size: 3rem; opacity: 0.5;"></i>
            <p class="mt-3">Sign in to load your emails</p>
        </div>
    </div>

    <script>
        function checkAuth() {
            const tokens = localStorage.getItem('gmail_tokens');
            const userEmail = localStorage.getItem('user_email');
            
            if (tokens && userEmail) {
                document.getElementById('userStatus').innerHTML = '<div class="alert alert-info"><i class="fas fa-check-circle me-2"></i><small>Showing emails for: <strong>' + userEmail + '</strong></small></div>';
                return true;
            }
            return false;
        }

        async function loadEmails() {
            if (!checkAuth()) {
                alert('Please sign in first');
                window.location.href = '/';
                return;
            }

            const tokens = JSON.parse(localStorage.getItem('gmail_tokens'));
            const emailList = document.getElementById('emailList');
            
            emailList.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div><p class="mt-2">Loading your emails...</p></div>';

            try {
                const response = await fetch('/api/emails', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ tokens: tokens })
                });

                const data = await response.json();
                
                if (data.success) {
                    displayEmails(data.emails);
                    updateStats(data.stats);
                    showAIInsights(data.stats);
                } else {
                    let errorHtml = '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Error loading emails: ' + (data.error || 'Unknown error');
                    if (data.error && data.error.includes('token')) {
                        errorHtml += '<br><a href="/auth" class="btn btn-warning btn-sm mt-2">Re-authenticate</a>';
                    }
                    errorHtml += '</div>';
                    emailList.innerHTML = errorHtml;
                }
            } catch (error) {
                emailList.innerHTML = '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Network error: ' + error.message + '</div>';
            }
        }

        async function analyzeAllEmails() {
            if (!checkAuth()) {
                alert('Please sign in first');
                return;
            }

            const emailList = document.getElementById('emailList');
            const originalContent = emailList.innerHTML;
            
            emailList.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div><p class="mt-2">AI is analyzing all emails...</p></div>';

            try {
                const tokens = JSON.parse(localStorage.getItem('gmail_tokens'));
                const response = await fetch('/api/analyze-all-emails', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ tokens: tokens })
                });

                const data = await response.json();
                
                if (data.success) {
                    displayEmails(data.emails);
                    showAdvancedInsights(data.analysis);
                } else {
                    emailList.innerHTML = originalContent;
                    alert('AI analysis failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                emailList.innerHTML = originalContent;
                alert('Network error: ' + error.message);
            }
        }

        function displayEmails(emails) {
            const emailList = document.getElementById('emailList');
            
            if (!emails || emails.length === 0) {
                emailList.innerHTML = '<div class="alert alert-info"><i class="fas fa-info-circle me-2"></i>No emails found in the last 24 hours</div>';
                return;
            }

            let html = '';
            emails.forEach(function(email) {
                const snippet = email.snippet.length > 100 ? email.snippet.substring(0, 100) + '...' : email.snippet;
                const priorityClass = 'priority-' + email.priority;
                const labels = email.ai_labels || [];
                
                html += `
                    <div class="email-item" onclick="viewEmailSummary('${email.id}')">
                        <div class="row align-items-center">
                            <div class="col-md-2"><strong>${escapeHtml(email.sender)}</strong></div>
                            <div class="col-md-5">
                                <strong>${escapeHtml(email.subject)}</strong>
                                <br>
                                <small class="text-muted">${escapeHtml(snippet)}</small>
                                <div class="mt-1">
                                    ${labels.map(label => `<span class="label-badge">${label}</span>`).join('')}
                                </div>
                            </div>
                            <div class="col-md-2 text-center">
                                <span class="priority-badge ${priorityClass}">${email.priority}</span>
                            </div>
                            <div class="col-md-2 text-end">
                                <small class="text-muted">${escapeHtml(email.date)}</small>
                                <div class="mt-1">
                                    <button class="btn btn-sm btn-outline-info" onclick="event.stopPropagation(); generateQuickReply('${email.id}')">
                                        <i class="fas fa-reply"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });

            emailList.innerHTML = html;
        }

        function updateStats(stats) {
            document.getElementById('statsSection').style.display = 'flex';
            document.getElementById('totalEmails').textContent = stats.total;
            document.getElementById('workEmails').textContent = stats.work;
            document.getElementById('promoEmails').textContent = stats.promotions;
            document.getElementById('lowEmails').textContent = stats.low;
        }

        function showAIInsights(stats) {
            document.getElementById('aiInsights').style.display = 'block';
            const insightText = document.getElementById('insightText');
            
            if (stats.work > stats.promotions && stats.work > stats.low) {
                insightText.innerHTML = '<i class="fas fa-chart-line me-2"></i>Most of your emails are work-related. Consider scheduling focused work periods.';
            } else if (stats.promotions > stats.work) {
                insightText.innerHTML = '<i class="fas fa-shopping-cart me-2"></i>You have many promotional emails. Consider creating filters for better organization.';
            } else {
                insightText.innerHTML = '<i class="fas fa-balance-scale me-2"></i>Your email distribution looks balanced. Keep managing your inbox effectively!';
            }
        }

        function showAdvancedInsights(analysis) {
            const insightText = document.getElementById('insightText');
            insightText.innerHTML = '<i class="fas fa-robot me-2"></i>' + (analysis || 'AI analysis completed successfully.');
        }

        function viewEmailSummary(emailId) {
            window.location.href = `/email/${emailId}/summary`;
        }

        function viewEmail(emailId) {
            window.location.href = `/email/${emailId}`;
        }

        function generateQuickReply(emailId) {
            window.location.href = `/email/${emailId}/smart-reply`;
        }

        document.addEventListener('DOMContentLoaded', function() {
            if (checkAuth()) {
                loadEmails();
            }
        });
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

# API Routes for new features
@app.route('/api/send-email', methods=['POST'])
def api_send_email():
    """API endpoint to send email"""
    try:
        data = request.json
        tokens = data.get('tokens')
        to = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        cc = data.get('cc')
        bcc = data.get('bcc')
        
        if not tokens or not to or not subject or not body:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        # Convert plain text to HTML for better formatting
        html_body = f"<div style='font-family: Arial, sans-serif; line-height: 1.6;'>{body.replace(chr(10), '<br>')}</div>"
        
        result = send_email(credentials, to, subject, html_body, cc, bcc)
        
        if result['success']:
            return jsonify({'success': True, 'message_id': result['message_id']})
        else:
            return jsonify({'success': False, 'error': result['error']})
            
    except Exception as e:
        logger.error(f"Send email error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ai-compose-email', methods=['POST'])
def api_ai_compose_email():
    """API endpoint for AI email composition"""
    try:
        data = request.json
        recipient = data.get('recipient')
        purpose = data.get('purpose')
        context = data.get('context', '')
        tone = data.get('tone', 'professional')
        
        if not recipient or not purpose:
            return jsonify({'success': False, 'error': 'Recipient and purpose are required'})
        
        email_content = generate_ai_composed_email(context, recipient, purpose, tone)
        
        return jsonify({
            'success': True, 
            'email_content': email_content
        })
        
    except Exception as e:
        logger.error(f"AI compose error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ai-enhance-email', methods=['POST'])
def api_ai_enhance_email():
    """API endpoint to enhance existing email with AI"""
    try:
        data = request.json
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        if not body:
            return jsonify({'success': False, 'error': 'Email body is required'})
        
        model = setup_gemini()
        if not model:
            return jsonify({'success': False, 'error': 'AI service unavailable'})
        
        prompt = f"""
        Please enhance and improve this email content. Make it more professional, clear, and effective:
        
        Subject: {subject}
        Current Content: {body}
        
        Please return only the enhanced version of the email body content, maintaining the original intent but improving clarity, grammar, and professionalism.
        """
        
        response = model.generate_content(prompt)
        enhanced_body = response.text
        
        return jsonify({
            'success': True, 
            'enhanced_body': enhanced_body
        })
        
    except Exception as e:
        logger.error(f"AI enhance error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# KEEP ALL YOUR EXISTING ROUTES AND FUNCTIONS - THEY REMAIN UNCHANGED
@app.route('/compose-voice')
def compose_voice():
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-microphone me-2"></i>Voice Compose</h3>
        <button class="btn btn-secondary" onclick="window.history.back()">
            <i class="fas fa-arrow-left me-2"></i>Back
        </button>
    </div>

    <div class="card bg-dark">
        <div class="card-body">
            <div class="text-center py-4">
                <i class="fas fa-microphone" style="font-size: 3rem;"></i>
                <p class="mt-3">Click to start voice recording</p>
                
                <div class="mb-4">
                    <button id="startRecord" class="btn btn-primary btn-lg" onclick="startRecording()">
                        <i class="fas fa-microphone me-2"></i>Start Recording
                    </button>
                    <button id="stopRecord" class="btn btn-danger btn-lg" onclick="stopRecording()" style="display: none;">
                        <i class="fas fa-stop me-2"></i>Stop Recording
                    </button>
                </div>
                
                <div id="recordingStatus" class="alert alert-info" style="display: none;">
                    <i class="fas fa-circle text-danger me-2"></i>Recording... Speak now
                </div>
                
                <div id="transcriptResult" style="display: none;">
                    <h5>Transcript:</h5>
                    <div class="bg-secondary p-3 rounded mb-3">
                        <p id="transcriptText"></p>
                    </div>
                    <button class="btn btn-success" onclick="useTranscript()">
                        <i class="fas fa-check me-2"></i>Use This Text
                    </button>
                    <button class="btn btn-warning" onclick="retryRecording()">
                        <i class="fas fa-redo me-2"></i>Try Again
                    </button>
                </div>

                <div class="mt-4">
                    <div class="alert alert-warning">
                        <i class="fas fa-info-circle me-2"></i>
                        Note: Voice recording is not available in the deployed version. This is a demonstration interface.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function startRecording() {
            alert('Voice recording is not available in the deployed version. Using demo text instead.');
            simulateVoiceInput();
        }
        
        function stopRecording() {
            // No-op in deployment
        }
        
        function simulateVoiceInput() {
            // Demo voice input
            const demoText = "Hello, I would like to schedule a meeting for next Tuesday at 2 PM to discuss the project timeline. Please let me know if that works for you.";
            document.getElementById('transcriptText').textContent = demoText;
            document.getElementById('transcriptResult').style.display = 'block';
            document.getElementById('startRecord').style.display = 'none';
            document.getElementById('stopRecord').style.display = 'none';
            document.getElementById('recordingStatus').style.display = 'none';
        }
        
        function useTranscript() {
            const text = document.getElementById('transcriptText').textContent;
            alert('In full implementation, this would open the compose window with: ' + text);
        }
        
        function retryRecording() {
            document.getElementById('transcriptResult').style.display = 'none';
            document.getElementById('startRecord').style.display = 'inline-block';
        }
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/smart-labels')
def smart_labels():
    content = '''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-tags me-2"></i>Smart Labels</h3>
        <button class="btn btn-primary" onclick="analyzeLabels()">
            <i class="fas fa-robot me-2"></i>Analyze Emails
        </button>
    </div>

    <div class="alert alert-info">
        <i class="fas fa-info-circle me-2"></i>
        AI-powered email labeling automatically categorizes your emails for better organization.
    </div>

    <div id="labelsResults" class="mt-4">
        <div class="text-center text-muted py-5">
            <i class="fas fa-tags" style="font-size: 3rem; opacity: 0.5;"></i>
            <p class="mt-3">Click "Analyze Emails" to see AI-generated labels</p>
        </div>
    </div>

    <script>
        async function analyzeLabels() {
            const tokens = localStorage.getItem('gmail_tokens');
            if (!tokens) {
                alert('Please sign in first');
                window.location.href = '/auth';
                return;
            }

            const labelsResults = document.getElementById('labelsResults');
            labelsResults.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-primary"></div><p class="mt-2">AI is analyzing your emails...</p></div>';

            try {
                const response = await fetch('/api/analyze-labels', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ tokens: JSON.parse(tokens) })
                });

                const data = await response.json();
                
                if (data.success) {
                    displayLabelAnalysis(data.analysis);
                } else {
                    labelsResults.innerHTML = '<div class="alert alert-danger">Error: ' + (data.error || 'Unknown error') + '</div>';
                }
            } catch (error) {
                labelsResults.innerHTML = '<div class="alert alert-danger">Network error: ' + error.message + '</div>';
            }
        }

        function displayLabelAnalysis(analysis) {
            let html = '<div class="row">';
            
            // Label distribution
            html += `
                <div class="col-md-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header">
                            <h6><i class="fas fa-chart-pie me-2"></i>Label Distribution</h6>
                        </div>
                        <div class="card-body">
            `;
            
            if (analysis.label_distribution) {
                for (const [label, count] of Object.entries(analysis.label_distribution)) {
                    html += `
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="label-badge">${label}</span>
                            <span class="text-muted">${count} emails</span>
                        </div>
                    `;
                }
            }
            
            html += `
                        </div>
                    </div>
                </div>
            `;

            // AI Recommendations
            html += `
                <div class="col-md-6">
                    <div class="card bg-dark h-100">
                        <div class="card-header">
                            <h6><i class="fas fa-lightbulb me-2"></i>AI Recommendations</h6>
                        </div>
                        <div class="card-body">
                            <div class="ai-insight">
                                <p>${analysis.recommendations || 'Based on your email patterns, consider creating filters for better organization.'}</p>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            html += '</div>';
            document.getElementById('labelsResults').innerHTML = html;
        }
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/email/<email_id>/summary')
def email_summary(email_id):
    content = f'''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-robot me-2"></i>AI Email Analysis</h3>
        <div>
            <button class="btn btn-secondary" onclick="window.history.back()">
                <i class="fas fa-arrow-left me-2"></i>Back
            </button>
            <button class="btn btn-primary" onclick="generateSmartReply('{email_id}')">
                <i class="fas fa-reply me-2"></i>AI Reply
            </button>
        </div>
    </div>

    <div id="emailAnalysis" class="text-center py-4">
        <div class="spinner-border text-primary"></div>
        <p class="mt-3">AI is analyzing this email...</p>
    </div>

    <script>
        async function loadEmailAnalysis() {{
            const tokens = localStorage.getItem('gmail_tokens');
            if (!tokens) {{
                document.getElementById('emailAnalysis').innerHTML = 
                    '<div class="alert alert-danger">Please sign in first</div>';
                return;
            }}

            try {{
                const response = await fetch('/api/email/{email_id}/analyze', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ tokens: JSON.parse(tokens) }})
                }});

                const data = await response.json();
                
                if (data.success) {{
                    displayEmailAnalysis(data);
                }} else {{
                    document.getElementById('emailAnalysis').innerHTML = 
                        '<div class="alert alert-danger">Error: ' + (data.error || 'Unknown error') + '</div>';
                }}
            }} catch (error) {{
                document.getElementById('emailAnalysis').innerHTML = 
                    '<div class="alert alert-danger">Network error: ' + error.message + '</div>';
            }}
        }}

        function displayEmailAnalysis(data) {{
            const email = data.email;
            const html = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card bg-dark mb-4">
                        <div class="card-body">
                            <h4 class="email-subject">${{escapeHtml(email.subject)}}</h4>
                            <div class="row mt-3">
                                <div class="col-md-6">
                                    <p><strong>From:</strong> ${{escapeHtml(email.sender)}}</p>
                                </div>
                                <div class="col-md-6">
                                    <p><strong>Date:</strong> ${{escapeHtml(email.date)}}</p>
                                </div>
                            </div>
                            <div class="email-body-content mt-3">
                                ${{email.body ? email.body : '<p class="text-muted">No content available</p>'}}
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4">
                    <div class="card bg-dark mb-4">
                        <div class="card-header">
                            <h6><i class="fas fa-robot me-2"></i>AI Summary</h6>
                        </div>
                        <div class="card-body">
                            <div class="ai-insight">
                                ${{email.summary ? email.summary.replace(/\\n/g, '<br>') : '<p class="text-muted">No summary available</p>'}}
                            </div>
                        </div>
                    </div>
                    
                    <div class="card bg-dark mb-4">
                        <div class="card-header">
                            <h6><i class="fas fa-tags me-2"></i>Smart Labels</h6>
                        </div>
                        <div class="card-body">
                            ${{email.ai_labels ? email.ai_labels.map(label => 
                                '<span class="label-badge">' + label + '</span>'
                            ).join('') : '<p class="text-muted">No labels generated</p>'}}
                        </div>
                    </div>
                    
                    <div class="card bg-dark">
                        <div class="card-header">
                            <h6><i class="fas fa-bullseye me-2"></i>Priority</h6>
                        </div>
                        <div class="card-body">
                            <span class="priority-badge priority-${{email.priority}}">${{email.priority}}</span>
                        </div>
                    </div>
                </div>
            </div>
            `;
            
            document.getElementById('emailAnalysis').innerHTML = html;
        }}

        function generateSmartReply(emailId) {{
            window.location.href = '/email/${{emailId}}/smart-reply';
        }}

        document.addEventListener('DOMContentLoaded', loadEmailAnalysis);
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/email/<email_id>/smart-reply')
def smart_reply(email_id):
    content = f'''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-robot me-2"></i>AI Smart Reply</h3>
        <button class="btn btn-secondary" onclick="window.history.back()">
            <i class="fas fa-arrow-left me-2"></i>Back
        </button>
    </div>

    <div id="smartReplyContent" class="text-center py-4">
        <div class="spinner-border text-primary"></div>
        <p class="mt-3">AI is generating smart reply options...</p>
    </div>

    <script>
        async function loadSmartReplies() {{
            const tokens = localStorage.getItem('gmail_tokens');
            if (!tokens) {{
                document.getElementById('smartReplyContent').innerHTML = 
                    '<div class="alert alert-danger">Please sign in first</div>';
                return;
            }}

            try {{
                const response = await fetch('/api/email/{email_id}/smart-reply', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ tokens: JSON.parse(tokens) }})
                }});

                const data = await response.json();
                
                if (data.success) {{
                    displaySmartReplies(data.replies);
                }} else {{
                    document.getElementById('smartReplyContent').innerHTML = 
                        '<div class="alert alert-danger">Error: ' + (data.error || 'Unknown error') + '</div>';
                }}
            }} catch (error) {{
                document.getElementById('smartReplyContent').innerHTML = 
                    '<div class="alert alert-danger">Network error: ' + error.message + '</div>';
            }}
        }}

        function displaySmartReplies(replyText) {{
            const html = `
            <div class="card bg-dark">
                <div class="card-body">
                    <h5><i class="fas fa-lightbulb me-2"></i>Smart Reply Options</h5>
                    <div class="ai-insight mt-3">
                        <pre style="white-space: pre-wrap; color: #e2e8f0;">${{escapeHtml(replyText)}}</pre>
                    </div>
                    <div class="mt-4">
                        <button class="btn btn-primary" onclick="useSmartReply()">
                            <i class="fas fa-check me-2"></i>Use Selected Reply
                        </button>
                        <button class="btn btn-outline-secondary" onclick="regenerateReplies()">
                            <i class="fas fa-redo me-2"></i>Generate More Options
                        </button>
                    </div>
                </div>
            </div>
            `;
            
            document.getElementById('smartReplyContent').innerHTML = html;
        }}

        function useSmartReply() {{
            alert('In full implementation, this would open the compose window with the selected reply.');
        }}

        function regenerateReplies() {{
            loadSmartReplies();
        }}

        document.addEventListener('DOMContentLoaded', loadSmartReplies);
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

# API Routes
@app.route('/api/speech-to-text', methods=['POST'])
def api_speech_to_text():
    """API endpoint for speech to text - disabled in deployment"""
    return jsonify({
        'success': True, 
        'text': 'Voice input is not available in the deployed version. Please use text input instead. This is a demonstration of the voice interface.'
    })

@app.route('/api/email/<email_id>/analyze', methods=['POST'])
def api_analyze_email(email_id):
    """API endpoint for AI email analysis"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        email_data = get_email_data(email_id, tokens)
        if not email_data:
            return jsonify({'success': False, 'error': 'Could not fetch email'})
        
        # Enhance with AI features
        email_data['summary'] = summarize_email(
            email_data['subject'], 
            email_data.get('body', email_data['snippet']), 
            email_data['snippet']
        )
        
        email_data['ai_labels'] = get_ai_labels(
            email_data['subject'],
            email_data.get('body', email_data['snippet']),
            email_data['sender']
        )
        
        return jsonify({
            'success': True, 
            'email': email_data
        })
        
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/email/<email_id>/smart-reply', methods=['POST'])
def api_smart_reply(email_id):
    """API endpoint for smart reply generation"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        email_data = get_email_data(email_id, tokens)
        if not email_data:
            return jsonify({'success': False, 'error': 'Could not fetch email'})
        
        smart_replies = generate_smart_reply(
            email_data['subject'],
            email_data.get('body', email_data['snippet']),
            email_data['sender']
        )
        
        return jsonify({
            'success': True, 
            'replies': smart_replies
        })
        
    except Exception as e:
        logger.error(f"Smart reply error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze-labels', methods=['POST'])
def api_analyze_labels():
    """API endpoint for analyzing email labels"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        # Get recent emails
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        if credentials.expired:
            credentials.refresh(Request())
        
        service = build('gmail', 'v1', credentials=credentials)
        
        yesterday = datetime.now() - timedelta(hours=24)
        query = f'after:{int(yesterday.timestamp())} in:inbox'
        
        result = service.users().messages().list(userId='me', maxResults=10, q=query).execute()
        messages = result.get('messages', [])
        
        label_distribution = {}
        all_labels = []
        
        for msg in messages:
            try:
                message = service.users().messages().get(
                    userId='me', 
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From']
                ).execute()
                
                headers = message.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
                sender_name = sender.split('<')[0].strip().replace('"', '') if '<' in sender else sender
                
                labels = get_ai_labels(subject, message.get('snippet', ''), sender_name)
                all_labels.extend(labels)
                
            except Exception as e:
                continue
        
        # Count label distribution
        for label in all_labels:
            label_distribution[label] = label_distribution.get(label, 0) + 1
        
        analysis = {
            'label_distribution': label_distribution,
            'recommendations': generate_label_recommendations(label_distribution)
        }
        
        return jsonify({
            'success': True, 
            'analysis': analysis
        })
        
    except Exception as e:
        logger.error(f"Label analysis error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze-all-emails', methods=['POST'])
def api_analyze_all_emails():
    """API endpoint for analyzing all emails with AI"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        if credentials.expired:
            credentials.refresh(Request())
        
        service = build('gmail', 'v1', credentials=credentials)
        
        yesterday = datetime.now() - timedelta(hours=24)
        query = f'after:{int(yesterday.timestamp())} in:inbox'
        
        result = service.users().messages().list(userId='me', maxResults=15, q=query).execute()
        messages = result.get('messages', [])
        
        emails = []
        priority_stats = {
            'work': 0,
            'medium': 0,
            'low': 0,
            'promotions': 0,
            'spam': 0,
            'total': len(messages)
        }
        
        for msg in messages:
            try:
                message = service.users().messages().get(
                    userId='me', 
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
                
                try:
                    from email.utils import parsedate_to_datetime
                    date_obj = parsedate_to_datetime(date)
                    simple_date = date_obj.strftime("%b %d, %I:%M %p")
                except:
                    simple_date = date[:16] if len(date) > 16 else date
                
                sender_name = sender.split('<')[0].strip().replace('"', '') if '<' in sender else sender
                
                priority = analyze_email_priority(subject, message.get('snippet', ''), sender_name)
                priority_stats[priority] += 1
                
                # AI Analysis
                ai_labels = get_ai_labels(subject, message.get('snippet', ''), sender_name)
                summary = summarize_email(subject, message.get('snippet', ''), message.get('snippet', ''))
                
                emails.append({
                    'id': msg['id'],
                    'subject': subject,
                    'sender': sender_name,
                    'snippet': message.get('snippet', 'No preview available'),
                    'date': simple_date,
                    'priority': priority,
                    'ai_labels': ai_labels,
                    'summary': summary
                })
            except Exception as e:
                logger.warning(f"Error processing message {msg.get('id')}: {str(e)}")
                continue
        
        # Generate overall analysis
        overall_analysis = generate_overall_analysis(emails, priority_stats)
        
        return jsonify({
            'success': True, 
            'emails': emails,
            'stats': priority_stats,
            'analysis': overall_analysis
        })
        
    except Exception as e:
        logger.error(f"Analyze all emails error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# Helper functions
def get_email_data(email_id, tokens):
    """Helper function to get email data"""
    try:
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        if credentials.expired:
            credentials.refresh(Request())
        
        service = build('gmail', 'v1', credentials=credentials)
        message = service.users().messages().get(userId='me', id=email_id, format='full').execute()
        
        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
        
        try:
            from email.utils import parsedate_to_datetime
            date_obj = parsedate_to_datetime(date)
            formatted_date = date_obj.strftime("%A, %B %d, %Y at %I:%M %p")
        except:
            formatted_date = date
        
        body = extract_email_body(message.get('payload', {}))
        priority = analyze_email_priority(subject, body, sender)
        
        return {
            'id': email_id,
            'subject': subject,
            'sender': sender.split('<')[0].strip().replace('"', '') if '<' in sender else sender,
            'date': formatted_date,
            'body': body,
            'priority': priority,
            'snippet': message.get('snippet', '')
        }
    except Exception as e:
        logger.error(f"Get email data error: {str(e)}")
        return None

def extract_email_body(payload):
    """Extract the email body from the payload"""
    try:
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                mime_type = part.get('mimeType', '')
                if mime_type == 'text/html' and 'body' in part and 'data' in part['body']:
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
                elif mime_type == 'text/plain' and 'body' in part and 'data' in part['body']:
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
        
        if not body and 'body' in payload and 'data' in payload['body']:
            data = payload['body']['data']
            body = base64.urlsafe_b64decode(data).decode('utf-8')
        
        if not body:
            return "No email content available"
        
        return body
        
    except Exception as e:
        logger.error(f"Error extracting email body: {str(e)}")
        return "Error loading email content"

def analyze_email_priority(subject, snippet, sender):
    """AI-powered email priority analysis"""
    content = (subject + ' ' + snippet).lower()
    sender_lower = sender.lower()
    
    work_keywords = ['urgent', 'asap', 'important', 'project', 'meeting', 'deadline', 'boss', 'manager', 'team', 'report', 'presentation', 'review', 'action required']
    promo_keywords = ['sale', 'discount', 'offer', 'deal', 'promo', 'buy now', 'limited time', 'coupon', 'save', 'special', 'exclusive', 'offer']
    spam_keywords = ['winner', 'prize', 'free', 'congratulations', 'lottery', 'click here', 'unsubscribe', 'selected', 'cash', 'million']
    
    work_score = sum(1 for keyword in work_keywords if keyword in content)
    promo_score = sum(1 for keyword in promo_keywords if keyword in content)
    spam_score = sum(1 for keyword in spam_keywords if keyword in content)
    
    if any(domain in sender_lower for domain in ['company.com', 'work.com', 'corporate.com', 'hr.', 'manager']):
        work_score += 2
    
    if spam_score >= 2:
        return 'spam'
    elif work_score >= 2:
        return 'work'
    elif promo_score >= 2:
        return 'promotions'
    elif work_score >= 1:
        return 'medium'
    else:
        return 'low'

def generate_label_recommendations(label_distribution):
    """Generate recommendations based on label distribution"""
    try:
        model = setup_gemini()
        if not model:
            return "Consider creating filters for frequently occurring labels."
        
        prompt = f"""
        Based on this email label distribution: {label_distribution}
        Provide 2-3 practical recommendations for email management and organization.
        Keep it concise and actionable.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except:
        return "Consider creating filters for your most common email types to automate organization."

def generate_overall_analysis(emails, stats):
    """Generate overall analysis of emails"""
    try:
        model = setup_gemini()
        if not model:
            return "AI analysis completed. Review your emails for patterns."
        
        prompt = f"""
        Analyze this email dataset:
        - Total emails: {stats['total']}
        - Work priority: {stats['work']}
        - Medium priority: {stats['medium']} 
        - Low priority: {stats['low']}
        - Promotions: {stats['promotions']}
        
        Provide a brief 2-3 sentence analysis of the email patterns and one suggestion for productivity improvement.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except:
        return f"Analyzed {stats['total']} emails. {stats['work']} require immediate attention."

# Existing routes (dashboard, priority, calendar, email view, api/emails, api/email)
@app.route('/dashboard')
def dashboard():
    content = '''
    <h3><i class="fas fa-chart-bar me-2"></i>Email Analytics Dashboard</h3>
    <p class="text-muted">AI-powered insights into your email habits</p>
    
    <div class="row mt-4">
        <div class="col-md-4 mb-4">
            <div class="card bg-dark text-center">
                <div class="card-body">
                    <h4><i class="fas fa-inbox"></i></h4>
                    <h5>Inbox Zero</h5>
                    <p class="mb-0">AI-powered organization</p>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-4">
            <div class="card bg-dark text-center">
                <div class="card-body">
                    <h4><i class="fas fa-robot"></i></h4>
                    <h5>Smart Sorting</h5>
                    <p class="mb-0">Automatic categorization</p>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-4">
            <div class="card bg-dark text-center">
                <div class="card-body">
                    <h4><i class="fas fa-bolt"></i></h4>
                    <h5>Fast Processing</h5>
                    <p class="mb-0">Real-time analysis</p>
                </div>
            </div>
        </div>
    </div>

    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card bg-dark">
                <div class="card-body">
                    <h5><i class="fas fa-chart-pie me-2"></i>Email Distribution</h5>
                    <div class="text-center py-4">
                        <p class="text-muted">Sign in to view your personalized email analytics</p>
                        <a href="/auth" class="btn btn-primary">
                            <i class="fab fa-google me-2"></i>Sign In to View Analytics
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/priority')
def priority():
    content = '''
    <h3><i class="fas fa-bullseye me-2"></i>Priority Inbox</h3>
    <p class="text-muted">Focus on what matters most</p>
    
    <div class="alert alert-info">
        <i class="fas fa-info-circle me-2"></i>
        This feature shows only high-priority emails that require your immediate attention.
    </div>

    <div class="card bg-dark">
        <div class="card-body">
            <div class="text-center py-5">
                <i class="fas fa-bullseye" style="font-size: 3rem; opacity: 0.5;"></i>
                <p class="mt-3">Sign in to access your priority inbox</p>
                <a href="/auth" class="btn btn-primary">
                    <i class="fab fa-google me-2"></i>Sign In to View Priority Emails
                </a>
            </div>
        </div>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/calendar')
def calendar():
    content = '''
    <h3><i class="fas fa-calendar-alt me-2"></i>Calendar Integration</h3>
    <p class="text-muted">Coming Soon: AI-powered calendar management</p>
    
    <div class="card bg-dark">
        <div class="card-body">
            <div class="text-center py-5">
                <i class="fas fa-calendar-plus" style="font-size: 3rem; opacity: 0.5;"></i>
                <p class="mt-3">Calendar features coming soon!</p>
                <p class="text-muted">This feature will integrate with your Google Calendar to provide AI-powered scheduling insights.</p>
            </div>
        </div>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/email/<email_id>')
def view_email(email_id):
    content = f'''
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3><i class="fas fa-envelope me-2"></i>Email Details</h3>
        <button class="btn btn-secondary" onclick="window.history.back()">
            <i class="fas fa-arrow-left me-2"></i>Back to Inbox
        </button>
    </div>

    <div id="emailContent" class="text-center py-5">
        <div class="spinner-border text-primary"></div>
        <p class="mt-3">Loading email content...</p>
    </div>

    <script>
        async function loadEmailContent() {{
            const tokens = localStorage.getItem('gmail_tokens');
            if (!tokens) {{
                document.getElementById('emailContent').innerHTML = 
                    '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Please sign in to view emails</div>';
                return;
            }}

            try {{
                const response = await fetch('/api/email/{email_id}', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ tokens: JSON.parse(tokens) }})
                }});

                const data = await response.json();
                
                if (data.success) {{
                    displayEmailContent(data.email);
                }} else {{
                    document.getElementById('emailContent').innerHTML = 
                        '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Error loading email: ' + 
                        (data.error || 'Unknown error') + '</div>';
                }}
            }} catch (error) {{
                document.getElementById('emailContent').innerHTML = 
                    '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Network error: ' + error.message + '</div>';
            }}
        }}

        function displayEmailContent(email) {{
            const emailContent = document.getElementById('emailContent');
            
            let bodyContent = email.body;
            if (!bodyContent || bodyContent.trim() === '') {{
                bodyContent = '<p class="text-muted"><i>No content available</i></p>';
            }} else if (!bodyContent.includes('<')) {{
                bodyContent = '<pre style="white-space: pre-wrap; font-family: inherit; background: #2d3748; padding: 20px; border-radius: 8px;">' + 
                             escapeHtml(bodyContent) + '</pre>';
            }}

            const html = `
            <div class="card bg-dark">
                <div class="card-body">
                    <h4 class="email-subject">${{escapeHtml(email.subject)}}</h4>
                    
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-user me-2"></i>From:</strong> ${{escapeHtml(email.sender)}}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-calendar me-2"></i>Date:</strong> ${{escapeHtml(email.date)}}</p>
                        </div>
                    </div>

                    <div class="row mt-2">
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-tag me-2"></i>Priority:</strong> 
                            <span class="priority-badge priority-${{email.priority}}">${{email.priority}}</span></p>
                        </div>
                        <div class="col-md-6">
                            <p><strong><i class="fas fa-envelope me-2"></i>ID:</strong> 
                            <code>${{email.id}}</code></p>
                        </div>
                    </div>

                    <hr>

                    <div class="email-body-content mt-4">
                        <h5><i class="fas fa-align-left me-2"></i>Content:</h5>
                        ${{bodyContent}}
                    </div>

                    <div class="mt-4">
                        <a href="/email/${{email.id}}/summary" class="btn btn-info">
                            <i class="fas fa-robot me-2"></i>AI Analysis
                        </a>
                        <button class="btn btn-primary" onclick="replyToEmail('{email_id}')">
                            <i class="fas fa-reply me-2"></i>Reply
                        </button>
                        <button class="btn btn-outline-secondary" onclick="forwardEmail('{email_id}')">
                            <i class="fas fa-share me-2"></i>Forward
                        </button>
                        <button class="btn btn-outline-danger" onclick="deleteEmail('{email_id}')">
                            <i class="fas fa-trash me-2"></i>Delete
                        </button>
                    </div>
                </div>
            </div>
            `;
            
            emailContent.innerHTML = html;
        }}

        function replyToEmail(emailId) {{
            alert('Reply functionality would open here for email: ' + emailId);
        }}

        function forwardEmail(emailId) {{
            alert('Forward functionality would open here for email: ' + emailId);
        }}

        function deleteEmail(emailId) {{
            if (confirm('Are you sure you want to move this email to trash?')) {{
                alert('Delete functionality would execute here for email: ' + emailId);
            }}
        }}

        document.addEventListener('DOMContentLoaded', loadEmailContent);
    </script>
    '''
    return render_template_string(BASE_TEMPLATE, content=content)

@app.route('/api/emails', methods=['POST'])
def api_emails():
    """API endpoint to fetch emails"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        if credentials.expired:
            try:
                credentials.refresh(Request())
                tokens['token'] = credentials.token
            except Exception as refresh_error:
                logger.error(f"Token refresh failed: {str(refresh_error)}")
                return jsonify({'success': False, 'error': f'Token refresh failed: {str(refresh_error)}'})
        
        service = build('gmail', 'v1', credentials=credentials)
        
        yesterday = datetime.now() - timedelta(hours=24)
        query = f'after:{int(yesterday.timestamp())} in:inbox'
        
        result = service.users().messages().list(
            userId='me', 
            maxResults=20,
            q=query
        ).execute()
        
        messages = result.get('messages', [])
        emails = []
        
        priority_stats = {
            'work': 0,
            'medium': 0,
            'low': 0,
            'promotions': 0,
            'spam': 0,
            'total': len(messages)
        }
        
        for msg in messages[:15]:
            try:
                message = service.users().messages().get(
                    userId='me', 
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
                
                try:
                    from email.utils import parsedate_to_datetime
                    date_obj = parsedate_to_datetime(date)
                    simple_date = date_obj.strftime("%b %d, %I:%M %p")
                except:
                    simple_date = date[:16] if len(date) > 16 else date
                
                sender_name = sender.split('<')[0].strip().replace('"', '') if '<' in sender else sender
                
                priority = analyze_email_priority(subject, message.get('snippet', ''), sender_name)
                priority_stats[priority] += 1
                
                # Basic AI analysis for inbox view
                ai_labels = get_ai_labels(subject, message.get('snippet', ''), sender_name)
                
                emails.append({
                    'id': msg['id'],
                    'subject': subject,
                    'sender': sender_name,
                    'snippet': message.get('snippet', 'No preview available'),
                    'date': simple_date,
                    'priority': priority,
                    'ai_labels': ai_labels
                })
            except Exception as e:
                logger.warning(f"Error processing message {msg.get('id')}: {str(e)}")
                continue
        
        return jsonify({
            'success': True, 
            'emails': emails,
            'stats': priority_stats
        })
        
    except Exception as e:
        logger.error(f"API Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/email/<email_id>', methods=['POST'])
def api_get_email(email_id):
    """API endpoint to get a single email's full content"""
    try:
        data = request.json
        tokens = data.get('tokens')
        
        if not tokens:
            return jsonify({'success': False, 'error': 'No tokens provided'})
        
        credentials = Credentials(
            token=tokens['token'],
            refresh_token=tokens['refresh_token'],
            token_uri=tokens['token_uri'],
            client_id=tokens['client_id'],
            client_secret=tokens['client_secret'],
            scopes=tokens.get('scopes', SCOPES)
        )
        
        if credentials.expired:
            try:
                credentials.refresh(Request())
                tokens['token'] = credentials.token
            except Exception as refresh_error:
                return jsonify({'success': False, 'error': f'Token refresh failed: {str(refresh_error)}'})
        
        service = build('gmail', 'v1', credentials=credentials)
        
        message = service.users().messages().get(
            userId='me', 
            id=email_id,
            format='full'
        ).execute()
        
        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
        
        try:
            from email.utils import parsedate_to_datetime
            date_obj = parsedate_to_datetime(date)
            formatted_date = date_obj.strftime("%A, %B %d, %Y at %I:%M %p")
        except:
            formatted_date = date
        
        body = extract_email_body(message.get('payload', {}))
        
        sender_name = sender.split('<')[0].strip().replace('"', '') if '<' in sender else sender
        priority = analyze_email_priority(subject, body, sender_name)
        
        email_data = {
            'id': email_id,
            'subject': subject,
            'sender': sender_name,
            'date': formatted_date,
            'body': body,
            'priority': priority,
            'snippet': message.get('snippet', '')
        }
        
        return jsonify({
            'success': True, 
            'email': email_data
        })
        
    except Exception as e:
        logger.error(f"API Email Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# Vercel requires this
@app.route('/favicon.ico')
def favicon():
    return '', 404

# Vercel requires the app to be named 'app'
app = app

# For local development
if __name__ == '__main__':
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("Warning: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set. OAuth will not work.")
        logger.warning("Please set these environment variables to enable Gmail integration.")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Gmail AI Assistant on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)