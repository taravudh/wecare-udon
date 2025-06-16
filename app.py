from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
import json
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import threading
from PIL import Image
import io
import base64
import csv
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wecare_incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Configure this
app.config['MAIL_PASSWORD'] = 'your-app-password'  # Configure this
app.config['MAIL_DEFAULT_SENDER'] = 'WeCare System <your-email@gmail.com>'

# Thailand timezone
THAILAND_TZ = pytz.timezone('Asia/Bangkok')

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)


# Database Models
class Department(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', backref='department', lazy=True)
    incidents = db.relationship('Incident', backref='department', lazy=True)


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='citizen')  # admin, governor, officer, citizen
    department_id = db.Column(db.String(36), db.ForeignKey('department.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    email_notifications = db.Column(db.Boolean, default=True)

    # Relationships
    assigned_incidents = db.relationship('Incident', foreign_keys='Incident.assigned_to', backref='assignee', lazy=True)
    created_assignments = db.relationship('Incident', foreign_keys='Incident.assigned_by', backref='assigner',
                                          lazy=True)
    incident_updates = db.relationship('IncidentUpdate', backref='user', lazy=True)
    assignments_made = db.relationship('IncidentAssignment', foreign_keys='IncidentAssignment.assigned_by',
                                       backref='assigner', lazy=True)
    assignments_received = db.relationship('IncidentAssignment', foreign_keys='IncidentAssignment.assigned_to',
                                           backref='assignee', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Incident(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default='general')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, in_progress, resolved, closed
    priority = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high, urgent
    reporter_name = db.Column(db.String(100), nullable=True)
    reporter_contact = db.Column(db.String(100), nullable=True)
    assigned_to = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    assigned_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    department_id = db.Column(db.String(36), db.ForeignKey('department.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assignments = db.relationship('IncidentAssignment', backref='incident', lazy=True, cascade='all, delete-orphan')
    updates = db.relationship('IncidentUpdate', backref='incident', lazy=True, cascade='all, delete-orphan')
    photos = db.relationship('IncidentPhoto', backref='incident', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'address': self.address,
            'status': self.status,
            'priority': self.priority,
            'reporter_name': self.reporter_name,
            'reporter_contact': self.reporter_contact,
            'assigned_to': self.assigned_to,
            'assigned_by': self.assigned_by,
            'department_id': self.department_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'photos': [photo.to_dict() for photo in self.photos]
        }


class IncidentPhoto(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'url': f'/static/uploads/{self.filename}',
            'uploaded_at': self.uploaded_at.isoformat()
        }


class IncidentAssignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=False)
    assigned_to = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    assigned_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)


class IncidentUpdate(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status_from = db.Column(db.String(20), nullable=True)
    status_to = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False, default='info')  # info, success, warning, error
    is_read = db.Column(db.Boolean, default=False)
    incident_id = db.Column(db.String(36), db.ForeignKey('incident.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'is_read': self.is_read,
            'incident_id': self.incident_id,
            'created_at': self.created_at.isoformat()
        }


# Utility Functions
def convert_to_thailand_time(utc_datetime):
    """Convert UTC datetime to Thailand timezone (GMT+7)"""
    if utc_datetime is None:
        return None

    # Make sure the datetime is timezone-aware (UTC)
    if utc_datetime.tzinfo is None:
        utc_datetime = pytz.utc.localize(utc_datetime)

    # Convert to Thailand timezone
    thailand_time = utc_datetime.astimezone(THAILAND_TZ)
    return thailand_time


def format_thailand_datetime(utc_datetime, format_str='%Y-%m-%d %H:%M:%S'):
    """Format datetime in Thailand timezone"""
    thailand_time = convert_to_thailand_time(utc_datetime)
    if thailand_time is None:
        return ''
    return thailand_time.strftime(format_str)


# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))

            user = User.query.get(session['user_id'])
            if not user or user.role not in roles:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Notification System
def create_notification(user_id, title, message, notification_type='info', incident_id=None):
    """Create a new notification for a user"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=notification_type,
        incident_id=incident_id
    )
    db.session.add(notification)
    db.session.commit()
    return notification


def send_email_notification(user_email, subject, body, incident_id=None):
    """Send email notification in background thread"""

    def send_async_email():
        try:
            msg = MIMEMultipart()
            msg['From'] = app.config['MAIL_DEFAULT_SENDER']
            msg['To'] = user_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'html'))

            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            text = msg.as_string()
            server.sendmail(app.config['MAIL_USERNAME'], user_email, text)
            server.quit()
        except Exception as e:
            print(f"Failed to send email: {str(e)}")

    # Send email in background thread
    thread = threading.Thread(target=send_async_email)
    thread.daemon = True
    thread.start()


def notify_incident_assignment(incident, assigned_user, assigner_user):
    """Notify user about incident assignment"""
    title = f"New Incident Assigned: {incident.title}"
    message = f"You have been assigned a new incident by {assigner_user.full_name}. Priority: {incident.priority.title()}"

    # Create in-app notification
    create_notification(assigned_user.id, title, message, 'info', incident.id)

    # Send email notification if enabled
    if assigned_user.email_notifications:
        email_body = f"""
        <html>
        <body>
            <h2>New Incident Assignment</h2>
            <p>Hello {assigned_user.full_name},</p>
            <p>You have been assigned a new incident:</p>
            <ul>
                <li><strong>Title:</strong> {incident.title}</li>
                <li><strong>Priority:</strong> {incident.priority.title()}</li>
                <li><strong>Category:</strong> {incident.category.title()}</li>
                <li><strong>Assigned by:</strong> {assigner_user.full_name}</li>
            </ul>
            <p>Please log in to the WeCare system to view details and update the status.</p>
            <p>Best regards,<br>WeCare System</p>
        </body>
        </html>
        """
        send_email_notification(assigned_user.email, title, email_body, incident.id)


def notify_status_update(incident, updated_by_user):
    """Notify relevant users about status updates"""
    title = f"Incident Status Updated: {incident.title}"
    message = f"Incident status changed to {incident.status.replace('_', ' ').title()} by {updated_by_user.full_name}"

    # Notify assigner if different from updater
    if incident.assigned_by and incident.assigned_by != updated_by_user.id:
        assigner = User.query.get(incident.assigned_by)
        if assigner:
            create_notification(assigner.id, title, message, 'success', incident.id)
            if assigner.email_notifications:
                email_body = f"""
                <html>
                <body>
                    <h2>Incident Status Update</h2>
                    <p>Hello {assigner.full_name},</p>
                    <p>An incident you assigned has been updated:</p>
                    <ul>
                        <li><strong>Title:</strong> {incident.title}</li>
                        <li><strong>New Status:</strong> {incident.status.replace('_', ' ').title()}</li>
                        <li><strong>Updated by:</strong> {updated_by_user.full_name}</li>
                    </ul>
                    <p>Best regards,<br>WeCare System</p>
                </body>
                </html>
                """
                send_email_notification(assigner.email, title, email_body, incident.id)


def get_user_incidents(user):
    """Get incidents based on user role and department"""
    if user.role == 'admin':
        return Incident.query.order_by(Incident.created_at.desc()).all()
    elif user.role == 'governor':
        return Incident.query.order_by(Incident.created_at.desc()).all()
    elif user.role == 'officer':
        if user.department_id:
            return Incident.query.filter(
                (Incident.department_id == user.department_id) |
                (Incident.assigned_to == user.id)
            ).order_by(Incident.created_at.desc()).all()
        else:
            return Incident.query.filter_by(assigned_to=user.id).order_by(Incident.created_at.desc()).all()
    else:
        return Incident.query.order_by(Incident.created_at.desc()).all()


def get_department_officers(department_id):
    """Get officers from a specific department"""
    return User.query.filter_by(role='officer', department_id=department_id, is_active=True).all()


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'heic', 'heif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def process_image(file_data, max_size=(1200, 1200), quality=85):
    """Process and optimize uploaded image"""
    try:
        image = Image.open(io.BytesIO(file_data))

        # Convert to RGB if necessary
        if image.mode in ('RGBA', 'P'):
            image = image.convert('RGB')

        # Resize if too large
        image.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Save optimized image
        output = io.BytesIO()
        image.save(output, format='JPEG', quality=quality, optimize=True)
        output.seek(0)

        return output.getvalue()
    except Exception as e:
        print(f"Error processing image: {str(e)}")
        return file_data


def generate_csv_response(incidents, filename="incidents_export.csv"):
    """Generate CSV response for incidents with Thailand timezone"""
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'ID', 'Title', 'Description', 'Category', 'Priority', 'Status',
        'Reporter Name', 'Reporter Contact', 'Latitude', 'Longitude', 'Address',
        'Assigned To', 'Department', 'Created At (GMT+7)', 'Updated At (GMT+7)', 'Photos Count'
    ])

    # Write data
    for incident in incidents:
        writer.writerow([
            incident.id,
            incident.title,
            incident.description or '',
            incident.category,
            incident.priority,
            incident.status,
            incident.reporter_name or '',
            incident.reporter_contact or '',
            incident.latitude,
            incident.longitude,
            incident.address or '',
            incident.assignee.full_name if incident.assignee else '',
            incident.department.name if incident.department else '',
            format_thailand_datetime(incident.created_at),
            format_thailand_datetime(incident.updated_at),
            len(incident.photos)
        ])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


# Template context processor
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}


@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return {'current_user': user}


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email, is_active=True).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash(f'Welcome back, {user.full_name}!', 'success')

            # Create login notification
            create_notification(user.id, 'Welcome Back!',
                                f'You logged in at {format_thailand_datetime(datetime.utcnow(), "%Y-%m-%d %H:%M")}',
                                'info')

            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'governor':
                return redirect(url_for('governor_dashboard'))
            elif user.role == 'officer':
                return redirect(url_for('officer_dashboard'))
            else:
                return redirect(url_for('citizen_dashboard'))
        else:
            flash('Invalid email or password, or account is disabled.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/citizen')
def citizen_dashboard():
    # Check if this is a CSV export request
    if request.args.get('export') == 'csv':
        # Get search and filter parameters
        search = request.args.get('search', '')
        status_filter = request.args.get('status', 'all')
        category_filter = request.args.get('category', 'all')
        priority_filter = request.args.get('priority', 'all')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')

        # Build query with same filters as the dashboard
        query = Incident.query

        # Apply filters
        if search:
            query = query.filter(
                (Incident.title.contains(search)) |
                (Incident.description.contains(search)) |
                (Incident.reporter_name.contains(search))
            )

        if status_filter != 'all':
            query = query.filter(Incident.status == status_filter)

        if category_filter != 'all':
            query = query.filter(Incident.category == category_filter)

        if priority_filter != 'all':
            query = query.filter(Incident.priority == priority_filter)

        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(Incident.created_at >= date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(Incident.created_at < date_to_obj)
            except ValueError:
                pass

        incidents = query.order_by(Incident.created_at.desc()).all()

        # Generate filename with current date and filters (in Thailand time)
        thailand_now = convert_to_thailand_time(datetime.utcnow())
        filename_parts = ['wecare_incidents']
        if status_filter != 'all':
            filename_parts.append(f'status_{status_filter}')
        if category_filter != 'all':
            filename_parts.append(f'category_{category_filter}')
        if priority_filter != 'all':
            filename_parts.append(f'priority_{priority_filter}')
        filename_parts.append(thailand_now.strftime('%Y%m%d_%H%M%S'))
        filename = '_'.join(filename_parts) + '.csv'

        return generate_csv_response(incidents, filename)

    # Regular dashboard view
    # Get search and filter parameters
    search = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    category_filter = request.args.get('category', 'all')
    priority_filter = request.args.get('priority', 'all')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    # Build query
    query = Incident.query

    # Apply filters
    if search:
        query = query.filter(
            (Incident.title.contains(search)) |
            (Incident.description.contains(search)) |
            (Incident.reporter_name.contains(search))
        )

    if status_filter != 'all':
        query = query.filter(Incident.status == status_filter)

    if category_filter != 'all':
        query = query.filter(Incident.category == category_filter)

    if priority_filter != 'all':
        query = query.filter(Incident.priority == priority_filter)

    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Incident.created_at >= date_from_obj)
        except ValueError:
            pass

    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Incident.created_at < date_to_obj)
        except ValueError:
            pass

    incidents = query.order_by(Incident.created_at.desc()).all()

    # Get filter options
    categories = db.session.query(Incident.category.distinct()).all()
    categories = [cat[0] for cat in categories]

    return render_template('citizen_dashboard.html',
                           incidents=incidents,
                           categories=categories,
                           current_filters={
                               'search': search,
                               'status': status_filter,
                               'category': category_filter,
                               'priority': priority_filter,
                               'date_from': date_from,
                               'date_to': date_to
                           })


@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    user = User.query.get(session['user_id'])
    incidents = get_user_incidents(user)
    users = User.query.filter_by(is_active=True).all()
    departments = Department.query.all()
    assignments = IncidentAssignment.query.all()

    stats = {
        'total_incidents': len(incidents),
        'pending_incidents': len([i for i in incidents if i.status == 'pending']),
        'in_progress_incidents': len([i for i in incidents if i.status == 'in_progress']),
        'resolved_incidents': len([i for i in incidents if i.status == 'resolved']),
        'total_users': len(users),
        'officers': len([u for u in users if u.role == 'officer']),
        'governors': len([u for u in users if u.role == 'governor']),
        'total_departments': len(departments)
    }

    return render_template('admin_dashboard.html',
                           current_user=user,
                           incidents=incidents,
                           users=users,
                           departments=departments,
                           assignments=assignments,
                           stats=stats)


@app.route('/reports')
@role_required('admin', 'governor')
def reports_dashboard():
    user = User.query.get(session['user_id'])

    # Get date range from query params
    date_from = request.args.get('date_from', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    date_to = request.args.get('date_to', datetime.now().strftime('%Y-%m-%d'))

    try:
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        date_from_obj = datetime.now() - timedelta(days=30)
        date_to_obj = datetime.now()

    # Get incidents in date range
    incidents = Incident.query.filter(
        Incident.created_at >= date_from_obj,
        Incident.created_at < date_to_obj
    ).all()

    # Calculate statistics
    stats = {
        'total_incidents': len(incidents),
        'by_status': {},
        'by_category': {},
        'by_priority': {},
        'by_department': {},
        'resolution_times': [],
        'daily_counts': {}
    }

    # Status breakdown
    for status in ['pending', 'in_progress', 'resolved', 'closed']:
        stats['by_status'][status] = len([i for i in incidents if i.status == status])

    # Category breakdown
    categories = db.session.query(Incident.category.distinct()).all()
    for cat in categories:
        category = cat[0]
        stats['by_category'][category] = len([i for i in incidents if i.category == category])

    # Priority breakdown
    for priority in ['low', 'medium', 'high', 'urgent']:
        stats['by_priority'][priority] = len([i for i in incidents if i.priority == priority])

    # Department breakdown
    departments = Department.query.all()
    for dept in departments:
        dept_incidents = [i for i in incidents if i.department_id == dept.id]
        stats['by_department'][dept.name] = len(dept_incidents)

    # Daily incident counts
    current_date = date_from_obj
    while current_date < date_to_obj:
        day_str = current_date.strftime('%Y-%m-%d')
        day_incidents = [i for i in incidents if i.created_at.date() == current_date.date()]
        stats['daily_counts'][day_str] = len(day_incidents)
        current_date += timedelta(days=1)

    # Resolution times (for resolved incidents)
    resolved_incidents = [i for i in incidents if i.status in ['resolved', 'closed']]
    for incident in resolved_incidents:
        resolution_time = (incident.updated_at - incident.created_at).total_seconds() / 3600  # hours
        stats['resolution_times'].append(resolution_time)

    # Average resolution time
    if stats['resolution_times']:
        stats['avg_resolution_time'] = sum(stats['resolution_times']) / len(stats['resolution_times'])
    else:
        stats['avg_resolution_time'] = 0

    return render_template('reports_dashboard.html',
                           stats=stats,
                           incidents=incidents,
                           date_from=date_from,
                           date_to=date_to,
                           departments=departments)


@app.route('/governor')
@role_required('governor')
def governor_dashboard():
    user = User.query.get(session['user_id'])
    incidents = get_user_incidents(user)
    officers = User.query.filter_by(role='officer', is_active=True).all()
    departments = Department.query.all()
    assignments = IncidentAssignment.query.all()

    stats = {
        'total_incidents': len(incidents),
        'pending_incidents': len([i for i in incidents if i.status == 'pending']),
        'in_progress_incidents': len([i for i in incidents if i.status == 'in_progress']),
        'resolved_incidents': len([i for i in incidents if i.status == 'resolved']),
        'total_officers': len(officers),
        'active_assignments': len(assignments),
        'department_count': len(departments)
    }

    return render_template('governor_dashboard.html',
                           current_user=user,
                           incidents=incidents,
                           officers=officers,
                           departments=departments,
                           stats=stats)


@app.route('/officer')
@role_required('officer')
def officer_dashboard():
    user = User.query.get(session['user_id'])
    assigned_incidents = get_user_incidents(user)

    return render_template('officer_dashboard.html',
                           current_user=user,
                           assigned_incidents=assigned_incidents)


# API Routes
@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        incidents = get_user_incidents(user)
    else:
        incidents = Incident.query.order_by(Incident.created_at.desc()).all()

    return jsonify([incident.to_dict() for incident in incidents])


@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get a specific incident with its photos"""
    try:
        incident = Incident.query.get_or_404(incident_id)
        incident_data = incident.to_dict()

        # Debug logging
        print(f"Incident {incident_id} has {len(incident.photos)} photos")
        for photo in incident.photos:
            print(f"Photo: {photo.filename}, URL: {photo.to_dict()['url']}")

        return jsonify(incident_data)
    except Exception as e:
        print(f"Error getting incident {incident_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/incidents', methods=['POST'])
def create_incident():
    try:
        data = request.get_json()

        # Validate required fields
        if not all(key in data for key in ['title', 'description', 'latitude', 'longitude']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Create new incident
        incident = Incident(
            title=data['title'],
            description=data['description'],
            category=data.get('category', 'general'),
            latitude=float(data['latitude']),
            longitude=float(data['longitude']),
            address=data.get('address'),
            reporter_name=data.get('reporter_name'),
            reporter_contact=data.get('reporter_contact')
        )

        db.session.add(incident)
        db.session.commit()

        print(f"Created incident {incident.id}")

        # Notify administrators about new incident
        admins = User.query.filter_by(role='admin', is_active=True).all()
        for admin in admins:
            create_notification(
                admin.id,
                'New Incident Reported',
                f'A new incident "{incident.title}" has been reported in {incident.category} category.',
                'info',
                incident.id
            )

        return jsonify(incident.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error creating incident: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/incidents/<incident_id>', methods=['PUT'])
def update_incident(incident_id):
    try:
        incident = Incident.query.get_or_404(incident_id)
        data = request.get_json()

        # Check permissions
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user.role == 'officer' and user.department_id != incident.department_id and incident.assigned_to != user.id:
                return jsonify({'error': 'Access denied'}), 403

        # Store old status for update tracking
        old_status = incident.status

        # Update allowed fields
        if 'status' in data:
            incident.status = data['status']
        if 'priority' in data:
            incident.priority = data['priority']
        if 'category' in data:
            incident.category = data['category']
        if 'assigned_to' in data:
            incident.assigned_to = data['assigned_to']
        if 'assigned_by' in data:
            incident.assigned_by = data['assigned_by']
        if 'department_id' in data:
            incident.department_id = data['department_id']

        incident.updated_at = datetime.utcnow()

        # Create update record if status changed
        if 'status' in data and old_status != data['status']:
            update = IncidentUpdate(
                incident_id=incident.id,
                user_id=session.get('user_id'),
                status_from=old_status,
                status_to=data['status'],
                notes=data.get('notes', '')
            )
            db.session.add(update)

            # Send notifications about status update
            if session.get('user_id'):
                updated_by = User.query.get(session['user_id'])
                notify_status_update(incident, updated_by)

        db.session.commit()

        return jsonify(incident.to_dict())

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        incident_id = request.form.get('incident_id')

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not incident_id:
            return jsonify({'error': 'Incident ID required'}), 400

        # Verify incident exists
        incident = Incident.query.get(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404

        print(
            f"Uploading file for incident {incident_id}: {file.filename}, type: {file.content_type}, size: {file.content_length}")

        if file and allowed_file(file.filename):
            # Read file data
            file_data = file.read()

            # Process and optimize image
            processed_data = process_image(file_data)

            # Generate unique filename
            file_extension = 'jpg'  # Always save as JPG after processing
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}.{file_extension}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save processed file
            with open(filepath, 'wb') as f:
                f.write(processed_data)

            # Create database record
            photo = IncidentPhoto(
                incident_id=incident_id,
                filename=filename,
                original_filename=file.filename,
                file_size=len(processed_data)
            )
            db.session.add(photo)
            db.session.commit()

            print(f"Successfully saved photo: {filename} for incident {incident_id}")

            return jsonify(photo.to_dict())

        return jsonify({'error': 'Invalid file type. Supported: JPG, PNG, WebP, HEIC'}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/assign_incident', methods=['POST'])
@role_required('admin', 'governor')
def assign_incident():
    try:
        data = request.get_json()
        incident_id = data['incident_id']
        assigned_to = data['assigned_to']
        notes = data.get('notes', '')
        department_id = data.get('department_id')

        # Update incident
        incident = Incident.query.get_or_404(incident_id)
        incident.assigned_to = assigned_to
        incident.assigned_by = session['user_id']
        incident.status = 'in_progress'
        incident.updated_at = datetime.utcnow()

        # Set department if provided
        if department_id:
            incident.department_id = department_id

        # Create assignment record
        assignment = IncidentAssignment(
            incident_id=incident_id,
            assigned_to=assigned_to,
            assigned_by=session['user_id'],
            notes=notes
        )

        # Create update record
        update = IncidentUpdate(
            incident_id=incident_id,
            user_id=session['user_id'],
            status_from='pending',
            status_to='in_progress',
            notes=f'Assigned to officer. {notes}' if notes else 'Assigned to officer.'
        )

        db.session.add(assignment)
        db.session.add(update)
        db.session.commit()

        # Send notifications
        assigned_user = User.query.get(assigned_to)
        assigner_user = User.query.get(session['user_id'])
        notify_incident_assignment(incident, assigned_user, assigner_user)

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Notification API Routes
@app.route('/api/notifications')
@login_required
def get_notifications():
    user_id = session['user_id']
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(
        50).all()
    return jsonify([notification.to_dict() for notification in notifications])


@app.route('/api/notifications/unread_count')
@login_required
def get_unread_count():
    user_id = session['user_id']
    count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    return jsonify({'count': count})


@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = Notification.query.filter_by(id=notification_id, user_id=session['user_id']).first_or_404()
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        Notification.query.filter_by(user_id=session['user_id'], is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Other existing API routes...
@app.route('/api/users', methods=['POST'])
@role_required('admin')
def create_user():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['email', 'full_name', 'role', 'password']
        if not all(key in data for key in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400

        # Create new user
        user = User(
            email=data['email'],
            full_name=data['full_name'],
            role=data['role'],
            department_id=data.get('department_id')
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'department_id': user.department_id
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<user_id>', methods=['PUT'])
@role_required('admin')
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()

        # Update allowed fields
        if 'full_name' in data:
            user.full_name = data['full_name']
        if 'email' in data:
            # Check if email already exists for another user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = data['email']
        if 'role' in data:
            user.role = data['role']
        if 'department_id' in data:
            user.department_id = data['department_id']
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        if 'is_active' in data:
            user.is_active = data['is_active']
        if 'email_notifications' in data:
            user.email_notifications = data['email_notifications']

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<user_id>', methods=['DELETE'])
@role_required('admin')
def deactivate_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = False
        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/departments', methods=['POST'])
@role_required('admin')
def create_department():
    try:
        data = request.get_json()

        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Department name is required'}), 400

        # Check if department already exists
        if Department.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Department already exists'}), 400

        # Create new department
        department = Department(
            name=data['name'],
            description=data.get('description', '')
        )

        db.session.add(department)
        db.session.commit()

        return jsonify({
            'success': True,
            'department': {
                'id': department.id,
                'name': department.name,
                'description': department.description
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/departments/<department_id>/officers')
def get_department_officers_api(department_id):
    officers = get_department_officers(department_id)
    return jsonify([{
        'id': officer.id,
        'full_name': officer.full_name,
        'email': officer.email
    } for officer in officers])


@app.route('/api/incident_updates/<incident_id>')
def get_incident_updates(incident_id):
    # Check permissions
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        incident = Incident.query.get_or_404(incident_id)

        if user.role == 'officer' and user.department_id != incident.department_id and incident.assigned_to != user.id:
            return jsonify({'error': 'Access denied'}), 403

    updates = IncidentUpdate.query.filter_by(incident_id=incident_id).order_by(IncidentUpdate.created_at.desc()).all()

    updates_data = []
    for update in updates:
        updates_data.append({
            'id': update.id,
            'user_name': update.user.full_name if update.user else 'System',
            'status_from': update.status_from,
            'status_to': update.status_to,
            'notes': update.notes,
            'created_at': update.created_at.isoformat()
        })

    return jsonify(updates_data)


def create_tables():
    """Create database tables and insert default data"""
    with app.app_context():
        db.create_all()

        # Create default departments
        departments_data = [
            ('Public Works', 'Road maintenance, utilities, infrastructure'),
            ('Public Safety', 'Police, fire, emergency services'),
            ('Environmental Services', 'Waste management, environmental issues'),
            ('Parks & Recreation', 'Parks, recreational facilities, green spaces'),
            ('Transportation', 'Traffic, public transport, road safety'),
            ('Health Services', 'Public health, sanitation, health emergencies')
        ]

        for name, description in departments_data:
            if not Department.query.filter_by(name=name).first():
                dept = Department(name=name, description=description)
                db.session.add(dept)

        # Create default admin user
        if not User.query.filter_by(email='admin@city.gov').first():
            admin = User(
                email='admin@city.gov',
                full_name='System Administrator',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)

        # Create default governor user
        if not User.query.filter_by(email='governor@city.gov').first():
            governor = User(
                email='governor@city.gov',
                full_name='City Governor',
                role='governor'
            )
            governor.set_password('governor123')
            db.session.add(governor)

        # Create sample officer
        public_works_dept = Department.query.filter_by(name='Public Works').first()
        if public_works_dept and not User.query.filter_by(email='officer.publicworks@city.gov').first():
            officer = User(
                email='officer.publicworks@city.gov',
                full_name='John Smith',
                role='officer',
                department_id=public_works_dept.id
            )
            officer.set_password('officer123')
            db.session.add(officer)

        db.session.commit()
        print("Database tables created and default data inserted successfully!")


if __name__ == '__main__':
    # Create tables before running the app
    create_tables()
    print("Starting WeCare Municipal Incident Management System...")
    print("Developed by The Mapper Co.,Ltd.")
    print("Visit: http://localhost:5000")
    print("\nDefault Login Credentials:")
    print("Administrator: admin@city.gov / admin123")
    print("Governor: governor@city.gov / governor123")
    print("Officer: officer.publicworks@city.gov / officer123")
    app.run(debug=True, host='0.0.0.0', port=5000)