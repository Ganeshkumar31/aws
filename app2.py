from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
import traceback

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///healthcare.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'noreply@healthcare.com')

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('healthcare.log')
    ]
)
logger = logging.getLogger(__name__)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'patient' or 'doctor'
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Patient-specific fields
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    blood_group = db.Column(db.String(10))
    address = db.Column(db.Text)
    
    # Doctor-specific fields
    specialization = db.Column(db.String(100))
    qualifications = db.Column(db.Text)
    experience = db.Column(db.Integer)
    availability = db.Column(db.Text)  # JSON string
    
    # Relationships
    doctor_appointments = db.relationship(
        'Appointment', 
        foreign_keys='Appointment.doctor_id', 
        backref='appointment_doctor', 
        lazy=True
    )
    patient_appointments = db.relationship(
        'Appointment', 
        foreign_keys='Appointment.patient_id', 
        backref='appointment_patient', 
        lazy=True
    )
    doctor_prescriptions = db.relationship(
        'Prescription', 
        foreign_keys='Prescription.doctor_id', 
        backref='prescribing_doctor', 
        lazy=True
    )

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.String(50), unique=True, nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    symptoms = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, confirmed, completed, cancelled
    diagnosis = db.Column(db.Text)
    treatment_plan = db.Column(db.Text)
    prescription = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to prescriptions
    prescriptions = db.relationship('Prescription', backref='appointment', lazy=True)

class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.String(50), unique=True, nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    medications = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def is_logged_in():
    return 'user_id' in session and 'role' in session

def send_email(to_email, subject, body, html_body=None):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject

        part1 = MIMEText(body, 'plain')
        msg.attach(part1)

        if html_body:
            part2 = MIMEText(html_body, 'html')
            msg.attach(part2)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        
        logger.info(f"Email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email').lower()
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            role = request.form.get('role')
            phone = request.form.get('phone')
            
            # Validate inputs
            if not all([name, email, password, confirm_password, role, phone]):
                flash('All fields are required', 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_template('register.html')
            
            if len(password) < 8:
                flash('Password must be at least 8 characters', 'danger')
                return render_template('register.html')
            
            # Check if user exists
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return render_template('register.html')
            
            # Create user based on role
            if role == 'patient':
                user = User(
                    email=email,
                    password=generate_password_hash(password),
                    name=name,
                    role=role,
                    phone=phone,
                    age=request.form.get('age'),
                    gender=request.form.get('gender'),
                    blood_group=request.form.get('blood_group'),
                    address=request.form.get('address')
                )
            elif role == 'doctor':
                user = User(
                    email=email,
                    password=generate_password_hash(password),
                    name=name,
                    role=role,
                    phone=phone,
                    specialization=request.form.get('specialization'),
                    qualifications=request.form.get('qualifications'),
                    experience=request.form.get('experience'),
                    availability='{}'  # Default empty JSON
                )
            else:
                flash('Invalid role selected', 'danger')
                return render_template('register.html')
            
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            send_email(
                email,
                'Welcome to Healthcare System',
                f"Hello {name}, your account was created successfully as a {role}.",
                f"""
                <html>
                    <body>
                        <h2>Welcome to Healthcare System, {name}!</h2>
                        <p>Your account has been successfully created as a {role}.</p>
                        <p>You can now login to your account and start using our services.</p>
                        <p>Thank you for joining us!</p>
                    </body>
                </html>
                """
            )
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not all([email, password, role]):
            flash('All fields are required', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email, role=role).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['role'] = user.role
            session['name'] = user.name
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid email, password, or role', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        flash('Please login to continue', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    role = session['role']
    
    if role == 'patient':
        appointments = Appointment.query.filter_by(patient_id=user_id).order_by(Appointment.date.desc()).all()
        doctors = User.query.filter_by(role='doctor').all()
        return render_template('patient_dashboard.html', appointments=appointments, doctors=doctors)
    elif role == 'doctor':
        appointments = Appointment.query.filter_by(doctor_id=user_id).order_by(Appointment.date.desc()).all()
        return render_template('doctor_dashboard.html', appointments=appointments)
    else:
        flash('Invalid user role', 'danger')
        return redirect(url_for('logout'))

# ... [rest of your route implementations remain the same] ...

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Internal Server Error: {error}")
    if app.debug:
        return f"<pre>{traceback.format_exc()}</pre>", 500
    return render_template("500.html"), 500

# Create database tables
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)