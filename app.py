from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import boto3
import uuid
import os
from dotenv import load_dotenv
import logging
from botocore.exceptions import ClientError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns = boto3.client('sns', region_name=AWS_REGION)

# Table Names
USERS_TABLE = os.environ.get('USERS_TABLE', 'HealthcareUsers')
APPOINTMENTS_TABLE = os.environ.get('APPOINTMENTS_TABLE', 'HealthcareAppointments')
PRESCRIPTIONS_TABLE = os.environ.get('PRESCRIPTIONS_TABLE', 'HealthcarePrescriptions')

# Initialize tables
users_table = dynamodb.Table(USERS_TABLE)
appointments_table = dynamodb.Table(APPOINTMENTS_TABLE)
prescriptions_table = dynamodb.Table(PRESCRIPTIONS_TABLE)

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

# Helper Functions
def is_logged_in():
    return 'email' in session and 'role' in session

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

def publish_notification(subject, message):
    try:
        response = sns.publish(
            TopicArn=os.environ.get('SNS_TOPIC_ARN'),
            Message=message,
            Subject=subject
        )
        logger.info(f"Notification published: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"Failed to publish notification: {e}")
        return False

# Routes
@app.route('/')
def home():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').lower().strip()
        
        if not email or not password or not role:
            flash('All fields are required', 'danger')
            return render_template('login.html')
        
        try:
            response = users_table.get_item(Key={'email': email})
            user = response.get('Item')
            
            if not user or user['role'] != role or not check_password_hash(user['password'], password):
                flash('Invalid credentials or role', 'danger')
                return render_template('login.html')
            
            session['email'] = email
            session['role'] = role
            session['name'] = user.get('name', 'User')
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        except ClientError as e:
            logger.error(f"DynamoDB error: {e}")
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        role = request.form.get('role', '').lower().strip()
        phone = request.form.get('phone', '').strip()
        
        # Additional fields based on role
        specialization = request.form.get('specialization', '').strip() if role == 'doctor' else ''
        age = request.form.get('age', '').strip() if role == 'patient' else ''
        gender = request.form.get('gender', '').strip() if role == 'patient' else ''
        
        # Validation
        errors = []
        if not all([name, email, password, confirm_password, role, phone]):
            errors.append('All fields are required')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters')
        if role == 'doctor' and not specialization:
            errors.append('Specialization is required for doctors')
        if role == 'patient' and not all([age, gender]):
            errors.append('Age and gender are required for patients')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        try:
            # Check if user exists
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('Email already registered', 'danger')
                return render_template('register.html')
            
            # Create user
            user_data = {
                'email': email,
                'name': name,
                'password': generate_password_hash(password),
                'role': role,
                'phone': phone,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            if role == 'doctor':
                user_data.update({
                    'specialization': specialization,
                    'qualifications': request.form.get('qualifications', '').strip(),
                    'experience': request.form.get('experience', '').strip(),
                    'availability': json.loads(request.form.get('availability', '{}'))
                })
            elif role == 'patient':
                user_data.update({
                    'age': age,
                    'gender': gender,
                    'blood_group': request.form.get('blood_group', '').strip(),
                    'address': request.form.get('address', '').strip()
                })
            
            users_table.put_item(Item=user_data)
            
            # Send welcome email
            email_body = f"""
            <html>
                <body>
                    <h2>Welcome to Healthcare System, {name}!</h2>
                    <p>Your account has been successfully created as a {role}.</p>
                    <p>You can now login to your account and start using our services.</p>
                    <p>Thank you for joining us!</p>
                </body>
            </html>
            """
            send_email(
                email,
                'Welcome to Healthcare System',
                f"Welcome {name}, your account has been created successfully as a {role}.",
                email_body
            )
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        except ClientError as e:
            logger.error(f"DynamoDB error: {e}")
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        flash('Please login to access the dashboard', 'danger')
        return redirect(url_for('login'))
    
    try:
        email = session['email']
        role = session['role']
        name = session['name']
        
        if role == 'patient':
            # Get patient appointments
            response = appointments_table.query(
                IndexName='PatientEmailIndex',
                KeyConditionExpression='patient_email = :email',
                ExpressionAttributeValues={':email': email}
            )
            appointments = response.get('Items', [])
            
            # Get available doctors
            doctors_response = users_table.scan(
                FilterExpression='#role = :role',
                ExpressionAttributeNames={'#role': 'role'},
                ExpressionAttributeValues={':role': 'doctor'}
            )
            doctors = doctors_response.get('Items', [])
            
            return render_template('patient_dashboard.html', 
                                appointments=appointments, 
                                doctors=doctors,
                                name=name)
        
        elif role == 'doctor':
            # Get doctor appointments
            response = appointments_table.query(
                IndexName='DoctorEmailIndex',
                KeyConditionExpression='doctor_email = :email',
                ExpressionAttributeValues={':email': email}
            )
            appointments = response.get('Items', [])
            
            # Get doctor profile
            doctor_response = users_table.get_item(Key={'email': email})
            doctor = doctor_response.get('Item', {})
            
            return render_template('doctor_dashboard.html', 
                                appointments=appointments,
                                doctor=doctor,
                                name=name)
        
        else:
            flash('Invalid user role', 'danger')
            return redirect(url_for('logout'))
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        flash('Failed to load dashboard. Please try again.', 'danger')
        return redirect(url_for('logout'))

@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if not is_logged_in() or session['role'] != 'patient':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        doctor_email = data.get('doctor_email')
        date = data.get('date')
        time = data.get('time')
        symptoms = data.get('symptoms')
        patient_email = session['email']
        
        if not all([doctor_email, date, time, symptoms]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Check if doctor exists
        doctor_response = users_table.get_item(Key={'email': doctor_email})
        if 'Item' not in doctor_response:
            return jsonify({'success': False, 'message': 'Doctor not found'}), 404
        
        doctor = doctor_response['Item']
        if doctor['role'] != 'doctor':
            return jsonify({'success': False, 'message': 'Invalid doctor'}), 400
        
        # Check doctor availability
        if not is_doctor_available(doctor_email, date, time):
            return jsonify({'success': False, 'message': 'Doctor not available at this time'}), 400
        
        # Create appointment
        appointment_id = str(uuid.uuid4())
        appointment_data = {
            'appointment_id': appointment_id,
            'doctor_email': doctor_email,
            'doctor_name': doctor['name'],
            'patient_email': patient_email,
            'patient_name': session['name'],
            'date': date,
            'time': time,
            'symptoms': symptoms,
            'status': 'scheduled',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        appointments_table.put_item(Item=appointment_data)
        
        # Send notifications
        send_appointment_notifications(appointment_data)
        
        return jsonify({
            'success': True,
            'message': 'Appointment booked successfully',
            'appointment_id': appointment_id
        }), 201
    
    except Exception as e:
        logger.error(f"Error booking appointment: {e}")
        return jsonify({'success': False, 'message': 'Failed to book appointment'}), 500

def is_doctor_available(doctor_email, date, time):
    # Check if doctor has any appointment at the same date and time
    try:
        response = appointments_table.scan(
            FilterExpression='doctor_email = :email AND #date = :date AND #time = :time',
            ExpressionAttributeNames={'#date': 'date', '#time': 'time'},
            ExpressionAttributeValues={
                ':email': doctor_email,
                ':date': date,
                ':time': time
            }
        )
        return len(response.get('Items', [])) == 0
    except Exception as e:
        logger.error(f"Error checking doctor availability: {e}")
        return False

def send_appointment_notifications(appointment):
    # Email to patient
    patient_email = appointment['patient_email']
    patient_subject = f"Appointment Confirmation - {appointment['date']} at {appointment['time']}"
    patient_body = f"""
    <html>
        <body>
            <h2>Your Appointment is Confirmed</h2>
            <p>Dear {appointment['patient_name']},</p>
            <p>Your appointment with Dr. {appointment['doctor_name']} has been successfully scheduled.</p>
            <p><strong>Details:</strong></p>
            <ul>
                <li>Date: {appointment['date']}</li>
                <li>Time: {appointment['time']}</li>
                <li>Symptoms: {appointment['symptoms']}</li>
            </ul>
            <p>Thank you for using our healthcare services.</p>
        </body>
    </html>
    """
    send_email(patient_email, patient_subject, patient_body, patient_body)
    
    # Email to doctor
    doctor_email = appointment['doctor_email']
    doctor_subject = f"New Appointment - {appointment['date']} at {appointment['time']}"
    doctor_body = f"""
    <html>
        <body>
            <h2>New Appointment Scheduled</h2>
            <p>Dear Dr. {appointment['doctor_name']},</p>
            <p>You have a new appointment with {appointment['patient_name']}.</p>
            <p><strong>Details:</strong></p>
            <ul>
                <li>Date: {appointment['date']}</li>
                <li>Time: {appointment['time']}</li>
                <li>Symptoms: {appointment['symptoms']}</li>
            </ul>
        </body>
    </html>
    """
    send_email(doctor_email, doctor_subject, doctor_body, doctor_body)
    
    # SNS notification
    notification_message = f"New appointment: {appointment['patient_name']} with Dr. {appointment['doctor_name']} on {appointment['date']} at {appointment['time']}"
    publish_notification("New Appointment", notification_message)

@app.route('/appointments/<appointment_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_appointment(appointment_id):
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        # Get appointment
        response = appointments_table.get_item(Key={'appointment_id': appointment_id})
        if 'Item' not in response:
            return jsonify({'success': False, 'message': 'Appointment not found'}), 404
        
        appointment = response['Item']
        user_email = session['email']
        role = session['role']
        
        # Authorization check
        if role == 'patient' and appointment['patient_email'] != user_email:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        if role == 'doctor' and appointment['doctor_email'] != user_email:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        if request.method == 'GET':
            return jsonify({'success': True, 'appointment': appointment}), 200
        
        elif request.method == 'PUT':
            data = request.get_json()
            
            # Patients can only cancel appointments
            if role == 'patient':
                if 'status' in data and data['status'] == 'cancelled':
                    appointments_table.update_item(
                        Key={'appointment_id': appointment_id},
                        UpdateExpression='SET #status = :status, updated_at = :now',
                        ExpressionAttributeNames={'#status': 'status'},
                        ExpressionAttributeValues={
                            ':status': 'cancelled',
                            ':now': datetime.utcnow().isoformat()
                        }
                    )
                    return jsonify({'success': True, 'message': 'Appointment cancelled'}), 200
                else:
                    return jsonify({'success': False, 'message': 'Patients can only cancel appointments'}), 400
            
            # Doctors can update status and add diagnosis
            elif role == 'doctor':
                update_expressions = []
                expression_values = {}
                expression_names = {}
                
                if 'status' in data:
                    update_expressions.append('#status = :status')
                    expression_names['#status'] = 'status'
                    expression_values[':status'] = data['status']
                
                if 'diagnosis' in data:
                    update_expressions.append('diagnosis = :diagnosis')
                    expression_values[':diagnosis'] = data['diagnosis']
                
                if 'prescription' in data:
                    update_expressions.append('prescription = :prescription')
                    expression_values[':prescription'] = data['prescription']
                
                if 'treatment_plan' in data:
                    update_expressions.append('treatment_plan = :treatment_plan')
                    expression_values[':treatment_plan'] = data['treatment_plan']
                
                if not update_expressions:
                    return jsonify({'success': False, 'message': 'No valid fields to update'}), 400
                
                update_expressions.append('updated_at = :now')
                expression_values[':now'] = datetime.utcnow().isoformat()
                
                update_expression = 'SET ' + ', '.join(update_expressions)
                
                appointments_table.update_item(
                    Key={'appointment_id': appointment_id},
                    UpdateExpression=update_expression,
                    ExpressionAttributeNames=expression_names,
                    ExpressionAttributeValues=expression_values
                )
                
                # Create prescription if provided
                if 'prescription' in data:
                    prescription_id = str(uuid.uuid4())
                    prescription_data = {
                        'prescription_id': prescription_id,
                        'appointment_id': appointment_id,
                        'doctor_email': appointment['doctor_email'],
                        'doctor_name': appointment['doctor_name'],
                        'patient_email': appointment['patient_email'],
                        'patient_name': appointment['patient_name'],
                        'medications': data['prescription'],
                        'created_at': datetime.utcnow().isoformat()
                    }
                    prescriptions_table.put_item(Item=prescription_data)
                
                return jsonify({'success': True, 'message': 'Appointment updated'}), 200
        
        elif request.method == 'DELETE':
            # Only patients can delete (cancel) appointments
            if role != 'patient':
                return jsonify({'success': False, 'message': 'Only patients can cancel appointments'}), 403
            
            appointments_table.delete_item(Key={'appointment_id': appointment_id})
            return jsonify({'success': True, 'message': 'Appointment cancelled'}), 200
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Error managing appointment: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/prescriptions', methods=['GET'])
def get_prescriptions():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        email = session['email']
        role = session['role']
        
        if role == 'patient':
            response = prescriptions_table.query(
                IndexName='PatientEmailIndex',
                KeyConditionExpression='patient_email = :email',
                ExpressionAttributeValues={':email': email}
            )
        elif role == 'doctor':
            response = prescriptions_table.query(
                IndexName='DoctorEmailIndex',
                KeyConditionExpression='doctor_email = :email',
                ExpressionAttributeValues={':email': email}
            )
        else:
            return jsonify({'success': False, 'message': 'Invalid role'}), 400
        
        prescriptions = response.get('Items', [])
        return jsonify({'success': True, 'prescriptions': prescriptions}), 200
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/profile', methods=['GET', 'PUT'])
def profile():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        email = session['email']
        
        if request.method == 'GET':
            response = users_table.get_item(Key={'email': email})
            if 'Item' not in response:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            user = response['Item']
            # Don't return password hash
            if 'password' in user:
                del user['password']
            
            return jsonify({'success': True, 'user': user}), 200
        
        elif request.method == 'PUT':
            data = request.get_json()
            
            update_expressions = []
            expression_values = {}
            expression_names = {}
            
            if 'name' in data:
                update_expressions.append('#name = :name')
                expression_names['#name'] = 'name'
                expression_values[':name'] = data['name']
                session['name'] = data['name']
            
            if 'phone' in data:
                update_expressions.append('phone = :phone')
                expression_values[':phone'] = data['phone']
            
            if 'password' in data:
                if len(data['password']) < 8:
                    return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
                update_expressions.append('password = :password')
                expression_values[':password'] = generate_password_hash(data['password'])
            
            # Role-specific updates
            role = session['role']
            if role == 'doctor':
                if 'specialization' in data:
                    update_expressions.append('specialization = :specialization')
                    expression_values[':specialization'] = data['specialization']
                if 'qualifications' in data:
                    update_expressions.append('qualifications = :qualifications')
                    expression_values[':qualifications'] = data['qualifications']
                if 'experience' in data:
                    update_expressions.append('experience = :experience')
                    expression_values[':experience'] = data['experience']
                if 'availability' in data:
                    update_expressions.append('availability = :availability')
                    expression_values[':availability'] = data['availability']
            
            elif role == 'patient':
                if 'age' in data:
                    update_expressions.append('age = :age')
                    expression_values[':age'] = data['age']
                if 'gender' in data:
                    update_expressions.append('gender = :gender')
                    expression_values[':gender'] = data['gender']
                if 'blood_group' in data:
                    update_expressions.append('blood_group = :blood_group')
                    expression_values[':blood_group'] = data['blood_group']
                if 'address' in data:
                    update_expressions.append('address = :address')
                    expression_values[':address'] = data['address']
            
            if not update_expressions:
                return jsonify({'success': False, 'message': 'No valid fields to update'}), 400
            
            update_expressions.append('updated_at = :now')
            expression_values[':now'] = datetime.utcnow().isoformat()
            
            update_expression = 'SET ' + ', '.join(update_expressions)
            
            users_table.update_item(
                Key={'email': email},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_names,
                ExpressionAttributeValues=expression_values
            )
            
            return jsonify({'success': True, 'message': 'Profile updated'}), 200
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Error in profile: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/doctors', methods=['GET'])
def get_doctors():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        specialization = request.args.get('specialization')
        
        filter_expression = '#role = :role'
        expression_values = {':role': 'doctor'}
        expression_names = {'#role': 'role'}
        
        if specialization:
            filter_expression += ' AND specialization = :specialization'
            expression_values[':specialization'] = specialization
        
        response = users_table.scan(
            FilterExpression=filter_expression,
            ExpressionAttributeNames=expression_names,
            ExpressionAttributeValues=expression_values
        )
        
        doctors = response.get('Items', [])
        
        # Remove sensitive data
        for doctor in doctors:
            if 'password' in doctor:
                del doctor['password']
            if 'created_at' in doctor:
                del doctor['created_at']
            if 'updated_at' in doctor:
                del doctor['updated_at']
        
        return jsonify({'success': True, 'doctors': doctors}), 200
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500

@app.route('/availability/<doctor_email>', methods=['GET'])
def get_doctor_availability(doctor_email):
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        response = users_table.get_item(Key={'email': doctor_email})
        if 'Item' not in response:
            return jsonify({'success': False, 'message': 'Doctor not found'}), 404
        
        doctor = response['Item']
        if doctor['role'] != 'doctor':
            return jsonify({'success': False, 'message': 'Not a doctor'}), 400
        
        availability = doctor.get('availability', {})
        return jsonify({'success': True, 'availability': availability}), 200
    
    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)