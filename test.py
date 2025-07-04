from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session handling

# Dummy users for demonstration
users = {
    'doctor@example.com': {
        'password': 'doctor123',
        'role': 'doctor',
        'name': 'Dr. John Doe',
        'specialization': 'Cardiology'
    },
    'patient@example.com': {
        'password': 'patient123',
        'role': 'patient',
        'name': 'Jane Smith'
    }
}

# Home/Login Page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users.get(email)
        if user and user['password'] == password:
            session['user'] = {
                'email': email,
                'role': user['role'],
                'name': user['name'],
                'specialization': user.get('specialization')
            }
            if user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            else:
                return redirect(url_for('patient_dashboard'))
        else:
            return "Invalid credentials", 401

    return render_template('login.html')

# Doctor Dashboard
@app.route('/doctor/dashboard')
def doctor_dashboard():
    if 'user' not in session or session['user']['role'] != 'doctor':
        return redirect(url_for('login'))
    return render_template('doctor_dashboard.html',
                           name=session['user']['name'],
                           doctor=session['user'])

# Patient Dashboard
@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user' not in session or session['user']['role'] != 'patient':
        return redirect(url_for('login'))
    return render_template('patient_dashboard.html', name=session['user']['name'])

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
@app.route('/home')
def home():
    return redirect(url_for('login'))
@app.route('/register')
def register():
    return "Register page not implemented yet."



if __name__ == '__main__':
    app.run(debug=True)
