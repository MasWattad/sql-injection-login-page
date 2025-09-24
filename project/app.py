from flask import Flask, request, render_template, redirect, url_for, flash 
import sqlite3
import re
import string
import bcrypt
import random
app = Flask(__name__)
app.secret_key = 'your_secret_key'

 # Generates a salt and hashes the password
def hash_password(password):
    salt = bcrypt.gensalt()  
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


 # Check if the entered password matches the stored hash
def verify_password(entered_password, stored_hash):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash)


# Function to validate input,reports suspicious patterns (SQL keywords, overly long input, special characters)
def validate_login(username, password):
    
    if len(username) > 20 or len(password) > 20:
        return "Input too long"
    
    suspicious_strings = ["'", "--", ";", "or ", "and", "select", "delete", "from", "update", "where", "union", "insert", "drop"]
    for strr in suspicious_strings:
       if strr.lower() in username.lower() or strr.lower() in password.lower():
            return "Suspicious input detected"
    
    return None

# Function to validate signup ,reports suspicious patterns and makes sure the password is strong 
def validate_signupinfo(username, password):
    
    if len(username) <5 :
        return "The username must be at least 5 characters long"
    if len(password) < 10:
        return "The password must be at least 10 characters long"
    if len(username) >20 :
        return "The username is too long"
    if len(password) > 20:
        return "The password is too long"

    suspicious_strings = ["'", "--", ";", "or ", "and", "select", "delete", "from", "update", "where", "union", "insert", "drop"]
    for strr in suspicious_strings:
       if strr.lower() in username.lower():
            return " username should not contain ' , -- , ; , or, and, select, delete, from, update, where, union, insert, drop"
       if strr.lower() in password.lower():
            return " password should not contain ' , -- , ; , or, and, select, delete, from, update, where, union, insert, drop"

    lower = False
    upper = False
    digit = False
    symbol = False
    # Define character sets of lowecase and uppercase letters legal symbols and numbers
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation

    # Iterates through each character in the password
    for char in password:
        if char in lowercase_letters:
            lower = True
        elif char in uppercase_letters:
            upper = True
        elif char in digits:
            digit = True
        elif char in symbols:
            symbol = True

    # Checks all condections for strong password (uppercase letter ,lowecase letter, number ,symbol) 
    if not lower:
        return "Password must contain at least one lowercase letter."
    if not upper:
        return "Password must contain at least one uppercase letter."
    if not digit:
        return "Password must contain at least one number."
    if not symbol:
        return "Password must contain at least one symbol."
    
    return None

@app.route('/generate_password', methods=['GET'])
def generate_password():
    password_length = random.randint(11, 19)  # Random length between 11 and 19
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[{]}|;:'\",<.>/?"
    excluded_chars = ["'", "--", ";"]
    
    # Removes excluded characters from symbols
    symbols = ''.join(c for c in symbols if c not in excluded_chars)

    all_characters = lowercase + uppercase + digits + symbols

    # Ensures the password contains at least one lowercase, one uppercase, one digit, and one symbol and picks it randomly 
    password = [random.choice(lowercase), random.choice(uppercase), random.choice(digits),random.choice(symbols),]

    # Fills the rest of the password with random characters
    for _ in range(password_length - 4):
        password.append(random.choice(all_characters))

    random.shuffle(password)
    return ''.join(password)

# Route for the login page
@app.route('/')
def login_page():
    return render_template('login.html')

# Route for the signup page
@app.route('/signup')
def signup_page():
    return render_template('signup.html')

# Route to handle signup submissions
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    hashed_password = hash_password(password)
    # Connects to SQLite database
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()

    # Checks if the username already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash('Username already exists. Please choose a different username.')
        return redirect(url_for('signup_page'))
    weak=validate_signupinfo(username, password)
    if weak is not None: 
        flash(weak)
        return redirect(url_for('signup_page'))
    # Inserts the new user with the password 
    else:
         cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
    conn.commit()
    conn.close()

    flash('User registered successfully! You can now log in.')
    return redirect(url_for('login_page'))

# Route to handle login submissions
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    suspicious = validate_login(username, password)
    if suspicious is not None: 
        flash(suspicious)
        return redirect(url_for('login_page'))

    # Connect to SQLite database
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    
    # Use a parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        stored_password = user[2] 
        if verify_password(password, stored_password.encode('utf-8')):
            return render_template('youin.html', username=user[1])
        else:
            flash('Invalid password.')
    else:
        flash('Invalid username.')
    
    return redirect(url_for('login_page'))

# Route to handle logging out
@app.route('/logout')
def logout():
    flash('You have been logged out.')
    return redirect(url_for('login_page'))

# Route for the youin page
@app.route('/youin')
def you_in():
    username = "name" 
    return render_template('youin.html', username=username)


# Route for the education page
@app.route('/education')
def education_page():
    return render_template('education.html')
correct_answers = {
   "q1": "b",
   "q2": "d",
   "q3": "c",
   "q4": "a",
   "q5": "c"
}

@app.route('/quizz')
def quizz_page():
    return render_template('quizz.html') 

@app.route('/submit', methods=['POST'])
def submit():
    score = 0
    total = 5  # Since you have 5 questions
    for question, correct_answer in correct_answers.items():
        user_answer = request.form.get(question)
        if user_answer == correct_answer:
            score += 1

    # Render the result template with the score
    return render_template('result.html', score=score, total=total)

if __name__ == '__main__':
    app.run(debug=True)
