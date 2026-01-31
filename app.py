from flask import Flask, render_template, request, redirect, url_for, session, flash
from database_helper import get_db_connection
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'super_secret_key_gather_io' # Session ke liye zaroori hai
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    # Marketplace: Saare trending ideas fetch karne ka logic yahan aayega
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Login logic: Database se user check karo
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        # Password ko hash karna
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db = get_db_connection()
        cursor = db.cursor()
        
        try:
            query = "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (username, email, hashed_password, role))
            db.commit()
            flash('Registration Successful! Please Login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.rollback()
            flash('Error: Username or Email already exists!', 'danger')
        finally:
            cursor.close()
            db.close()
            
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)