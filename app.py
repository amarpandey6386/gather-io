from flask import Flask, render_template, request, redirect, url_for, session
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

if __name__ == '__main__':
    app.run(debug=True)