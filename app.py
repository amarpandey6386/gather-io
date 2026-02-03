from flask import Flask, render_template, request, redirect, url_for, session, flash
from database_helper import get_db_connection
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key_gather_io' # Session ke liye zaroori hai
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    user_id = session.get('user_id', 0)
    
    # Query to get ideas with vote counts and check if current user voted
    query = """
        SELECT i.*, c.club_name, 
        (SELECT COUNT(*) FROM votes v WHERE v.idea_id = i.idea_id) as vote_total,
        (SELECT COUNT(*) FROM votes v WHERE v.idea_id = i.idea_id AND v.user_id = %s) as user_voted
        FROM ideas i 
        JOIN clubs c ON i.target_club_id = c.club_id
        WHERE i.status = 'trending'
        ORDER BY vote_total DESC
    """
    cursor.execute(query, (user_id,))
    ideas = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template('index.html', ideas=ideas)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # User ko email se dhoondo
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()

        # check_password_hash hashed aur plain password ko compare karta hai
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            # managed_club_id ko session mein dalo (Admin dashboard ke liye)
            session['managed_club_id'] = user.get('managed_club_id')
            
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password. Please try again.", "danger")

    return render_template('login.html')

@app.route('/student_dashboard')
def student_dashboard():
    if 'logged_in' in session and session['role'] == 'student':
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Student ki history fetch karna
        cursor.execute("""
            SELECT i.*, c.club_name 
            FROM ideas i 
            JOIN clubs c ON i.target_club_id = c.club_id 
            WHERE i.creator_id = %s 
            ORDER BY i.created_at DESC
        """, (session['user_id'],))
        
        my_ideas = cursor.fetchall()
        cursor.close()
        db.close()
        return render_template('student_dash.html', ideas=my_ideas)
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # 1. Admin ka data fetch karein
    cursor.execute("SELECT managed_club_id, username FROM users WHERE user_id = %s", (user_id,))
    admin_data = cursor.fetchone()
    
    # DEBUG: Terminal mein check karne ke liye
    print(f"--- DEBUG ADMIN --- ID: {user_id}, Data: {admin_data}")

    if not admin_data or admin_data['managed_club_id'] is None:
        cursor.close()
        db.close()
        # Ek pyara sa error message page par hi dikhane ke liye
        return f"<h1>Setup Incomplete</h1><p>Bhai, database mein user <b>{session['username']}</b> ko abhi tak koi club assign nahi hua hai. MySQL mein <code>managed_club_id</code> set karo.</p>"

    club_id = admin_data['managed_club_id']

    # 2. Club Info fetch karein
    cursor.execute("SELECT club_name FROM clubs WHERE club_id = %s", (club_id,))
    club_info = cursor.fetchone()
    session['club_name'] = club_info['club_name'] if club_info else "Assigned Club"

    # 3. IDEA POOL: Student suggestions (sirf is club ke liye)
    cursor.execute("""
        SELECT i.*, u.username as creator_name, 
        COUNT(v.idea_id) as vote_total
        FROM ideas i 
        JOIN users u ON i.creator_id = u.user_id 
        LEFT JOIN votes v ON i.idea_id = v.idea_id
        WHERE i.target_club_id = %s AND i.status != 'selected'
        ORDER BY i.vote_total DESC
    """, (club_id,))
    idea_pool = cursor.fetchall()

    # 4. HISTORY: Pehle se select kiye huye events
    cursor.execute("""
        SELECT i.title, i.category, s.event_status, s.created_at 
        FROM selected_events s
        JOIN ideas i ON s.idea_id = i.idea_id
        WHERE s.admin_id = %s
        ORDER BY s.created_at DESC
    """, (user_id,))
    history = cursor.fetchall()

    cursor.close()
    db.close()
    return render_template('admin_dash.html', trending=idea_pool, history=history)

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        club_name = request.form.get('club_name')

        # Password ko hash karna zaroori hai (Fixes Invalid Salt Error)
        hashed_pw = generate_password_hash(password)

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        try:
            # 1. Insert User with hashed password
            cursor.execute("""
                INSERT INTO users (username, email, password, role) 
                VALUES (%s, %s, %s, %s)
            """, (username, email, hashed_pw, role))
            
            new_user_id = cursor.lastrowid

            # 2. If Admin, Create Club and Link
            if role == 'admin' and club_name:
                cursor.execute("""
                    INSERT INTO clubs (club_name, creator_admin_id) 
                    VALUES (%s, %s)
                """, (club_name, new_user_id))
                
                new_club_id = cursor.lastrowid

                # Link club to user
                cursor.execute("""
                    UPDATE users SET managed_club_id = %s WHERE user_id = %s
                """, (new_club_id, new_user_id))

            db.commit()
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            db.rollback()
            print(f"Registration Error: {e}")
            flash("Error: Username or Email already exists.", "danger")
        finally:
            cursor.close()
            db.close()

    return render_template('register.html')


@app.route('/suggest_idea', methods=['GET', 'POST'])
def suggest_idea():
    if 'logged_in' not in session or session['role'] != 'student':
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        target_club_id = request.form['target_club_id']
        creator_id = session['user_id']

        try:
            query = """INSERT INTO ideas (title, description, category, creator_id, target_club_id) 
                       VALUES (%s, %s, %s, %s, %s)"""
            cursor.execute(query, (title, description, category, creator_id, target_club_id))
            db.commit()
            flash('Your idea has been submitted to the marketplace!', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception as e:
            print(e)
            flash('Error submitting idea.', 'danger')
            

    # Dropdown ke liye clubs fetch karna
    cursor.execute("SELECT club_id, club_name FROM clubs")
    all_clubs = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template('suggest_idea.html', clubs=all_clubs)

@app.route('/vote/<int:idea_id>', methods=['POST'])
def vote(idea_id):
    if 'logged_in' not in session:
        return jsonify({"error": "Login required"}), 401

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # 1. Check if already voted
        cursor.execute("SELECT * FROM votes WHERE user_id = %s AND idea_id = %s", (user_id, idea_id))
        if cursor.fetchone():
            cursor.execute("DELETE FROM votes WHERE user_id = %s AND idea_id = %s", (user_id, idea_id))
        else:
            cursor.execute("INSERT INTO votes (user_id, idea_id) VALUES (%s, %s)", (user_id, idea_id))

        db.commit()

        # 2. Recalculate total votes for this idea from the votes table
        cursor.execute("SELECT COUNT(*) as total FROM votes WHERE idea_id = %s", (idea_id,))
        new_count = cursor.fetchone()['total']

        # 3. Update the ideas table so the marketplace shows the right number
        cursor.execute("UPDATE ideas SET vote_total = %s WHERE idea_id = %s", (new_count, idea_id))
        db.commit()

        return jsonify({"new_count": new_count})

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()
@app.route('/select_idea/<int:idea_id>', methods=['POST'])
def select_idea(idea_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 1. Idea ka status badal kar 'selected' karo
        cursor.execute("UPDATE ideas SET status = 'selected' WHERE idea_id = %s", (idea_id,))

        # 2. Selected events table mein entry dalo
        # Note: Humein created_at manually dalne ki zaroorat nahi agar SQL mein DEFAULT CURRENT_TIMESTAMP set hai
        cursor.execute("""
            INSERT INTO selected_events (idea_id, admin_id, event_status) 
            VALUES (%s, %s, 'upcoming')
        """, (idea_id, user_id))

        db.commit()
        flash("Idea successfully selected and launched!", "success")
    except Exception as e:
        db.rollback()
        print(f"Error selecting idea: {e}")
        flash("Something went wrong.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/active_events')
def active_events():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    
    # Wo ideas jo Admin ne select kar liye hain
    cursor.execute("""
        SELECT i.title, i.description, i.category, c.club_name, s.event_id, s.volunteer_limit,
        (SELECT COUNT(*) FROM event_registrations er WHERE er.event_id = s.event_id AND er.type = 'volunteer') as current_volunteers
        FROM ideas i
        JOIN selected_events s ON i.idea_id = s.idea_id
        JOIN clubs c ON i.target_club_id = c.club_id
        WHERE s.event_status = 'upcoming'
    """)
    active_events = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template('active_events.html', events=active_events)

@app.route('/join_event/<int:event_id>/<string:reg_type>', methods=['POST'])
def join_event(event_id, reg_type):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()

    try:
        # Check if already registered
        cursor.execute("INSERT INTO event_registrations (event_id, user_id, type) VALUES (%s, %s, %s)", 
                       (event_id, user_id, reg_type))
        db.commit()
        flash(f"Success! You are now a {reg_type} for this event.", "success")
    except Exception as e:
        db.rollback()
        flash("You are already registered for this event!", "warning")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('active_events'))

if __name__ == '__main__':
    app.run(debug=True)