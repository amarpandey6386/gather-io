from flask import Flask, render_template, request, redirect, url_for, session, flash
from database_helper import get_db_connection
from flask_bcrypt import Bcrypt

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
        email = request.form['email']
        password_candidate = request.form['password']
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True) # dictionary=True se data {'column': value} format mein milega
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user and bcrypt.check_password_hash(user['password'], password_candidate):
            # Session mein user ki details save karna
            session['logged_in'] = True
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            flash(f"Welcome back, {user['username']}!", 'success')
            
            # Role ke hisaab se redirect karna
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid login credentials', 'danger')
            
        cursor.close()
        db.close()
        
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

    # 1. Admin ka Club ID pata karo
    cursor.execute("""
    SELECT c.club_id, c.club_name 
    FROM clubs c 
    JOIN users u ON u.managed_club_id = c.club_id 
    WHERE u.user_id = %s
    """, (user_id,))
    admin_club = cursor.fetchone()

    if admin_club:
        club_id = admin_club['club_id']
        session['club_name'] = admin_club['club_name']

        # 2. IDEA POOL: Wo ideas jo abhi tak select nahi huye (Pending/Trending)
        cursor.execute("""
            SELECT i.*, u.username as creator_name 
            FROM ideas i 
            JOIN users u ON i.user_id = u.user_id 
            WHERE i.target_club_id = %s AND i.status != 'selected'
            ORDER BY i.vote_total DESC
        """, (club_id,))
        idea_pool = cursor.fetchall()

        # 3. SELECTED HISTORY: Jo pehle hi select ho chuke hain
        cursor.execute("""
            SELECT i.title, i.category, s.event_status, s.selected_at 
            FROM ideas i 
            JOIN selected_events s ON i.idea_id = s.idea_id 
            WHERE i.target_club_id = %s
        """, (club_id,))
        history = cursor.fetchall()
    else:
        idea_pool = []
        history = []

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
    clubs = cursor.fetchall()
    
    cursor.close()
    db.close()
    return render_template('suggest_idea.html', clubs=clubs)

@app.route('/vote/<int:idea_id>', methods=['POST'])
def vote(idea_id):
    if 'logged_in' not in session:
        return {"error": "Unauthorized"}, 401

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Check if already voted
    cursor.execute("SELECT * FROM votes WHERE user_id = %s AND idea_id = %s", (user_id, idea_id))
    existing_vote = cursor.fetchone()

    if existing_vote:
        # Unvote logic
        cursor.execute("DELETE FROM votes WHERE user_id = %s AND idea_id = %s", (user_id, idea_id))
        action = "unvoted"
    else:
        # Vote logic
        cursor.execute("INSERT INTO votes (user_id, idea_id) VALUES (%s, %s)", (user_id, idea_id))
        action = "voted"

    db.commit()
    
    # New vote count fetch karo
    cursor.execute("SELECT COUNT(*) as count FROM votes WHERE idea_id = %s", (idea_id,))
    vote_count = cursor.fetchone()['count']
    
    cursor.close()
    db.close()

    return {"action": action, "count": vote_count}

@app.route('/select_idea/<int:idea_id>', methods=['POST'])
def select_idea(idea_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return {"error": "Unauthorized"}, 401

    db = get_db_connection()
    cursor = db.cursor()

    try:
        # 1. Update Idea status
        cursor.execute("UPDATE ideas SET status = 'selected' WHERE idea_id = %s", (idea_id,))
        
        # 2. Add to Selected Events table
        # Aap chahein toh yahan volunteer_limit default 10 rakh sakte hain
        cursor.execute("""
            INSERT INTO selected_events (idea_id, admin_id, volunteer_limit) 
            VALUES (%s, %s, %s)
        """, (idea_id, session['user_id'], 10))
        
        db.commit()
        flash("Idea Selected! It's now an official event.", "success")
    except Exception as e:
        db.rollback()
        flash("Error selecting idea.", "danger")
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