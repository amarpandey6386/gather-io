from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database_helper import get_db_connection
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'super_secret_key_eventhub')  # Use env variable in production
bcrypt = Bcrypt(app)

# Allowed email domains for registration
ALLOWED_EMAIL_DOMAINS = ['cuchd.in']  # Add more domains here if needed

def is_valid_university_email(email):
    """Check if email belongs to allowed university domains"""
    if not email or '@' not in email:
        return False
    domain = email.split('@')[1].lower()
    return domain in ALLOWED_EMAIL_DOMAINS

# Prevent caching of authenticated pages
@app.after_request
def add_header(response):
    if 'logged_in' in session:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

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
        elif not user:
            flash("No account found with this email. Please register first.", "danger")
        else:
            flash("Incorrect password. Please try again.", "danger")

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
        
        # Fetch unread notifications
        cursor.execute("""
            SELECT n.*, i.title as event_title
            FROM notifications n
            JOIN selected_events s ON n.event_id = s.event_id
            JOIN ideas i ON s.idea_id = i.idea_id
            WHERE n.user_id = %s AND n.is_read = FALSE
            ORDER BY n.created_at DESC
            LIMIT 10
        """, (session['user_id'],))
        
        notifications = cursor.fetchall()
        
        # Fetch upcoming events with details
        cursor.execute("""
            SELECT s.*, i.title, i.category, c.club_name,
            (SELECT COUNT(*) FROM event_participants ep WHERE ep.event_id = s.event_id) as current_participants,
            (SELECT COUNT(*) FROM event_participants ep WHERE ep.event_id = s.event_id AND ep.student_id = %s) as is_registered
            FROM selected_events s
            JOIN ideas i ON s.idea_id = i.idea_id
            JOIN clubs c ON i.target_club_id = c.club_id
            WHERE s.event_status = 'upcoming' AND s.registration_deadline >= CURDATE()
            ORDER BY s.event_date ASC
        """, (session['user_id'],))
        
        upcoming_events = cursor.fetchall()
        
        # Convert timedelta to time string for display
        from datetime import timedelta
        for event in upcoming_events:
            if event.get('event_time') and isinstance(event['event_time'], timedelta):
                total_seconds = int(event['event_time'].total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                # Convert to 12-hour format
                period = 'AM' if hours < 12 else 'PM'
                display_hours = hours % 12
                if display_hours == 0:
                    display_hours = 12
                event['event_time_display'] = f"{display_hours:02d}:{minutes:02d} {period}"
            else:
                event['event_time_display'] = str(event.get('event_time', 'TBA'))
        
        cursor.close()
        db.close()
        return render_template('student_dash.html', ideas=my_ideas, notifications=notifications, upcoming_events=upcoming_events)
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # 1. Fetch the admin data
        cursor.execute("SELECT managed_club_id, username FROM users WHERE user_id = %s", (user_id,))
        admin_data = cursor.fetchone()

        if not admin_data or admin_data['managed_club_id'] is None:
            cursor.close()
            db.close()
            flash("Your account is not linked to any club. Please contact administrator.", "danger")
            return redirect(url_for('index'))

        club_id = admin_data['managed_club_id']

        # 2. Fetch the club info
        cursor.execute("SELECT club_name FROM clubs WHERE club_id = %s", (club_id,))
        club_info = cursor.fetchone()
        session['club_name'] = club_info['club_name'] if club_info else "Assigned Club"

        # 3. IDEA POOL: Student suggestions
        cursor.execute("""
            SELECT i.*, u.username as creator_name, 
            COALESCE(COUNT(v.vote_id), 0) as vote_total
            FROM ideas i 
            JOIN users u ON i.creator_id = u.user_id 
            LEFT JOIN votes v ON i.idea_id = v.idea_id
            WHERE i.target_club_id = %s AND i.status != 'selected'
            GROUP BY i.idea_id, i.title, i.description, i.category, i.creator_id, i.target_club_id, i.status, i.created_at, i.vote_total, u.username
            ORDER BY vote_total DESC
        """, (club_id,))
        idea_pool = cursor.fetchall()

        # 4. UPCOMING EVENTS: Events that haven't started yet
        cursor.execute("""
            SELECT i.title, i.category, s.event_status, s.created_at, s.event_id
            FROM selected_events s
            JOIN ideas i ON s.idea_id = i.idea_id
            WHERE s.admin_id = %s AND s.event_status = 'upcoming'
            ORDER BY s.created_at DESC
        """, (user_id,))
        upcoming_events = cursor.fetchall()

        # 5. LIVE EVENTS: Events currently happening
        cursor.execute("""
            SELECT i.title, i.category, s.event_status, s.created_at, s.event_id,
            (SELECT COUNT(*) FROM event_participants WHERE event_id = s.event_id) as participant_count
            FROM selected_events s
            JOIN ideas i ON s.idea_id = i.idea_id
            WHERE s.admin_id = %s AND s.event_status = 'live'
            ORDER BY s.created_at DESC
        """, (user_id,))
        live_events = cursor.fetchall()

        # 6. HISTORY: Closed events
        cursor.execute("""
            SELECT i.title, i.category, s.event_status, s.created_at, s.event_id
            FROM selected_events s
            JOIN ideas i ON s.idea_id = i.idea_id
            WHERE s.admin_id = %s AND s.event_status = 'closed'
            ORDER BY s.created_at DESC
        """, (user_id,))
        history = cursor.fetchall()

        # 7. MEMBERSHIP REQUESTS: Pending requests for this club
        cursor.execute("""
            SELECT r.*, u.username, u.email
            FROM club_membership_requests r
            JOIN users u ON r.student_id = u.user_id
            WHERE r.club_id = %s AND r.status = 'pending'
            ORDER BY r.created_at DESC
        """, (club_id,))
        membership_requests = cursor.fetchall()

        cursor.close()
        db.close()
        return render_template('admin_dash.html', trending=idea_pool, upcoming_events=upcoming_events, live_events=live_events, history=history, membership_requests=membership_requests)
    
    except Exception as e:
        print(f"Admin Dashboard Error: {e}")
        flash("Error loading dashboard. Please try again.", "danger")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'info')
    response = redirect(url_for('login'))
    # Prevent browser from caching authenticated pages
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        club_name = request.form.get('club_name')

        # Validate university email domain
        if not is_valid_university_email(email):
            flash(f"Please use a valid university email address (@cuchd.in)", "danger")
            return render_template('register.html')

        # Hash the password for secured authentication
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
    if 'logged_in' not in session:
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
        existing_vote = cursor.fetchone()
        
        if existing_vote:
            # Remove vote (unvote)
            cursor.execute("DELETE FROM votes WHERE user_id = %s AND idea_id = %s", (user_id, idea_id))
            action = 'unvoted'
        else:
            # Add vote
            cursor.execute("INSERT INTO votes (user_id, idea_id) VALUES (%s, %s)", (user_id, idea_id))
            action = 'voted'

        db.commit()

        # 2. Recalculate total votes for this idea from the votes table
        cursor.execute("SELECT COUNT(*) as total FROM votes WHERE idea_id = %s", (idea_id,))
        new_count = cursor.fetchone()['total']

        # 3. Update the ideas table so the marketplace shows the right number
        cursor.execute("UPDATE ideas SET vote_total = %s WHERE idea_id = %s", (new_count, idea_id))
        db.commit()

        return jsonify({"count": new_count, "action": action})

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/select_idea/<int:idea_id>', methods=['GET'])
def select_idea(idea_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get idea details
        cursor.execute("SELECT * FROM ideas WHERE idea_id = %s", (idea_id,))
        idea = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if not idea:
            flash("Idea not found", "danger")
            return redirect(url_for('admin_dashboard'))
        
        return render_template('event_details_form.html', idea=idea)
    
    except Exception as e:
        print(f"Error: {e}")
        flash("Something went wrong", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/launch_event/<int:idea_id>', methods=['POST'])
def launch_event(idea_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get form data
        venue = request.form.get('venue')
        event_date = request.form.get('event_date')
        event_time = request.form.get('event_time')
        description = request.form.get('description')
        max_participants = request.form.get('max_participants')
        registration_deadline = request.form.get('registration_deadline')

        # 1. Update idea status
        cursor.execute("UPDATE ideas SET status = 'selected' WHERE idea_id = %s", (idea_id,))

        # 2. Create event with details
        cursor.execute("""
            INSERT INTO selected_events (idea_id, admin_id, event_status, event_venue, event_date, event_time, event_description, max_participants, registration_deadline) 
            VALUES (%s, %s, 'upcoming', %s, %s, %s, %s, %s, %s)
        """, (idea_id, user_id, venue, event_date, event_time, description, max_participants, registration_deadline))

        db.commit()
        flash("Event launched successfully!", "success")
    except Exception as e:
        db.rollback()
        print(f"Error launching event: {e}")
        flash("Something went wrong.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/notify_event/<int:event_id>', methods=['POST'])
def notify_event(event_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get event details
        cursor.execute("""
            SELECT i.title, i.idea_id, i.target_club_id, s.event_status
            FROM selected_events s
            JOIN ideas i ON s.idea_id = i.idea_id
            WHERE s.event_id = %s AND s.admin_id = %s
        """, (event_id, session['user_id']))
        
        event = cursor.fetchone()
        
        if not event:
            return jsonify({"error": "Event not found"}), 404

        # Change event status from 'upcoming' to 'live'
        cursor.execute("""
            UPDATE selected_events 
            SET event_status = 'live' 
            WHERE event_id = %s
        """, (event_id,))

        # Get ALL students (not just voters)
        cursor.execute("""
            SELECT user_id
            FROM users
            WHERE role = 'student'
        """)
        
        students = cursor.fetchall()
        
        # Create notification message
        message = f"🎉 Event LIVE NOW! '{event['title']}' has started. Join us!"
        
        # Insert notifications for all students
        notification_count = 0
        for student in students:
            # Check if notification already exists to avoid duplicates
            cursor.execute("""
                SELECT notification_id FROM notifications
                WHERE user_id = %s AND event_id = %s
            """, (student['user_id'], event_id))
            
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO notifications (user_id, event_id, message)
                    VALUES (%s, %s, %s)
                """, (student['user_id'], event_id, message))
                notification_count += 1
        
        db.commit()
        
        return jsonify({
            "success": True,
            "message": f"Event is now LIVE! Notification sent to {notification_count} student(s)",
            "count": notification_count
        })
    
    except Exception as e:
        db.rollback()
        print(f"Notify Error: {e}")
        return jsonify({"error": "Failed to send notifications"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/close_event/<int:event_id>', methods=['POST'])
def close_event(event_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Verify admin owns this event
        cursor.execute("""
            SELECT event_id FROM selected_events
            WHERE event_id = %s AND admin_id = %s
        """, (event_id, session['user_id']))
        
        if not cursor.fetchone():
            return jsonify({"error": "Unauthorized"}), 403

        # Change event status to 'closed'
        cursor.execute("""
            UPDATE selected_events 
            SET event_status = 'closed' 
            WHERE event_id = %s
        """, (event_id,))

        db.commit()
        return jsonify({"success": True, "message": "Event closed successfully"})
    
    except Exception as e:
        db.rollback()
        print(f"Close Event Error: {e}")
        return jsonify({"error": "Failed to close event"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("""
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE notification_id = %s AND user_id = %s
        """, (notification_id, session['user_id']))
        
        db.commit()
        return jsonify({"success": True})
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/clubs')
def clubs():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get all clubs with member count
        cursor.execute("""
            SELECT c.*, u.username as admin_name,
            (SELECT COUNT(*) FROM club_members cm WHERE cm.club_id = c.club_id) as member_count
            FROM clubs c
            LEFT JOIN users u ON c.creator_admin_id = u.user_id
            ORDER BY c.club_name
        """)
        all_clubs = cursor.fetchall()

        # If student, get their membership status for each club
        if session['role'] == 'student':
            for club in all_clubs:
                # Check if already a member
                cursor.execute("""
                    SELECT member_id FROM club_members 
                    WHERE student_id = %s AND club_id = %s
                """, (session['user_id'], club['club_id']))
                club['is_member'] = cursor.fetchone() is not None

                # Check if request is pending
                cursor.execute("""
                    SELECT status FROM club_membership_requests 
                    WHERE student_id = %s AND club_id = %s
                """, (session['user_id'], club['club_id']))
                request = cursor.fetchone()
                club['request_status'] = request['status'] if request else None

        cursor.close()
        db.close()
        return render_template('clubs.html', clubs=all_clubs)

    except Exception as e:
        print(f"Clubs Error: {e}")
        flash("Error loading clubs", "danger")
        return redirect(url_for('index'))

@app.route('/request_club_membership/<int:club_id>', methods=['POST'])
def request_club_membership(club_id):
    if 'logged_in' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor()

    try:
        message = request.json.get('message', '')

        # Insert membership request
        cursor.execute("""
            INSERT INTO club_membership_requests (student_id, club_id, request_message)
            VALUES (%s, %s, %s)
        """, (session['user_id'], club_id, message))

        db.commit()
        return jsonify({"success": True, "message": "Membership request sent!"})

    except Exception as e:
        db.rollback()
        print(f"Request Error: {e}")
        return jsonify({"error": "Request already sent or failed"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/approve_membership/<int:request_id>', methods=['POST'])
def approve_membership(request_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get request details
        cursor.execute("""
            SELECT r.*, c.creator_admin_id
            FROM club_membership_requests r
            JOIN clubs c ON r.club_id = c.club_id
            WHERE r.request_id = %s
        """, (request_id,))
        
        req = cursor.fetchone()
        
        if not req or req['creator_admin_id'] != session['user_id']:
            return jsonify({"error": "Unauthorized"}), 403

        # Update request status
        cursor.execute("""
            UPDATE club_membership_requests 
            SET status = 'approved' 
            WHERE request_id = %s
        """, (request_id,))

        # Add to club_members
        cursor.execute("""
            INSERT INTO club_members (student_id, club_id)
            VALUES (%s, %s)
        """, (req['student_id'], req['club_id']))

        db.commit()
        return jsonify({"success": True, "message": "Membership approved!"})

    except Exception as e:
        db.rollback()
        print(f"Approve Error: {e}")
        return jsonify({"error": "Failed to approve"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/reject_membership/<int:request_id>', methods=['POST'])
def reject_membership(request_id):
    if 'logged_in' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # Get request details
        cursor.execute("""
            SELECT r.*, c.creator_admin_id
            FROM club_membership_requests r
            JOIN clubs c ON r.club_id = c.club_id
            WHERE r.request_id = %s
        """, (request_id,))
        
        req = cursor.fetchone()
        
        if not req or req['creator_admin_id'] != session['user_id']:
            return jsonify({"error": "Unauthorized"}), 403

        # Update request status
        cursor.execute("""
            UPDATE club_membership_requests 
            SET status = 'rejected' 
            WHERE request_id = %s
        """, (request_id,))

        db.commit()
        return jsonify({"success": True, "message": "Membership rejected"})

    except Exception as e:
        db.rollback()
        print(f"Reject Error: {e}")
        return jsonify({"error": "Failed to reject"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/register_for_event/<int:event_id>', methods=['POST'])
def register_for_event(event_id):
    if 'logged_in' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    try:
        data = request.json
        student_name = data.get('name')
        student_email = data.get('email')
        student_phone = data.get('phone')
        participation_type = data.get('type', 'participant')
        additional_info = data.get('info', '')

        # Check if event is full
        cursor.execute("""
            SELECT s.max_participants,
            (SELECT COUNT(*) FROM event_participants WHERE event_id = %s) as current_count
            FROM selected_events s
            WHERE s.event_id = %s
        """, (event_id, event_id))
        
        event_info = cursor.fetchone()
        
        if event_info and event_info['current_count'] >= event_info['max_participants']:
            return jsonify({"error": "Event is full"}), 400

        # Register participant
        cursor.execute("""
            INSERT INTO event_participants (event_id, student_id, student_name, student_email, student_phone, participation_type, additional_info)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (event_id, session['user_id'], student_name, student_email, student_phone, participation_type, additional_info))

        db.commit()
        return jsonify({"success": True, "message": "Registration successful!"})

    except Exception as e:
        db.rollback()
        print(f"Registration Error: {e}")
        return jsonify({"error": "Already registered or failed"}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/mark_all_notifications_read', methods=['POST'])
def mark_all_notifications_read():
    if 'logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute("""
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        
        db.commit()
        return jsonify({"success": True})
    
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        db.close()

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

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        feedback_type = data.get('feedback_type')
        message = data.get('message')
        rating = data.get('rating', 5)
        
        # Get user_id if logged in
        user_id = session.get('user_id', None)
        
        db = get_db_connection()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO feedback (user_id, name, email, feedback_type, message, rating)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, name, email, feedback_type, message, rating))
        
        db.commit()
        cursor.close()
        db.close()
        
        return jsonify({"success": True, "message": "Feedback submitted successfully!"})
    
    except Exception as e:
        print(f"Feedback Error: {e}")
        return jsonify({"success": False, "error": "Failed to submit feedback"}), 500

@app.route('/join_event/<int:event_id>/<string:reg_type>', methods=['POST'])
def join_event(event_id, reg_type):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

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