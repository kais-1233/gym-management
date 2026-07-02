from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
import requests
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import os 
import csv
import re
from flask import Response
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-for-sessions")

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# PostgreSQL Database Connection
def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        dbname=os.getenv("DB_NAME"),
        cursor_factory=psycopg2.extras.DictCursor
    )

# Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_days_left(expiry_date):
    today = datetime.today().date()
    if hasattr(expiry_date, "year"):
        return (expiry_date - today).days
    expiry_date = datetime.strptime(str(expiry_date), "%Y-%m-%d").date()
    return (expiry_date - today).days

# --- AUTHENTICATION ROUTES ---

def send_whatsapp_message(mobile, msg_type, name, gym_name, plan=None, expiry_date=None):
    if msg_type == "welcome":
        message = f"Hello {name}! 🏋️ Welcome to {gym_name}. Aapka {plan}-month ka plan activate ho gaya hai."
    elif msg_type == "expiring":
        message = f"Hi {name}, reminder! ⏳ Aapka gym subscription {expiry_date} ko expire hone wala hai. Kripya time par renew kar lein."
    elif msg_type == "expired":
        message = f"Hi {name}, aapka gym plan aaj expire ho chuka hai 🚫. Renew karein!"
    
    print(f"\n📩 [MESSAGE] -> {mobile}", flush=True)

    try:
        log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'whatsapp_logs.txt')
        with open(log_file, "a", encoding="utf-8") as f:
            time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{time_now}] TO: {mobile} | MSG: {message}\n")
    except Exception as e:
        print("Log error:", e)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        mobile = request.form["mobile"]
        gym_name = request.form["gym_name"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"] # NEW FIELD
        
        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match! Please try again.", "danger")
            return redirect(url_for('register'))
        #   Mobile 10-digit Validation ---
        if not re.match(r'^\d{10}$', mobile):
            flash("Invalid mobile number. Must be exactly 10 digits.", "danger")
            return redirect(url_for('register'))
        # Email Validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.com$', email):
            flash("Invalid email format. Must contain '@' and end with '.com'.", "danger")
            return redirect(url_for('register'))

        # Password Validation (6-12 chars, at least 1 letter, 1 number, 1 special char)
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,12}$', password):
            flash("Password must be 6 to 12 characters and include a letter, a number, and a special character.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (name, email, mobile, gym_name, password_hash) VALUES (%s, %s, %s, %s, %s)",
                (name, email, mobile, gym_name, hashed_password)
            )
            conn.commit()
            flash("Registration successful! You can now login.", "success")
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Email or Mobile already registered. Try logging in.", "warning")
            return redirect(url_for('register'))
        finally:
            conn.close()
            
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_id = request.form["login_id"] 
        password = request.form["password"]
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s OR mobile = %s", (login_id, login_id))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['gym_name'] = user['gym_name']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Email/Mobile or Password! Please try again.", "danger")
            return redirect(url_for('login'))
            
    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        mobile = request.form["mobile"]
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s AND mobile = %s", (email, mobile))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['reset_user_id'] = user['id']
            flash("Account verified. Please enter your new password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("No account found with this Email and Mobile combination.", "danger")
            return redirect(url_for('forgot_password'))
            
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if 'reset_user_id' not in session:
        flash("Unauthorized access. Please verify your account first.", "danger")
        return redirect(url_for('forgot_password'))
        
    if request.method == "POST":
        new_password = request.form["new_password"]
        
        # Password Validation (6-12 chars, at least 1 letter, 1 number, 1 special char)
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,12}$', new_password):
            flash("Password must be 6 to 12 characters and include a letter, a number, and a special character.", "danger")
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(new_password)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, session['reset_user_id']))
        conn.commit()
        conn.close()
        
        session.pop('reset_user_id', None)
        flash("Password reset successfully! You can now login.", "success")
        return redirect(url_for('login'))
        
    return render_template("reset_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- MAIN APP ROUTES ---

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE members
        SET member_status='left'
        WHERE member_status='active'
        AND user_id = %s
        AND expiry_date <= CURRENT_DATE - INTERVAL '30 days'
    """, (session['user_id'],))
    conn.commit()

    cursor.execute("SELECT * FROM members WHERE member_status='active' AND user_id = %s", (session['user_id'],))
    members = cursor.fetchall()
    
    member_list = []
    active = expiring = expired = 0

    for member in members:
        member_dict = dict(member)
        days = get_days_left(member["expiry_date"])
        member_dict["days_left"] = days
        member_list.append(member_dict)

        if days <= 0:
            expired += 1
        elif days <= 2:
            expiring += 1
        else:
            active += 1

    conn.close()

    return render_template(
        "dashboard.html",
        total=len(members),
        active=active,
        expiring=expiring,
        expired=expired,
        members=member_list,
        gym_name=session.get('gym_name')
    )

@app.route("/add", methods=["GET","POST"])
@login_required
def add_member():
    if request.method == "POST":
        name = request.form["name"]
        mobile = request.form["mobile"]
        plan = int(request.form["plan"])
        join_date = request.form["join_date"]
        # --- NEW: Mobile 10-digit Validation ---
        if not re.match(r'^\d{10}$', mobile):
            flash("Invalid mobile number. Must be exactly 10 digits.", "danger")
            return redirect("/add")
        join_dt = datetime.strptime(join_date, "%Y-%m-%d")
        # 1 Month = 30 Days strictly
        expiry_dt = join_dt + timedelta(days=plan * 30)
        expiry_date = expiry_dt.strftime("%Y-%m-%d")

        photo_path = "" 
        if 'photo' in request.files:
            photo = request.files["photo"]
            if photo and photo.filename != "":
                filename = photo.filename
                photo_path = os.path.join(UPLOAD_FOLDER, filename)
                photo.save(photo_path)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO members (user_id, name, mobile, plan, join_date, expiry_date, photo)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (session['user_id'], name, mobile, plan, join_date, expiry_date, photo_path))

        conn.commit()
        conn.close()
        
        send_whatsapp_message(mobile, "welcome", name=name, gym_name=session['gym_name'], plan=plan)
        return redirect("/members")

    return render_template("add_member.html")

@app.route("/members")
@login_required
def members():
    status = request.args.get("status")
    search = request.args.get("search", "")
    page_title = "Total Members"

    conn = get_db()
    cursor = conn.cursor()

    if search:
        page_title = "Search Results"
        cursor.execute("SELECT * FROM members WHERE user_id=%s", (session['user_id'],))
    else:
        if status == "active":
            page_title = "Active Members"
        elif status == "expiring":
            page_title = "Expiring Soon"
        elif status == "expired":
            page_title = "Expired Members"
            
        cursor.execute("SELECT * FROM members WHERE user_id=%s AND member_status='active'", (session['user_id'],))
        
    members = cursor.fetchall()
    
    member_list = []
    for member in members:
        days_left = get_days_left(member["expiry_date"])
        member_dict = dict(member)
        member_dict["days_left"] = days_left  
         
        if search and search.lower() not in member["name"].lower() and search not in member["mobile"]:
            continue

        if not search:
            if status == "active" and days_left <= 2: continue
            elif status == "expiring" and not (1 <= days_left <= 2): continue
            elif status == "expired" and days_left > 0: continue

        member_list.append(member_dict)

    conn.close()
    return render_template("members.html", members=member_list, page_title=page_title)

@app.route("/edit/<int:id>", methods=["GET","POST"])
@login_required
def edit_member(id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM members WHERE id=%s AND user_id=%s", (id, session['user_id']))
    member = cursor.fetchone()

    if not member:
        conn.close()
        return "Unauthorized or member not found", 403

    if request.method == "POST":
        name = request.form["name"]
        mobile = request.form["mobile"]
        plan = int(request.form["plan"])
        join_date = request.form["join_date"]
        # --- NEW: Mobile 10-digit Validation ---
        if not re.match(r'^\d{10}$', mobile):
            flash("Invalid mobile number. Must be exactly 10 digits.", "danger")
            return redirect("/add")
        join_dt = datetime.strptime(join_date, "%Y-%m-%d")
        # 1 Month = 30 Days strictly
        expiry_dt = join_dt + timedelta(days=plan * 30)
        expiry_date = expiry_dt.strftime("%Y-%m-%d")

        cursor.execute("""
            UPDATE members
            SET name=%s, mobile=%s, plan=%s, join_date=%s, expiry_date=%s, member_status='active'
            WHERE id=%s AND user_id=%s
        """, (name, mobile, plan, join_date, expiry_date, id, session['user_id']))

        conn.commit()
        conn.close()
        return redirect("/members")

    conn.close()
    return render_template("edit_member.html", member=member)

@app.route("/left-gym")
@login_required
def left_gym():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM members WHERE member_status='left' AND user_id=%s", (session['user_id'],))
    members = cursor.fetchall()
    
    left_members = []
    for member in members:
        member_dict = dict(member)
        member_dict["days_left"] = get_days_left(member["expiry_date"])
        left_members.append(member_dict)

    conn.close()
    return render_template("members.html", members=left_members, page_title="Left Gym Members")

@app.route("/recent-joins")
@login_required
def recent_joins():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM members
        WHERE EXTRACT(MONTH FROM join_date) = EXTRACT(MONTH FROM CURRENT_DATE)
        AND EXTRACT(YEAR FROM join_date) = EXTRACT(YEAR FROM CURRENT_DATE)
        AND user_id = %s
        ORDER BY join_date DESC
    """, (session['user_id'],))
    
    members = cursor.fetchall()
    conn.close()

    member_list = []
    for member in members:
        member_dict = dict(member)
        member_dict["days_left"] = get_days_left(member["expiry_date"])
        member_list.append(member_dict)

    return render_template("members.html", members=member_list, page_title="Recent Joined Members")

@app.route("/export")
@login_required
def export_excel():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, name, mobile, plan, join_date, expiry_date FROM members WHERE user_id=%s", (session['user_id'],))
    members = cursor.fetchall()
    conn.close()

    def generate():
        yield "ID,Name,Mobile,Plan (Months),Join Date,Expiry Date\n"
        for m in members:
            yield f"{m['id']},{m['name']},{m['mobile']},{m['plan']},{m['join_date']},{m['expiry_date']}\n"

    return Response(
        generate(), 
        mimetype='text/csv', 
        headers={"Content-Disposition": "attachment; filename=members_export.csv"}
    )
@app.route("/delete/<int:id>")
@login_required
def delete_member(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM members WHERE id=%s AND user_id=%s", (id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect("/members")

if __name__ == "__main__":
    app.run(debug=True)