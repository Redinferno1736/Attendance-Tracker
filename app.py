import os
import requests
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from functools import wraps
from datetime import datetime

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def get_db_connection():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    return conn

with get_db_connection() as conn:
    db = conn.cursor()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
            username TEXT NOT NULL, 
            hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS timetable(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER, 
            subject TEXT NOT NULL, 
            day TEXT NOT NULL, 
            time TEXT NOT NULL, 
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS attendance(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL, 
            date TEXT NOT NULL, 
            status TEXT NOT NULL, 
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        if not username:
            return apology("Username is required!")
        elif not password:
            return apology("Password is required!")
        elif not confirmation:
            return apology("Password confirmation is required!")
        if password != confirmation:
            return apology("Passwords do not match!")

        hash = generate_password_hash(password)
        try:
            with get_db_connection() as conn:
                db = conn.cursor()
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash))
                conn.commit()
            return redirect('/')
        except sqlite3.IntegrityError:
            return apology("Username has already been registered!")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        with get_db_connection() as conn:
            db = conn.cursor()
            db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),))
            rows = db.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    with get_db_connection() as conn:
        db = conn.cursor()
        db.execute("SELECT subject, day, time FROM timetable WHERE user_id = ?", (user_id,))
        rows = db.fetchall()

    len_days = {}
    tt = {}
    for row in rows:
        subject = row["subject"]
        day = row["day"]
        time = row["time"]
        if day not in len_days:
            len_days[day] = 1
        else:
            len_days[day] += 1
        if day not in tt:
            tt[day] = [[subject, time]]
        else:
            tt[day].append([subject, time])
    return render_template("index.html", tt=tt, len_days=len_days)

@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")

@app.route("/log", methods=["GET", "POST"])
@login_required
def log():
    user_id = session["user_id"]
    if request.method == "POST":
        subject = request.form.get("subject")
        day = request.form.get("day")
        time = request.form.get("time")

        with get_db_connection() as conn:
            db = conn.cursor()
            db.execute("SELECT * FROM timetable WHERE user_id = ? AND day = ? AND time = ?", (user_id, day, time))
            existing_entry = db.fetchone()

        if existing_entry:
            return apology("This time slot is already taken for the selected day. Please choose a different time.")

        with get_db_connection() as conn:
            db = conn.cursor()
            db.execute("INSERT INTO timetable (user_id, subject, day, time) VALUES (?, ?, ?, ?)", (user_id, subject, day, time))
            conn.commit()
        return redirect("/")
    else:
        return render_template("log.html")

@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():
    user_id = session["user_id"]
    if request.method == "POST":
        date = request.form.get("date")
        status = request.form.get("status")

        with get_db_connection() as conn:
            db = conn.cursor()
            db.execute("SELECT * FROM attendance WHERE user_id = ? AND date = ?", (user_id, date))
            existing_entry = db.fetchone()

        if existing_entry:
            return apology("Attendance for this date has already been recorded. Tough luck scamming")

        with get_db_connection() as conn:
            db = conn.cursor()
            db.execute("INSERT INTO attendance (user_id, date, status) VALUES (?, ?, ?)", (user_id, date, status))
            conn.commit()
        return redirect("/report")
    else:
        return render_template("attendance.html")


@app.route("/report")
@login_required
def report():
    user_id = session["user_id"]
    
    with get_db_connection() as conn:
        db = conn.cursor()
        db.execute("SELECT day, subject, COUNT(*) as total_classes FROM timetable WHERE user_id=? GROUP BY day, subject", (user_id,))
        timetable_data = db.fetchall()
        
        db.execute("""
            SELECT attendance.date, timetable.subject, COUNT(*) as attended_classes 
            FROM attendance 
            JOIN timetable ON attendance.user_id = timetable.user_id 
            WHERE attendance.status='present' AND attendance.user_id=? 
            GROUP BY attendance.date, timetable.subject
        """, (user_id,))
        attendance_data = db.fetchall()
        
        db.execute("""
            SELECT attendance.date, timetable.subject, COUNT(*) as absent_classes 
            FROM attendance 
            JOIN timetable ON attendance.user_id = timetable.user_id 
            WHERE attendance.status='absent' AND attendance.user_id=? 
            GROUP BY attendance.date, timetable.subject
        """, (user_id,))
        absent_data = db.fetchall()

    attendance_by_day = {}
    for values in attendance_data:
        sub = values['subject']
        date = datetime.strptime(values['date'], '%Y-%m-%d')
        day_of_week = date.strftime('%A')
        if (day_of_week, sub) not in attendance_by_day:
            attendance_by_day[(day_of_week, sub)] = 0
        attendance_by_day[(day_of_week, sub)] += values['attended_classes']

    absent_by_day = {}
    for entry in absent_data:
        sub = entry['subject']
        date = datetime.strptime(entry['date'], '%Y-%m-%d')
        day_of_week = date.strftime('%A')
        if (day_of_week, sub) not in absent_by_day:
            absent_by_day[(day_of_week, sub)] = 0
        absent_by_day[(day_of_week, sub)] += entry['absent_classes']

    attendance_percentage = {}
    for items in timetable_data:
        day = items["day"]
        subject = items["subject"]
        attended = attendance_by_day.get((day, subject), 0)
        absent = absent_by_day.get((day, subject), 0)
        if subject not in attendance_percentage:
            attendance_percentage[subject] = {'attended': 0, 'absent': 0, 'total': 0}
        attendance_percentage[subject]['attended'] += attended
        attendance_percentage[subject]['absent'] += absent
        attendance_percentage[subject]['total'] += attended + absent

    total_attended = sum(data['attended'] for data in attendance_percentage.values())
    total_classes = sum(data['total'] for data in attendance_percentage.values())
    overall_percentage = (total_attended / total_classes) * 100 

    return render_template("report.html", attendance_percentage=attendance_percentage, overall_percentage=overall_percentage)