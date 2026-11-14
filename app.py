import os
import csv
import sqlite3
import threading
from io import StringIO, BytesIO
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    session, send_file
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from flask_wtf.csrf import CSRFProtect


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

secret_key = os.environ.get("MESSVOICE_SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "MESSVOICE_SECRET_KEY is missing. "
        "Set the environment variable before starting MessVoice."
    )

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable HTTPS-only cookies when running behind HTTPS in production.
# Set MESSVOICE_HTTPS=1 on the production host after HTTPS is configured.
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("MESSVOICE_HTTPS") == "1"
)

csrf = CSRFProtect(app)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "votes.db"
)

# Guards create_database() so it runs exactly once per process,
# whether the app is started via `python app.py` or `gunicorn app:app`.
_db_initialized = False
_db_init_lock = threading.Lock()


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# =========================================================
# DATABASE INITIALIZATION
# Keeps existing students and votes
# =========================================================

def create_database():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                breakfast TEXT,
                lunch TEXT,
                dinner TEXT,
                student_id TEXT
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(votes)"
            ).fetchall()
        }

        if "student_id" not in columns:
            conn.execute(
                "ALTER TABLE votes ADD COLUMN student_id TEXT"
            )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        admin = conn.execute("""
            SELECT id
            FROM admins
            WHERE username = ?
        """, ("admin",)).fetchone()

        if admin is None:
            initial_password = os.environ.get(
                "MESSVOICE_INITIAL_ADMIN_PASSWORD"
            )

            if not initial_password or len(initial_password) < 12:
                raise RuntimeError(
                    "Admin account is missing. Set "
                    "MESSVOICE_INITIAL_ADMIN_PASSWORD to a strong "
                    "password of at least 12 characters, then restart."
                )

            conn.execute("""
                INSERT INTO admins (username, password)
                VALUES (?, ?)
            """, (
                "admin",
                generate_password_hash(initial_password)
            ))

        # Add the one-vote-per-student index only when existing
        # linked votes do not contain duplicate student IDs.
        duplicates = conn.execute("""
            SELECT student_id
            FROM votes
            WHERE student_id IS NOT NULL
            GROUP BY student_id
            HAVING COUNT(*) > 1
        """).fetchall()

        if not duplicates:
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS
                unique_vote_per_student
                ON votes(student_id)
                WHERE student_id IS NOT NULL
            """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# =========================================================
# ENSURE DB IS READY ON FIRST REQUEST (GUNICORN-SAFE)
# =========================================================
# This runs before the very first request in each worker process.
# All SQL statements inside create_database() are idempotent
# (CREATE TABLE IF NOT EXISTS, INSERT only when admin is absent),
# so existing students, votes, and admin records are never touched.

@app.before_request
def ensure_db_initialized():
    global _db_initialized
    if not _db_initialized:
        with _db_init_lock:
            if not _db_initialized:
                create_database()
                _db_initialized = True


# =========================================================
# LOGIN PROTECTION
# =========================================================

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("student_id"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect("/admin")
        return f(*args, **kwargs)
    return decorated_function


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# STUDENT REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not student_id or not name or not password:
            return "Please fill all required fields.", 400

        if len(password) < 8:
            return "Password must be at least 8 characters long.", 400

        if password != confirm_password:
            return "Passwords do not match.", 400

        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO students
                    (student_id, name, password)
                VALUES (?, ?, ?)
            """, (
                student_id,
                name,
                generate_password_hash(password)
            ))
            conn.commit()

        except sqlite3.IntegrityError:
            conn.rollback()
            return "This Student ID is already registered.", 409

        finally:
            conn.close()

        return redirect("/login")

    return render_template("register.html")


# =========================================================
# STUDENT LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            student = conn.execute("""
                SELECT id, student_id, name, password
                FROM students
                WHERE student_id = ?
            """, (student_id,)).fetchone()
        finally:
            conn.close()

        if student and check_password_hash(
            student["password"], password
        ):
            session.clear()
            session["student_id"] = student["student_id"]
            session["student_name"] = student["name"]
            return redirect("/dashboard")

        return "Invalid Student ID or Password.", 401

    return render_template("login.html")


# =========================================================
# FORGOT PASSWORD
# =========================================================
# The form must include student_id, name, new_password,
# and confirm_password fields.
# This basic identity check is not sufficient for a public
# deployment; use verified email/OTP or admin-assisted recovery.
# =========================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        name = request.form.get("name", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not student_id or not name or not new_password:
            return "Please fill all required fields.", 400

        if len(new_password) < 8:
            return "Password must be at least 8 characters long.", 400

        if new_password != confirm_password:
            return "Passwords do not match.", 400

        conn = get_db()

        try:
            student = conn.execute("""
                SELECT id
                FROM students
                WHERE student_id = ? AND name = ?
            """, (student_id, name)).fetchone()

            if student is None:
                return "Student details could not be verified.", 400

            conn.execute("""
                UPDATE students
                SET password = ?
                WHERE id = ?
            """, (
                generate_password_hash(new_password),
                student["id"]
            ))

            conn.commit()

        finally:
            conn.close()

        return redirect("/login")

    return render_template("forgot_password.html")


# =========================================================
# STUDENT DASHBOARD
# =========================================================

@app.route("/dashboard")
@student_required
def dashboard():
    conn = get_db()

    try:
        student = conn.execute("""
            SELECT student_id, name
            FROM students
            WHERE student_id = ?
        """, (session["student_id"],)).fetchone()

        if student is None:
            session.clear()
            return redirect("/login")

        existing_vote = conn.execute("""
            SELECT id
            FROM votes
            WHERE student_id = ?
            LIMIT 1
        """, (session["student_id"],)).fetchone()

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        student_name=student["name"],
        student=student,
        already_voted=existing_vote is not None
    )


# =========================================================
# SUBMIT VOTE
# =========================================================

@app.route("/vote", methods=["GET", "POST"])
@student_required
def vote():
    if request.method == "GET":
        return redirect("/dashboard")

    breakfast = request.form.get("breakfast", "").strip()
    lunch = request.form.get("lunch", "").strip()
    dinner = request.form.get("dinner", "").strip()

    if not breakfast or not lunch or not dinner:
        return "Please select all three meal preferences.", 400

    conn = get_db()

    try:
        # Check again on the server, not just in the webpage.
        existing_vote = conn.execute("""
            SELECT id
            FROM votes
            WHERE student_id = ?
            LIMIT 1
        """, (session["student_id"],)).fetchone()

        if existing_vote:
            return "You have already submitted your vote.", 409

        conn.execute("""
            INSERT INTO votes
                (breakfast, lunch, dinner, student_id)
            VALUES (?, ?, ?, ?)
        """, (
            breakfast,
            lunch,
            dinner,
            session["student_id"]
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        conn.rollback()
        return "A vote has already been submitted for this account.", 409

    finally:
        conn.close()

    return redirect("/dashboard")


# =========================================================
# RESULTS HELPER
# =========================================================

def fetch_meal_results(conn, meal):
    allowed_meals = {"breakfast", "lunch", "dinner"}

    if meal not in allowed_meals:
        raise ValueError("Invalid meal name")

    return conn.execute(f"""
        SELECT {meal}, COUNT(*) AS count
        FROM votes
        WHERE student_id IS NOT NULL
          AND {meal} IS NOT NULL
          AND TRIM({meal}) != ''
        GROUP BY {meal}
        ORDER BY count DESC
    """).fetchall()


# =========================================================
# STUDENT RESULTS
# =========================================================

@app.route("/results")
@student_required
def results():
    conn = get_db()

    try:
        total_votes = conn.execute("""
            SELECT COUNT(*)
            FROM votes
            WHERE student_id IS NOT NULL
        """).fetchone()[0]

        breakfast_results = fetch_meal_results(conn, "breakfast")
        lunch_results = fetch_meal_results(conn, "lunch")
        dinner_results = fetch_meal_results(conn, "dinner")

    finally:
        conn.close()

    return render_template(
        "results.html",
        total_votes=total_votes,
        breakfast_results=breakfast_results,
        lunch_results=lunch_results,
        dinner_results=dinner_results
    )


# =========================================================
# MENU
# =========================================================

@app.route("/menu")
@student_required
def menu():
    return render_template("menu.html")


# =========================================================
# STUDENT LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            admin = conn.execute("""
                SELECT id, username, password
                FROM admins
                WHERE username = ?
            """, (username,)).fetchone()
        finally:
            conn.close()

        if admin and check_password_hash(
            admin["password"], password
        ):
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = admin["username"]
            return redirect("/admin/dashboard")

        return "Invalid Admin Username or Password.", 401

    return render_template("admin_login.html")


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = get_db()

    try:
        total_students = conn.execute("""
            SELECT COUNT(*) FROM students
        """).fetchone()[0]

        total_votes = conn.execute("""
            SELECT COUNT(*)
            FROM votes
            WHERE student_id IS NOT NULL
        """).fetchone()[0]

        def get_admin_results(meal):
            rows = fetch_meal_results(conn, meal)
            output = []

            for row in rows:
                count = row["count"]
                percentage = (
                    round(count * 100 / total_votes, 1)
                    if total_votes else 0
                )
                output.append((row[meal], count, percentage))

            return output

        breakfast_results = get_admin_results("breakfast")
        lunch_results = get_admin_results("lunch")
        dinner_results = get_admin_results("dinner")

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        total_students=total_students,
        total_votes=total_votes,
        breakfast_results=breakfast_results,
        lunch_results=lunch_results,
        dinner_results=dinner_results
    )


# =========================================================
# ADMIN STUDENTS: SEARCH AND FILTER
# =========================================================

@app.route("/admin/students")
@admin_required
def admin_students():
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "all").strip().lower()

    if status not in ("all", "voted", "not-voted"):
        status = "all"

    query = """
        SELECT
            students.id,
            students.student_id,
            students.name,
            CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM votes
                    WHERE votes.student_id = students.student_id
                ) THEN 'Voted'
                ELSE 'Not Voted'
            END AS vote_status
        FROM students
    """

    conditions = []
    parameters = []

    if search:
        conditions.append("""
            (students.student_id LIKE ? OR students.name LIKE ?)
        """)
        value = "%" + search + "%"
        parameters.extend([value, value])

    if status == "voted":
        conditions.append("""
            EXISTS (
                SELECT 1 FROM votes
                WHERE votes.student_id = students.student_id
            )
        """)
    elif status == "not-voted":
        conditions.append("""
            NOT EXISTS (
                SELECT 1 FROM votes
                WHERE votes.student_id = students.student_id
            )
        """)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY students.id DESC"

    conn = get_db()

    try:
        students = conn.execute(query, parameters).fetchall()
    finally:
        conn.close()

    return render_template(
        "admin_students.html",
        students=students,
        search=search,
        status=status
    )


# =========================================================
# ADMIN: EDIT STUDENT
# =========================================================

@app.route(
    "/admin/student/edit/<int:student_db_id>",
    methods=["GET", "POST"]
)
@admin_required
def edit_student(student_db_id):
    conn = get_db()

    try:
        student = conn.execute("""
            SELECT id, student_id, name
            FROM students
            WHERE id = ?
        """, (student_db_id,)).fetchone()

        if student is None:
            return "Student not found.", 404

        if request.method == "POST":
            new_student_id = request.form.get(
                "student_id", ""
            ).strip()
            new_name = request.form.get("name", "").strip()

            if not new_student_id or not new_name:
                return "Please fill all fields.", 400

            try:
                conn.execute("""
                    UPDATE students
                    SET student_id = ?, name = ?
                    WHERE id = ?
                """, (
                    new_student_id,
                    new_name,
                    student_db_id
                ))

                # Preserve the link to the student's existing vote.
                conn.execute("""
                    UPDATE votes
                    SET student_id = ?
                    WHERE student_id = ?
                """, (
                    new_student_id,
                    student["student_id"]
                ))

                conn.commit()

            except sqlite3.IntegrityError:
                conn.rollback()
                return "This Student ID is already in use.", 409

            return redirect("/admin/students")

    finally:
        conn.close()

    return render_template(
        "admin_edit_student.html",
        student=student
    )


# =========================================================
# ADMIN: RESET STUDENT PASSWORD
# =========================================================

@app.route(
    "/admin/student/reset-password/<int:student_db_id>",
    methods=["GET", "POST"]
)
@admin_required
def reset_student_password(student_db_id):
    conn = get_db()

    try:
        student = conn.execute("""
            SELECT id, student_id, name
            FROM students
            WHERE id = ?
        """, (student_db_id,)).fetchone()

        if student is None:
            return "Student not found.", 404

        if request.method == "POST":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get(
                "confirm_password", ""
            )

            if not new_password or not confirm_password:
                return "Please fill all fields.", 400

            if new_password != confirm_password:
                return "Passwords do not match.", 400

            if len(new_password) < 8:
                return (
                    "Password must be at least 8 characters long.",
                    400
                )

            conn.execute("""
                UPDATE students
                SET password = ?
                WHERE id = ?
            """, (
                generate_password_hash(new_password),
                student_db_id
            ))

            conn.commit()
            return redirect("/admin/students")

    finally:
        conn.close()

    return render_template(
        "admin_reset_password.html",
        student=student
    )


# =========================================================
# ADMIN: DELETE STUDENT
# =========================================================

@app.route(
    "/admin/student/delete/<int:student_db_id>",
    methods=["POST"]
)
@admin_required
def delete_student(student_db_id):
    conn = get_db()

    try:
        student = conn.execute("""
            SELECT student_id
            FROM students
            WHERE id = ?
        """, (student_db_id,)).fetchone()

        if student is None:
            return "Student not found.", 404

        conn.execute("""
            DELETE FROM votes
            WHERE student_id = ?
        """, (student["student_id"],))

        conn.execute("""
            DELETE FROM students
            WHERE id = ?
        """, (student_db_id,))

        conn.commit()

    finally:
        conn.close()

    return redirect("/admin/students")


# =========================================================
# ADMIN LOGOUT
# =========================================================

@app.route("/admin/logout", methods=["GET", "POST"])
@admin_required
def admin_logout():
    session.clear()
    return redirect("/admin")


# =========================================================
# ADMIN: EXPORT RESULTS AS CSV
# =========================================================

@app.route("/admin/export-results")
@admin_required
def export_results():
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Meal", "Food Option", "Votes", "Percentage"
    ])

    conn = get_db()

    try:
        total_votes = conn.execute("""
            SELECT COUNT(*)
            FROM votes
            WHERE student_id IS NOT NULL
        """).fetchone()[0]

        for meal in ("breakfast", "lunch", "dinner"):
            rows = conn.execute(f"""
                SELECT {meal}, COUNT(*) AS vote_count
                FROM votes
                WHERE student_id IS NOT NULL
                  AND {meal} IS NOT NULL
                  AND TRIM({meal}) != ''
                GROUP BY {meal}
                ORDER BY vote_count DESC
            """).fetchall()

            for row in rows:
                count = row["vote_count"]
                percentage = (
                    round(count * 100 / total_votes, 2)
                    if total_votes else 0
                )

                writer.writerow([
                    meal.capitalize(),
                    row[meal],
                    count,
                    percentage
                ])

    finally:
        conn.close()

    file_data = BytesIO(
        output.getvalue().encode("utf-8-sig")
    )
    output.close()
    file_data.seek(0)

    return send_file(
        file_data,
        mimetype="text/csv",
        as_attachment=True,
        download_name="messvoice_voting_results.csv"
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    create_database()
    app.run(debug=False)