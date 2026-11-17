import os
import csv
import io
import sqlite3
from datetime import date, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, Response, session, send_from_directory
)

from werkzeug.security import (
    generate_password_hash, check_password_hash
)

from werkzeug.utils import secure_filename


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-this-key"
)

# Database configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.environ.get(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "jobs.db")
)

# Ensure database directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Upload configuration
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# Create database tables and update existing columns
def create_table():

    conn = get_db_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company TEXT NOT NULL,
                role TEXT NOT NULL,
                location TEXT,
                date TEXT,
                status TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        job_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(jobs)"
            ).fetchall()
        ]

        if "user_id" not in job_columns:
            conn.execute("""
                ALTER TABLE jobs
                ADD COLUMN user_id INTEGER REFERENCES users(id)
            """)

        if "interview_date" not in job_columns:
            conn.execute("""
                ALTER TABLE jobs
                ADD COLUMN interview_date TEXT
            """)

        if "interview_time" not in job_columns:
            conn.execute("""
                ALTER TABLE jobs
                ADD COLUMN interview_time TEXT
            """)

        user_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]

        if "profile_pic" not in user_columns:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN profile_pic TEXT
            """)

        conn.commit()

    finally:
        conn.close()


# IMPORTANT:
# Create the tables when this module is imported.
# This is required for Render/Gunicorn.
create_table()


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return "Please fill in all fields."

        if len(password) < 8:
            return "Password must contain at least 8 characters."

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        try:
            existing_user = conn.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing_user:
                return "This email is already registered."

            user_count = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

            cursor = conn.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, hashed_password)
            )

            new_user_id = cursor.lastrowid

            if user_count == 0:
                conn.execute(
                    "UPDATE jobs SET user_id = ? WHERE user_id IS NULL",
                    (new_user_id,)
                )

            conn.commit()

        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(user["password"], password):

            session.clear()

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            return redirect(url_for("home"))

        return "Invalid email or password. Please try again."

    return render_template("login.html")


# Forgot password
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        conn = get_db_connection()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()
        finally:
            conn.close()

        if user:
            session["reset_email"] = email
            return redirect(url_for("reset_password"))

        return "Email address not found."

    return render_template("forgot_password.html")


# Reset password
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():

    if "reset_email" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            return "Passwords do not match."

        if len(password) < 8:
            return "Password must contain at least 8 characters."

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        try:
            conn.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (hashed_password, session["reset_email"])
            )

            conn.commit()

        finally:
            conn.close()

        session.pop("reset_email", None)

        return redirect(url_for("login"))

    return render_template("reset_password.html")


# User profile
@app.route("/profile", methods=["GET", "POST"])
def profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        if request.method == "POST":

            name = request.form.get("name", "").strip()

            if not name:
                return "Name cannot be empty."

            profile_pic = request.files.get("profile_pic")

            conn.execute(
                "UPDATE users SET name = ? WHERE id = ?",
                (name, session["user_id"])
            )

            session["user_name"] = name

            if profile_pic and profile_pic.filename:

                if not allowed_file(profile_pic.filename):
                    return "Please upload a valid image file."

                filename = secure_filename(profile_pic.filename)

                filename = f"user_{session['user_id']}_{filename}"

                profile_pic.save(
                    os.path.join(app.config["UPLOAD_FOLDER"], filename)
                )

                conn.execute(
                    "UPDATE users SET profile_pic = ? WHERE id = ?",
                    (filename, session["user_id"])
                )

            conn.commit()

        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    finally:
        conn.close()

    return render_template("profile.html", user=user)


# Display uploaded profile photos
@app.route("/uploads/<filename>")
def uploaded_file(filename):

    if "user_id" not in session:
        return redirect(url_for("login"))

    expected_prefix = f"user_{session['user_id']}_"

    if not filename.startswith(expected_prefix):
        return "File not found.", 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )


# Change password
@app.route("/change_password", methods=["POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    conn = get_db_connection()

    try:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not user or not check_password_hash(
            user["password"], current_password
        ):
            return "Current password is incorrect."

        if new_password != confirm_password:
            return "New passwords do not match."

        if len(new_password) < 8:
            return "New password must contain at least 8 characters."

        hashed_password = generate_password_hash(new_password)

        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed_password, session["user_id"])
        )

        conn.commit()

    finally:
        conn.close()

    return redirect(url_for("profile"))


# Logout
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# Dashboard
@app.route("/")
def home():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        jobs = conn.execute(
            """
            SELECT * FROM jobs
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],)
        ).fetchall()

        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    finally:
        conn.close()

    today = date.today()
    tomorrow = today + timedelta(days=1)

    upcoming_interviews = []
    tomorrow_interviews = []

    for job in jobs:

        interview_date = job["interview_date"]

        if interview_date:

            try:
                interview_day = date.fromisoformat(interview_date)

                if interview_day >= today:

                    days_left = (interview_day - today).days

                    interview_card = dict(job)
                    interview_card["days_left"] = days_left

                    upcoming_interviews.append(interview_card)

                if interview_day == tomorrow:
                    tomorrow_interviews.append(job)

            except ValueError:
                pass

    total_applications = len(jobs)

    applied = sum(1 for job in jobs if job["status"] == "Applied")
    interviews = sum(1 for job in jobs if job["status"] == "Interview")
    selected = sum(1 for job in jobs if job["status"] == "Selected")
    rejected = sum(1 for job in jobs if job["status"] == "Rejected")
    pending = sum(1 for job in jobs if job["status"] == "Pending")

    success_rate = 0

    if total_applications > 0:
        success_rate = (selected / total_applications) * 100

    return render_template(
        "index.html",
        user=user,
        jobs=jobs,
        user_name=session.get("user_name"),
        total_applications=total_applications,
        applied=applied,
        interviews=interviews,
        selected=selected,
        rejected=rejected,
        pending=pending,
        success_rate=success_rate,
        upcoming_interviews=upcoming_interviews,
        tomorrow_interviews=tomorrow_interviews
    )


# Add job
@app.route("/add", methods=["GET", "POST"])
def add_job():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        company = request.form.get("company")
        role = request.form.get("role")
        location = request.form.get("location")
        job_date = request.form.get("date")
        interview_date = request.form.get("interview_date")
        interview_time = request.form.get("interview_time")
        status = request.form.get("status")

        conn = get_db_connection()

        try:
            conn.execute(
                """
                INSERT INTO jobs
                (
                    company, role, location, date,
                    interview_date, interview_time, status, user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    company,
                    role,
                    location,
                    job_date,
                    interview_date,
                    interview_time,
                    status,
                    session["user_id"]
                )
            )

            conn.commit()

        finally:
            conn.close()

        return redirect(url_for("home"))

    return render_template("add_job.html")


# View job
@app.route("/view/<int:id>")
def view_job(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        job = conn.execute(
            """
            SELECT * FROM jobs
            WHERE id = ? AND user_id = ?
            """,
            (id, session["user_id"])
        ).fetchone()

    finally:
        conn.close()

    if job is None:
        return "Job not found.", 404

    return render_template("view_job.html", job=job)


# Update job status
@app.route("/update_status/<int:id>", methods=["POST"])
def update_status(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    status = request.form.get("status")

    conn = get_db_connection()

    try:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?
            WHERE id = ? AND user_id = ?
            """,
            (status, id, session["user_id"])
        )

        conn.commit()

    finally:
        conn.close()

    return redirect(url_for("view_job", id=id))


# Edit job
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_job(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        job = conn.execute(
            """
            SELECT * FROM jobs
            WHERE id = ? AND user_id = ?
            """,
            (id, session["user_id"])
        ).fetchone()

        if job is None:
            return "Job not found.", 404

        if request.method == "POST":

            company = request.form.get("company")
            role = request.form.get("role")
            location = request.form.get("location")
            job_date = request.form.get("date")
            interview_date = request.form.get("interview_date")
            interview_time = request.form.get("interview_time")
            status = request.form.get("status")

            conn.execute(
                """
                UPDATE jobs
                SET company = ?,
                    role = ?,
                    location = ?,
                    date = ?,
                    interview_date = ?,
                    interview_time = ?,
                    status = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    company,
                    role,
                    location,
                    job_date,
                    interview_date,
                    interview_time,
                    status,
                    id,
                    session["user_id"]
                )
            )

            conn.commit()

            return redirect(url_for("home"))

    finally:
        conn.close()

    return render_template("edit_job.html", job=job)


# Delete job
@app.route("/delete/<int:id>", methods=["POST"])
def delete_job(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        conn.execute(
            """
            DELETE FROM jobs
            WHERE id = ? AND user_id = ?
            """,
            (id, session["user_id"])
        )

        conn.commit()

    finally:
        conn.close()

    return redirect(url_for("home"))


# Export jobs to CSV
@app.route("/export")
def export_jobs():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        jobs = conn.execute(
            """
            SELECT company, role, location, date,
                   interview_date, interview_time, status
            FROM jobs
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],)
        ).fetchall()

    finally:
        conn.close()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Company",
        "Job Role",
        "Location",
        "Application Date",
        "Interview Date",
        "Interview Time",
        "Status"
    ])

    for job in jobs:

        writer.writerow([
            job["company"],
            job["role"],
            job["location"],
            job["date"],
            job["interview_date"],
            job["interview_time"],
            job["status"]
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=job_applications.csv"
    )

    return response


# Calendar View
@app.route("/calendar")
def calendar():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    try:
        jobs = conn.execute(
            """
            SELECT id, company, role, date,
                   interview_date, interview_time, status
            FROM jobs
            WHERE user_id = ?
            ORDER BY
                CASE
                    WHEN interview_date IS NULL OR interview_date = ''
                    THEN date
                    ELSE interview_date
                END
            """,
            (session["user_id"],)
        ).fetchall()

    finally:
        conn.close()

    return render_template("calendar.html", jobs=jobs)


# Run application locally
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )