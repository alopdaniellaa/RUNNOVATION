from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import mysql.connector
from mysql.connector import Error
from pathlib import Path

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"  # change this in real deployment


# ==========================================
# DATABASE CONNECTION (MySQL)
# ==========================================

def get_db():
    """
    Returns a new MySQL connection.
    Adjust host/user/password if you changed them in XAMPP.
    """
    return mysql.connector.connect(
        host="localhost",
        user="root",        # default for XAMPP
        password="",        # default: empty
        database="runnovation_db",
    )


# ==========================================
# HELPERS
# ==========================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()
    conn.close()
    return user

# ==========================================
# SCREEN 1: SPLASH + LANDING PAGES
# ==========================================

@app.route("/")
def splash():
    # Fullscreen splash, auto-redirects to landing page
    user = current_user()
    return render_template("splash.html", user=user)


@app.route("/landing")
def landing():
    # Actual landing / hero screen (no auto-redirect)
    user = current_user()
    return render_template("landing.html", user=user)


# ==========================================
# SCREEN 2: REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not full_name or not email or not password or not confirm:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(
                "INSERT INTO users (full_name, email, password_hash) VALUES (%s, %s, %s)",
                (full_name, email, password_hash),
            )
            conn.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))
        except Error as e:
            msg = str(e)
            if "Duplicate entry" in msg and "for key 'email'" in msg:
                flash("Email is already registered.", "error")
            else:
                flash("Database error while registering.", "error")
        finally:
            conn.close()

    return render_template("register.html")


# ==========================================
# SCREEN 3: LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_action = request.form.get("next", "dashboard")  # dashboard or connect_strava

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Login successful.", "success")

            if next_action == "connect_strava":
                return redirect(url_for("connect_strava"))
            else:
                return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    # GET request
    return render_template("login.html")


# ==========================================
# SCREEN 4: FORGOT PASSWORD (mock)
# ==========================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        # In a real system you would send an email here.
        flash("If this email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


# ==========================================
# SCREEN 5: DASHBOARD
# ==========================================

def get_top_rated_routes():
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT 
            r.id,
            r.name,
            AVG(f.difficulty_rating) AS avg_diff,
            AVG(f.safety_rating) AS avg_safety,
            COUNT(f.id) AS review_count
        FROM routes r
        LEFT JOIN feedback f ON f.route_id = r.id
        GROUP BY r.id
        HAVING review_count > 0
        ORDER BY avg_diff DESC, avg_safety DESC
        LIMIT 3;
    """)
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    top_routes = get_top_rated_routes()
    return render_template("dashboard.html", user=user, top_routes=top_routes)


    # Count Strava-based routes for this user
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM routes WHERE user_id = %s AND source = 'strava'",
        (user["id"],),
    )
    strava_routes_count = cur.fetchone()["cnt"]

    # Count feedback on this user's routes
    cur.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM feedback f
        JOIN routes r ON f.route_id = r.id
        WHERE r.user_id = %s
        """,
        (user["id"],),
    )
    feedback_count = cur.fetchone()["cnt"]

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        strava_routes_count=strava_routes_count,
        feedback_count=feedback_count,
    )


# ==========================================
# SCREEN 6: CONNECT STRAVA (demo)
# ==========================================

@app.route("/connect-strava", methods=["GET", "POST"])
@login_required
def connect_strava():
    user = current_user()

    if request.method == "POST":
        # Demo only: mark as connected.
        # Real app: perform OAuth and import Strava data into routes table.
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "UPDATE users SET strava_connected = 1 WHERE id = %s", (user["id"],)
        )
        conn.commit()
        conn.close()

        flash("Your Strava data has been synced successfully. (Demo)", "success")
        return redirect(url_for("dashboard"))

    return render_template("connect_strava.html", user=user)


# ==========================================
# SCREEN 7: STRAVA ANALYTICS
# ==========================================

@app.route("/strava-analytics")
@login_required
def strava_analytics():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT distance_km, elevation_gain, avg_pace_min_per_km
        FROM routes
        WHERE user_id = %s AND source = 'strava'
        """,
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    distances = [float(r["distance_km"]) for r in rows]
    elevations = [int(r["elevation_gain"]) for r in rows]
    paces = [float(r["avg_pace_min_per_km"]) for r in rows if r["avg_pace_min_per_km"] is not None]

    total_distance = sum(distances) if distances else 0
    avg_pace = (sum(paces) / len(paces)) if paces else 0
    avg_elev = (sum(elevations) / len(elevations)) if elevations else 0
    run_count = len(rows)

    return render_template(
        "strava_analytics.html",
        user=user,
        total_distance=total_distance,
        avg_pace=avg_pace,
        avg_elev=avg_elev,
        run_count=run_count,
    )


# ==========================================
# SCREEN 8: ROUTE ANALYTICS
# ==========================================

@app.route("/route-analytics")
@login_required
def route_analytics():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT *
        FROM routes
        WHERE user_id = %s AND source = 'strava'
        ORDER BY popularity DESC
        """,
        (user["id"],),
    )
    routes = cur.fetchall()
    conn.close()

    return render_template("route_analytics.html", user=user, routes=routes)


# ==========================================
# SCREEN 9: ROUTE DETAILS
# ==========================================

@app.route("/routes/<int:route_id>")
@login_required
def route_details(route_id):
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT *
        FROM routes
        WHERE id = %s AND user_id = %s AND source = 'strava'
        """,
        (route_id, user["id"]),
    )
    route = cur.fetchone()
    if not route:
        conn.close()
        flash("Route not found.", "error")
        return redirect(url_for("route_analytics"))

    cur.execute(
        """
        SELECT
            AVG(difficulty_rating) AS avg_diff,
            AVG(safety_rating) AS avg_safety,
            COUNT(*) AS feedback_count
        FROM feedback
        WHERE route_id = %s
        """,
        (route_id,),
    )
    agg = cur.fetchone()

    cur.execute(
        """
        SELECT f.*, u.full_name
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        WHERE f.route_id = %s
        ORDER BY f.created_at DESC
        """,
        (route_id,),
    )
    comments = cur.fetchall()

    conn.close()

    return render_template(
        "route_details.html",
        user=user,
        route=route,
        agg=agg,
        comments=comments,
    )


# ==========================================
# SCREEN 10: SUBMIT FEEDBACK
# ==========================================

@app.route("/routes/<int:route_id>/feedback", methods=["GET", "POST"])
@login_required
def submit_feedback(route_id):
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM routes WHERE id = %s AND source = 'strava'", (route_id,))
    route = cur.fetchone()
    if not route:
        conn.close()
        flash("Route not found.", "error")
        return redirect(url_for("route_analytics"))

    if request.method == "POST":
        try:
            difficulty_rating = int(request.form.get("difficulty_rating", 0))
            safety_rating = int(request.form.get("safety_rating", 0))
        except ValueError:
            difficulty_rating = 0
            safety_rating = 0

        comment = request.form.get("comment", "").strip()

        if not (1 <= difficulty_rating <= 5) or not (1 <= safety_rating <= 5):
            flash("Ratings must be between 1 and 5.", "error")
            conn.close()
            return redirect(url_for("submit_feedback", route_id=route_id))

        cur.execute(
            """
            INSERT INTO feedback (user_id, route_id, difficulty_rating, safety_rating, comment)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user["id"], route_id, difficulty_rating, safety_rating, comment),
        )
        conn.commit()
        conn.close()

        flash("Feedback submitted. Thank you!", "success")
        return redirect(url_for("route_details", route_id=route_id))

    conn.close()
    return render_template("submit_feedback.html", user=user, route=route)


# ==========================================
# SCREEN 11: COMMUNITY INSIGHTS
# ==========================================

@app.route("/community-insights")
@login_required
def community_insights():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT
            r.name,
            AVG(f.difficulty_rating) AS avg_diff,
            AVG(f.safety_rating) AS avg_safety,
            COUNT(*) AS count
        FROM feedback f
        JOIN routes r ON f.route_id = r.id
        WHERE r.user_id = %s
        GROUP BY r.id
        ORDER BY avg_safety DESC
        """,
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    return render_template("community_insights.html", user=user, rows=rows)


# ==========================================
# SCREEN 12: PROFILE
# ==========================================

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_profile":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            if not full_name or not email:
                flash("Name and email are required.", "error")
            else:
                try:
                    cur.execute(
                        "UPDATE users SET full_name = %s, email = %s WHERE id = %s",
                        (full_name, email, user["id"]),
                    )
                    conn.commit()
                    flash("Profile updated.", "success")
                except Error as e:
                    if "Duplicate entry" in str(e):
                        flash("Email already in use.", "error")
                    else:
                        flash("Error updating profile.", "error")

        elif action == "change_password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            # refresh user for password check
            cur.execute("SELECT * FROM users WHERE id = %s", (user["id"],))
            fresh_user = cur.fetchone()

            if not check_password_hash(fresh_user["password_hash"], current_pw):
                flash("Current password is incorrect.", "error")
            elif new_pw != confirm_pw:
                flash("New passwords do not match.", "error")
            elif not new_pw:
                flash("New password cannot be empty.", "error")
            else:
                new_hash = generate_password_hash(new_pw)
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s",
                    (new_hash, user["id"]),
                )
                conn.commit()
                flash("Password changed successfully.", "success")

        elif action == "disconnect_strava":
            cur.execute(
                "UPDATE users SET strava_connected = 0, strava_athlete_id = NULL WHERE id = %s",
                (user["id"],),
            )
            conn.commit()
            flash("Strava disconnected.", "success")

    # reload user data
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    updated_user = cur.fetchone()
    conn.close()

    return render_template("profile.html", user=updated_user)


# ==========================================
# SCREEN 13: DELETE ACCOUNT
# ==========================================

@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    user = current_user()
    if request.method == "POST":
        confirm = request.form.get("confirm", "")
        if confirm == "DELETE":
            conn = get_db()
            cur = conn.cursor(dictionary=True)
            cur.execute("DELETE FROM users WHERE id = %s", (user["id"],))
            conn.commit()
            conn.close()
            session.clear()
            flash("Your account and associated data have been deleted.", "success")
            return redirect(url_for("landing"))
        else:
            flash('Type "DELETE" to confirm.', "error")

    return render_template("delete_account.html", user=user)


# ==========================================
# SCREEN 15: ABOUT / HELP
# ==========================================

@app.route("/about")
def about():
    user = current_user()
    return render_template("about.html", user=user)


# ==========================================
# OPTIONAL: SIMPLE API FOR DEBUGGING
# ==========================================

@app.route("/api/routes")
@login_required
def api_routes():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM routes WHERE user_id = %s AND source = 'strava'",
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))



# ==========================================
# MAIN ENTRY
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
