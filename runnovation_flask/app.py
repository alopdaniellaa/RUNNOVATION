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
import requests
from pathlib import Path
import json
import polyline


app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"  # change this in real deployment

# ==========================================
# STRAVA API CONFIG
# ==========================================
STRAVA_CLIENT_ID = "189419"
STRAVA_CLIENT_SECRET = "fb9eede9dc0bf4046d7683e19d2584c7488cf40c"
STRAVA_REDIRECT_URI = "http://127.0.0.1:5000/strava-callback"

# ==========================================
# DATABASE CONNECTION (MySQL)
# ==========================================
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="runnovation_db"
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

# make current_user available in templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user())

# ==========================================
# SCREEN 1: SPLASH + LANDING
# ==========================================
@app.route("/")
def splash():
    user = current_user()
    return render_template("splash.html", user=user)

@app.route("/landing")
def landing():
    user = current_user()
    return render_template("landing.html", user=user)

# ==========================================
# SCREEN 2: Register 
# ==========================================
@app.route("/register", methods=["GET", "POST"])
def register():
    strava_prefill = session.get("strava_prefill")  # dict with keys: fullname, email, athlete_id, access_token

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
            strava_athlete_id = None
            strava_connected_val = 0
            strava_access_token = None
            if strava_prefill and strava_prefill.get("athlete_id"):
                strava_athlete_id = strava_prefill.get("athlete_id")
                strava_connected_val = 1
                strava_access_token = strava_prefill.get("access_token")

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            existing = cur.fetchone()
            if existing:
                flash("Email is already registered. Please log in.", "error")
                conn.close()
                return redirect(url_for("login"))

            cur.execute(
                "INSERT INTO users (full_name, email, password_hash, strava_connected, strava_athlete_id, strava_access_token, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, NOW())",
                (full_name, email, password_hash, strava_connected_val, strava_athlete_id, strava_access_token)
            )
            conn.commit()
            new_id = cur.lastrowid

            # clear prefill
            session.pop("strava_prefill", None)
            session["user_id"] = new_id
            flash("Account created and logged in. Welcome!", "success")

            # --- Fetch and save Strava activities if connected ---
            if strava_connected_val and strava_access_token:
                user = {"id": new_id, "strava_access_token": strava_access_token}
                activities = fetch_strava_activities(user)
                if activities:
                    save_strava_routes(user, activities)

            conn.close()
            return redirect(url_for("dashboard"))
        except Error as e:
            flash("Database error while registering.", "error")
            conn.close()
            return redirect(url_for("register"))

    return render_template("register.html", strava_prefill=strava_prefill)



# ==========================================
# SCREEN 3: LOGIN
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_action = request.form.get("next", "dashboard")

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Login successful.", "success")
            # If user clicked Login & Connect Strava, send them to connect flow
            if next_action == "connect_strava":
                return redirect(url_for("connect_strava_link_existing"))
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# ==========================================
# SCREEN 4: FORGOT PASSWORD (mock)
# ==========================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        flash("If this email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")

# ==========================================
# SCREEN 5: DASHBOARD
# ==========================================
def get_top_rated_routes_with_coords(limit=5):
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT 
            r.id,
            r.name,
            r.coordinates,
            AVG(f.safety_rating) AS safety
        FROM routes r
        JOIN feedback f ON f.route_id = r.id
        WHERE r.coordinates IS NOT NULL
        GROUP BY r.id
        ORDER BY safety DESC
        LIMIT %s
    """, (limit,))

    rows = cur.fetchall()
    conn.close()

    # Convert JSON string → Python list
    import json
    for r in rows:
        r["coordinates"] = json.loads(r["coordinates"])

    return rows


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    top_routes = get_top_rated_routes_with_coords(limit=3)

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    # Count Strava-based routes
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM routes WHERE user_id = %s AND source = 'strava'",
        (user["id"],),
    )
    strava_routes_count = cur.fetchone()["cnt"]

    # Count feedback on user's routes
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
        top_routes=top_routes,
        strava_routes_count=strava_routes_count,
        feedback_count=feedback_count,
    )

# ==========================================
# STRAVA OAUTH - two distinct entry points:
# - one for registration (from register page)
# - one for login (from login page)
# ==========================================
@app.route("/connect-strava-register")
def connect_strava_register():
    # user clicked "Continue with Strava" on the REGISTER page
    session["strava_mode"] = "register"
    strava_auth_url = (
        f"https://www.strava.com/oauth/authorize?"
        f"client_id={STRAVA_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={STRAVA_REDIRECT_URI}&"
        f"approval_prompt=auto&"
        f"scope=read,activity:read"
    )
    return redirect(strava_auth_url)

@app.route("/connect-strava-login")
def connect_strava_login():
    # user clicked "Continue with Strava" on the LOGIN page
    session["strava_mode"] = "login"
    strava_auth_url = (
        f"https://www.strava.com/oauth/authorize?"
        f"client_id={STRAVA_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={STRAVA_REDIRECT_URI}&"
        f"approval_prompt=auto&"
        f"scope=read,activity:read"
    )
    return redirect(strava_auth_url)

# This route is used if a logged-in user (normal login) wants to link their account to Strava
# (the 'Login & Connect Strava' button behavior)
@app.route("/connect-strava-link-existing")
@login_required
def connect_strava_link_existing():
    # mark mode so callback knows to attach tokens / athlete id to this logged-in account
    session["strava_mode"] = "link_existing"
    strava_auth_url = (
        f"https://www.strava.com/oauth/authorize?"
        f"client_id={STRAVA_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={STRAVA_REDIRECT_URI}&"
        f"approval_prompt=auto&"
        f"scope=read,activity:read"
    )
    return redirect(strava_auth_url)

# ==========================================
# STRAVA CALLBACK
# - Does NOT auto-create accounts in 'login' mode
# - In 'register' mode redirects back to /register with prefill
# - In 'link_existing' mode attaches athlete id to current user
# ==========================================
# ==========================================
# STRAVA CALLBACK
# ==========================================
@app.route("/strava-callback")
def strava_callback():
    code = request.args.get("code")
    if not code:
        flash("Failed to connect Strava (no code).", "error")
        return redirect(url_for("landing"))

    # exchange code for token + athlete profile
    token_url = "https://www.strava.com/oauth/token"
    try:
        response = requests.post(token_url, data={
            "client_id": STRAVA_CLIENT_ID,
            "client_secret": STRAVA_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code"
        }, timeout=10)
    except Exception as e:
        flash("Failed to contact Strava.", "error")
        return redirect(url_for("landing"))

    data = response.json()
    athlete = data.get("athlete", {})
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_at = data.get("expires_at")

    athlete_id = athlete.get("id")
    firstname = athlete.get("firstname", "")
    lastname = athlete.get("lastname", "")
    fullname = (firstname + " " + lastname).strip()
    athlete_email = athlete.get("email")  # may be None

    if not athlete_id:
        flash("Failed to read Strava athlete id.", "error")
        return redirect(url_for("landing"))

    # check DB for this strava athlete id or email
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE strava_athlete_id = %s", (athlete_id,))
    user_by_athlete = cur.fetchone()

    user_by_email = None
    if athlete_email:
        cur.execute("SELECT * FROM users WHERE email = %s", (athlete_email.lower(),))
        user_by_email = cur.fetchone()

    mode = session.pop("strava_mode", None)  # 'login', 'register', or 'link_existing'

    # ------------------ REGISTER MODE ------------------
    if mode == "register":
        # prepare prefill with access token
        prefill = {
            "full_name": fullname or "",
            "email": (athlete_email.lower() if athlete_email else ""),
            "athlete_id": athlete_id,
            "access_token": access_token  # <- important
        }
        session["strava_prefill"] = prefill
        conn.close()
        flash("Continue registration to finish creating your account.", "info")
        return redirect(url_for("register"))

    # ------------------ LOGIN MODE ------------------
    # LOGIN mode sa strava-callback
    if mode == "login":
        if user_by_athlete:
        # Update DB token in case it changed
            cur.execute(
                "UPDATE users SET strava_access_token = %s WHERE id = %s",
                (access_token, user_by_athlete["id"])
            )
            conn.commit()

        # Create local user object with access token
            user = {
                "id": user_by_athlete["id"],
                "strava_access_token": access_token
            }

        # Fetch and save Strava activities
            activities = fetch_strava_activities(user)
            if activities:
                save_strava_routes(user, activities)

            session["user_id"] = user_by_athlete["id"]
            conn.close()
            flash("Logged in with Strava.", "success")
            return redirect(url_for("dashboard"))


    # ------------------ LINK EXISTING ------------------
    if mode == "link_existing":
        current = current_user()
        cur.execute(
            "UPDATE users SET strava_connected = 1, strava_athlete_id = %s, strava_access_token = %s WHERE id = %s",
            (athlete_id, access_token, current["id"])
        )
        conn.commit()

        # fetch and save Strava activities for this user
        user = {"id": current["id"], "strava_access_token": access_token}
        activities = fetch_strava_activities(user)
        if activities:
            save_strava_routes(user, activities)

        conn.close()
        flash("Strava account linked and activities saved.", "success")
        return redirect(url_for("profile"))

    conn.close()
    flash("Unknown Strava flow.", "error")
    return redirect(url_for("landing"))




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
        SELECT name, distance_km, elevation_gain, avg_pace_min_per_km
        FROM routes
        WHERE user_id = %s AND source = 'strava'
        ORDER BY created_at ASC
        """,
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()

    # Prepare chart data
    run_labels = [r["name"] for r in rows]
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
        run_labels=run_labels,
        distances=distances,
        elevations=elevations,
        paces=paces
    )

# ==========================================
# SCREEN 8: ROUTE ANALYTICS
# ==========================================
@app.route("/route-analytics")
@login_required
def route_analytics():
    import json

    user = current_user()

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    # ==================================================
    # 1️⃣ GET ALL STRAVA ROUTES (FOR CARDS + MAP)
    # ==================================================
    cur.execute("""
        SELECT *
        FROM routes
        WHERE user_id = %s
          AND source = 'strava'
          AND coordinates IS NOT NULL
        ORDER BY created_at DESC
    """, (user["id"],))

    routes = cur.fetchall()

    # Decode coordinates JSON → Python list
    for r in routes:
        r["coordinates"] = json.loads(r["coordinates"]) if r["coordinates"] else []

    # ==================================================
    # 2️⃣ GET TOP-RATED ROUTES (FOR HIGHLIGHT / MAP COLOR)
    # ==================================================
    cur.execute("""
        SELECT 
            r.id,
            r.name,
            r.coordinates,
            AVG(f.safety_rating) AS safety,
            AVG(f.difficulty_rating) AS difficulty,
            COUNT(f.id) AS review_count
        FROM routes r
        JOIN feedback f ON f.route_id = r.id
        WHERE r.coordinates IS NOT NULL
        GROUP BY r.id
        HAVING review_count > 0
        ORDER BY safety DESC
        LIMIT 5
    """)

    top_routes = cur.fetchall()

    # Decode coordinates
    for tr in top_routes:
        tr["coordinates"] = json.loads(tr["coordinates"])

    conn.close()

    return render_template(
        "route_analytics.html",
        user=user,
        routes=routes,
        top_routes=top_routes
    )





# ==========================================
# SCREEN 9: ROUTE DETAILS
# ==========================================

@app.route("/routes/<int:route_id>")
@login_required
def route_details(route_id):
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT id, name, distance_km, elevation_gain,
            avg_pace_min_per_km, difficulty, coordinates
        FROM routes
        WHERE id = %s AND user_id = %s
    """, (route_id, user["id"]))

    route = cur.fetchone()

    if not route:
        conn.close()
        flash("Route not found.", "error")
        return redirect(url_for("route_analytics"))

    # Convert JSON → Python list
    if route["coordinates"]:
        route["coordinates"] = json.loads(route["coordinates"])


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

@app.route("/route-map")
@login_required
def route_map():
    user = current_user()
    
    # Mock data example
    routes = [
        {
            "name": "Morning Run",
            "distance_km": 5.2,
            "difficulty": "Easy",
            "popularity": 80,
            "coordinates": [
                [14.5995,120.9842],
                [14.6000,120.9850],
                [14.6010,120.9860]
            ]
        },
        {
            "name": "Evening Jog",
            "distance_km": 8.0,
            "difficulty": "Medium",
            "popularity": 60,
            "coordinates": [
                [14.6020,120.9860],
                [14.6030,120.9870],
                [14.6040,120.9880]
            ]
        }
    ]

    return render_template("route_map.html", user=user, routes=routes)


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

def fetch_strava_activities(user):
    if not user["strava_access_token"]:
        return []

    headers = {
        "Authorization": f"Bearer {user['strava_access_token']}"
    }

    url = "https://www.strava.com/api/v3/athlete/activities"

    params = {
        "per_page": 30,
        "page": 1
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print("Strava API error:", response.text)
        return []

    return response.json()

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

def save_strava_routes(user, activities):
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    for act in activities:
        if act.get("type") != "Run":
            continue

        # --- Decode route polyline ---
        coordinates = None
        if act.get("map") and act["map"].get("summary_polyline"):
            decoded = polyline.decode(act["map"]["summary_polyline"])
            coordinates = json.dumps([[lat, lng] for lat, lng in decoded])

        distance_km = round(act["distance"] / 1000, 2)
        elev = int(act["total_elevation_gain"])
        moving_time = act["moving_time"]

        pace = round((moving_time / 60) / distance_km, 2) if distance_km else None

        cur.execute("""
            INSERT INTO routes
            (user_id, name, distance_km, elevation_gain,
             avg_pace_min_per_km, source, coordinates)
            VALUES (%s, %s, %s, %s, %s, 'strava', %s)
        """, (
            user["id"],
            act["name"],
            distance_km,
            elev,
            pace,
            coordinates
        ))

    conn.commit()
    conn.close()



# ==========================================
# MAIN ENTRY
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
