from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from models_outdated import db, User
import os
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_to="auth.google_login"
)

# Register the Google OAuth blueprint
auth_bp.register_blueprint(google_bp, url_prefix="/login")

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for("auth.register"))
        new_user = User(
            username=username,
            password=generate_password_hash(password, method="pbkdf2:sha256"),
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("tts.index"))  # Change 'index' to 'tts.index'
    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("tts.index"))  # Change 'index' to 'tts.index'
        else:
            flash("Invalid credentials.")
    return render_template("login.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth_bp.route("/login/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch user information from Google.")
        return redirect(url_for("auth.login"))

    user_info = resp.json()
    user = User.query.filter_by(email=user_info["email"]).first()

    if user is None:
        # Create a new user using the UserCreate schema
        new_user = User(
            username=user_info["email"],  # Use email as the username or customize as needed
            email=user_info["email"],
            password=generate_password_hash("default_password", method="pbkdf2:sha256"),  # Set a default password; it won't be used
            profile_pic=user_info.get("picture"),  # Optional: Add the profile picture if you store it
            role="REGULAR",  # Assuming OAuth users have a regular role by default
        )
        db.session.add(user)
        db.session.commit()

    return user