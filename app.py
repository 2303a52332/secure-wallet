import os
import io
import hashlib

from datetime import timezone, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from cryptography.fernet import (
    Fernet,
    InvalidToken
)

from models import (
    db,
    User,
    SecureFile,
    ActivityLog
)


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "secure-wallet-development-key"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///secure_wallet.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ==========================================
# DATABASE
# ==========================================

db.init_app(app)


# ==========================================
# LOGIN MANAGER
# ==========================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


# ==========================================
# ACTIVITY LOG FUNCTION
# ==========================================

def log_activity(action, user_id):

    activity = ActivityLog(
        action=action,
        user_id=user_id
    )

    db.session.add(activity)
    db.session.commit()


# ==========================================
# ENCRYPTION KEY
# ==========================================

KEY_FILE = "secret.key"


if not os.path.exists(KEY_FILE):

    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as key_file:

        key_file.write(key)


with open(KEY_FILE, "rb") as key_file:

    encryption_key = key_file.read()


fernet = Fernet(encryption_key)


# ==========================================
# STORAGE
# ==========================================

STORAGE_FOLDER = "storage"

os.makedirs(
    STORAGE_FOLDER,
    exist_ok=True
)


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================
# REGISTER
# ==========================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        # Get form data safely
        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # --------------------------------------
        # Empty field validation
        # --------------------------------------

        if not username or not email or not password:

            flash(
                "Please fill in all fields."
            )

            return render_template(
                "register.html"
            )

        # --------------------------------------
        # Password confirmation
        # --------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match."
            )

            return render_template(
                "register.html"
            )

        # --------------------------------------
        # Username validation
        # --------------------------------------

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            flash(
                "Username already exists."
            )

            return render_template(
                "register.html"
            )

        # --------------------------------------
        # Email validation
        # --------------------------------------

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Email already registered."
            )

            return render_template(
                "register.html"
            )

        # --------------------------------------
        # Hash password
        # --------------------------------------

        password_hash = generate_password_hash(
            password
        )

        # --------------------------------------
        # Create user
        # --------------------------------------

        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)

        db.session.commit()

        # --------------------------------------
        # Success message
        # --------------------------------------

        flash(
            "Account created successfully. "
            "Please log in."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        # --------------------------------------
        # Get login information
        # --------------------------------------

        identifier = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        # --------------------------------------
        # Normalize email
        # --------------------------------------

        email_identifier = identifier.lower()

        # --------------------------------------
        # First try email
        # --------------------------------------

        user = User.query.filter_by(
            email=email_identifier
        ).first()

        # --------------------------------------
        # If email doesn't exist,
        # try username
        # --------------------------------------

        if not user:

            user = User.query.filter_by(
                username=identifier
            ).first()

        # --------------------------------------
        # Verify password
        # --------------------------------------

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            # Create login session
            login_user(user)

            # Record activity
            log_activity(
                "User logged in",
                user.id
            )

            # Redirect to dashboard
            return redirect(
                url_for("dashboard")
            )

        # --------------------------------------
        # Login failed
        # --------------------------------------

        flash(
            "Invalid email/username or password."
        )

    return render_template(
        "login.html"
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        username=current_user.username
    )


# ==========================================
# UPLOAD FILE
# ==========================================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
@login_required
def upload():

    if request.method == "POST":

        # --------------------------------------
        # Get uploaded file
        # --------------------------------------

        file = request.files.get("file")

        if not file or file.filename == "":

            flash(
                "Please select a file."
            )

            return render_template(
                "upload.html"
            )

        # --------------------------------------
        # Secure filename
        # --------------------------------------

        original_filename = secure_filename(
            file.filename
        )

        # --------------------------------------
        # Read file
        # --------------------------------------

        file_data = file.read()

        # --------------------------------------
        # SHA-256 hash
        # --------------------------------------

        file_hash = hashlib.sha256(
            file_data
        ).hexdigest()

        # --------------------------------------
        # Encrypt file
        # --------------------------------------

        encrypted_data = fernet.encrypt(
            file_data
        )

        # --------------------------------------
        # Create encrypted filename
        # --------------------------------------

        encrypted_filename = (
            str(current_user.id)
            + "_"
            + original_filename
            + ".encrypted"
        )

        encrypted_path = os.path.join(
            STORAGE_FOLDER,
            encrypted_filename
        )

        # --------------------------------------
        # Save encrypted file
        # --------------------------------------

        with open(
            encrypted_path,
            "wb"
        ) as encrypted_file:

            encrypted_file.write(
                encrypted_data
            )

        # --------------------------------------
        # Save file information to database
        # --------------------------------------

        secure_file = SecureFile(

            original_filename=original_filename,

            encrypted_filename=encrypted_filename,

            file_hash=file_hash,

            user_id=current_user.id

        )

        db.session.add(
            secure_file
        )

        db.session.commit()

        # --------------------------------------
        # Activity log
        # --------------------------------------

        log_activity(
            "Uploaded file: "
            + original_filename,
            current_user.id
        )

        flash(
            "File encrypted and uploaded successfully!"
        )

        return redirect(
            url_for("my_files")
        )

    return render_template(
        "upload.html"
    )


# ==========================================
# MY FILES
# ==========================================

@app.route("/my-files")
@login_required
def my_files():

    files = SecureFile.query.filter_by(

        user_id=current_user.id

    ).order_by(

        SecureFile.uploaded_at.desc()

    ).all()

    return render_template(
        "my_files.html",
        files=files
    )


# ==========================================
# DOWNLOAD + DECRYPT
# ==========================================

@app.route(
    "/download/<int:file_id>"
)
@login_required
def download_file(file_id):

    # --------------------------------------
    # Find file belonging to current user
    # --------------------------------------

    secure_file = SecureFile.query.filter_by(

        id=file_id,

        user_id=current_user.id

    ).first()

    if not secure_file:

        flash(
            "File not found or access denied."
        )

        return redirect(
            url_for("my_files")
        )

    # --------------------------------------
    # Encrypted file path
    # --------------------------------------

    encrypted_path = os.path.join(

        STORAGE_FOLDER,

        secure_file.encrypted_filename

    )

    if not os.path.exists(
        encrypted_path
    ):

        flash(
            "Encrypted file not found."
        )

        return redirect(
            url_for("my_files")
        )

    # --------------------------------------
    # Decrypt
    # --------------------------------------

    try:

        with open(
            encrypted_path,
            "rb"
        ) as encrypted_file:

            encrypted_data = (
                encrypted_file.read()
            )

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except InvalidToken:

        flash(
            "Security error: File may have "
            "been modified or corrupted."
        )

        return redirect(
            url_for("my_files")
        )

    # --------------------------------------
    # SHA-256 integrity verification
    # --------------------------------------

    current_hash = hashlib.sha256(
        decrypted_data
    ).hexdigest()

    if current_hash != secure_file.file_hash:

        flash(
            "Integrity check failed. "
            "File may have been tampered with."
        )

        return redirect(
            url_for("my_files")
        )

    # --------------------------------------
    # Activity log
    # --------------------------------------

    log_activity(
        "Downloaded file: "
        + secure_file.original_filename,
        current_user.id
    )

    # --------------------------------------
    # Send decrypted file
    # --------------------------------------

    return send_file(

        io.BytesIO(
            decrypted_data
        ),

        as_attachment=True,

        download_name=(
            secure_file.original_filename
        )

    )


# ==========================================
# ACTIVITY LOGS
# ==========================================

@app.route("/activity-logs")
@login_required
def activity_logs():

    logs = ActivityLog.query.filter_by(

        user_id=current_user.id

    ).order_by(

        ActivityLog.timestamp.desc()

    ).all()

    # --------------------------------------
    # India Standard Time
    # UTC + 5:30
    # --------------------------------------

    ist = timezone(
        timedelta(
            hours=5,
            minutes=30
        )
    )

    for log in logs:

        if log.timestamp:

            log.timestamp = log.timestamp.replace(

                tzinfo=timezone.utc

            ).astimezone(
                ist
            )

    return render_template(
        "activity_logs.html",
        logs=logs
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
@login_required
def logout():

    user_id = current_user.id

    # --------------------------------------
    # Record logout activity
    # --------------------------------------

    log_activity(
        "User logged out",
        user_id
    )

    # --------------------------------------
    # Logout
    # --------------------------------------

    logout_user()

    return redirect(
        url_for("login")
    )


# ==========================================
# CREATE DATABASE TABLES
# ==========================================

with app.app_context():

    db.create_all()


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )