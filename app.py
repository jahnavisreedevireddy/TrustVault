import os
import io
import json
import hashlib
import secrets
import zipfile
import smtplib
import ssl
import logging

from email.message import EmailMessage
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    abort
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename


# =====================================
# 1. FLASK CONFIGURATION
# =====================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-development-secret"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable this only when using HTTPS.
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("TRUSTVAULT_HTTPS", "0") == "1"
)

app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = (
    os.environ.get("TRUSTVAULT_HTTPS", "0") == "1"
)

if app.config["SECRET_KEY"] == "change-this-development-secret":
    app.logger.warning(
        "Using the development SECRET_KEY. "
        "Set a private SECRET_KEY before deployment."
    )

BASE_DIR = Path(__file__).resolve().parent

UPLOAD_FOLDER = BASE_DIR / "private_uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "png",
    "jpg",
    "jpeg",
    "docx"
}

VALID_ROLES = ["Admin", "Owner", "Viewer"]

PASSWORD_RESET_MAX_AGE = 30 * 60
RESET_TOKEN_SALT = "trustvault-password-reset-v1"

# For local testing, the reset link is printed in the terminal.
# Set TRUSTVAULT_SHOW_RESET_LINK=0 in production.
SHOW_RESET_LINK_IN_TERMINAL = (
    os.environ.get("TRUSTVAULT_SHOW_RESET_LINK", "0") == "1"
)


# =====================================
# 2. INITIALIZE EXTENSIONS
# =====================================

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

csrf = CSRFProtect(app)


# =====================================
# 3. PASSWORD SECURITY
# =====================================

def strong_password(password):

    if not isinstance(password, str):
        return False

    if len(password) < 8 or len(password) > 128:
        return False

    return (
        any(char.isupper() for char in password)
        and any(char.islower() for char in password)
        and any(char.isdigit() for char in password)
        and any(not char.isalnum() for char in password)
    )


def password_reset_serializer():

    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt=RESET_TOKEN_SALT
    )


# =====================================
# 4. SEND PASSWORD RESET EMAIL
# =====================================

def send_password_reset_email(user, reset_url):

    if SHOW_RESET_LINK_IN_TERMINAL:

        print(
            "\n========== TRUSTVAULT PASSWORD RESET LINK ==========",
            flush=True
        )

        print(reset_url, flush=True)

        print(
            "=====================================================\n",
            flush=True
        )

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))

    smtp_from = os.environ.get(
        "SMTP_FROM",
        smtp_user or ""
    )

    if not all([
        smtp_host,
        smtp_user,
        smtp_password,
        smtp_from
    ]):
        app.logger.warning(
            "SMTP is not configured. Password reset email was not sent."
        )
        return False

    message = EmailMessage()

    message["Subject"] = "TrustVault Password Reset"
    message["From"] = smtp_from
    message["To"] = user.email

    message.set_content(
        "Hello " + user.username + ",\n\n"
        "Use the link below to reset your TrustVault password. "
        "The link expires in 30 minutes and can only be used once.\n\n"
        + reset_url
        + "\n\nIf you did not request this, ignore this email."
    )

    context = ssl.create_default_context()

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
        timeout=20
    ) as server:

        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

        server.login(
            smtp_user,
            smtp_password
        )

        server.send_message(message)

    return True


# =====================================
# 5. REQUEST DEBUGGING
# =====================================

@app.before_request
def show_request():

    print(
        "\nREQUEST RECEIVED:",
        request.method,
        request.path,
        flush=True
    )


# =====================================
# 6. UTC TIME FUNCTION
# =====================================

def utc_now():

    return datetime.now(
        timezone.utc
    ).replace(tzinfo=None)


# =====================================
# 7. DATABASE MODELS
# =====================================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="Viewer"
    )


class Document(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(150),
        nullable=False
    )

    description = db.Column(
        db.Text
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    original_name = db.Column(
        db.String(255),
        nullable=False
    )

    file_hash = db.Column(
        db.String(64),
        nullable=False
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=utc_now
    )


class Permission(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    can_edit = db.Column(
        db.Boolean,
        default=False
    )


class AuditLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    actor_id = db.Column(
        db.Integer,
        nullable=False
    )

    document_id = db.Column(
        db.Integer,
        nullable=True
    )

    action = db.Column(
        db.String(100),
        nullable=False
    )

    previous_hash = db.Column(
        db.String(64)
    )

    entry_hash = db.Column(
        db.String(64),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=utc_now
    )

    # 0 = legacy record
    # 1 = new verifiable record

    hash_version = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    hash_timestamp = db.Column(
        db.String(40),
        nullable=True
    )


# =====================================
# 8. USER LOADER
# =====================================

@login_manager.user_loader
def load_user(user_id):

    try:
        return db.session.get(
            User,
            int(user_id)
        )

    except (ValueError, TypeError):
        return None


# =====================================
# 9. AUDIT HASH FUNCTION
# =====================================

def make_audit_hash(
    actor_id,
    document_id,
    action,
    previous_hash,
    timestamp
):

    content = json.dumps(
        {
            "actor_id": actor_id,
            "document_id": document_id,
            "action": action,
            "previous_hash": previous_hash,
            "timestamp": timestamp
        },
        sort_keys=True
    )

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


# =====================================
# 10. AUDIT CHAIN VERIFICATION
# =====================================

def audit_chain_status():

    logs = AuditLog.query.order_by(
        AuditLog.id.asc()
    ).all()

    expected_previous = "GENESIS"

    legacy_count = 0
    verified_count = 0

    for log in logs:

        if log.previous_hash != expected_previous:

            return {
                "chain_ok": False,
                "fully_verified": False,
                "legacy_count": legacy_count,
                "verified_count": verified_count,
                "message": (
                    "Audit chain linkage error at record "
                    + str(log.id)
                )
            }

        if not log.entry_hash:

            return {
                "chain_ok": False,
                "fully_verified": False,
                "legacy_count": legacy_count,
                "verified_count": verified_count,
                "message": (
                    "Missing entry hash at record "
                    + str(log.id)
                )
            }

        version = log.hash_version or 0

        if version == 0:

            legacy_count += 1

        elif version == 1:

            if not log.hash_timestamp:

                return {
                    "chain_ok": False,
                    "fully_verified": False,
                    "legacy_count": legacy_count,
                    "verified_count": verified_count,
                    "message": (
                        "Missing hash timestamp at record "
                        + str(log.id)
                    )
                }

            calculated_hash = make_audit_hash(
                log.actor_id,
                log.document_id,
                log.action,
                log.previous_hash,
                log.hash_timestamp
            )

            if calculated_hash != log.entry_hash:

                return {
                    "chain_ok": False,
                    "fully_verified": False,
                    "legacy_count": legacy_count,
                    "verified_count": verified_count,
                    "message": (
                        "Entry hash mismatch at record "
                        + str(log.id)
                    )
                }

            verified_count += 1

        else:

            return {
                "chain_ok": False,
                "fully_verified": False,
                "legacy_count": legacy_count,
                "verified_count": verified_count,
                "message": (
                    "Unknown hash version at record "
                    + str(log.id)
                )
            }

        expected_previous = log.entry_hash

    if legacy_count > 0:

        message = (
            str(legacy_count)
            + " legacy record(s) cannot be independently verified. "
            + str(verified_count)
            + " new record(s) verified. "
            + "Chain links are intact."
        )

    else:

        message = (
            "All "
            + str(verified_count)
            + " audit records verified successfully."
        )

    return {
        "chain_ok": True,
        "fully_verified": legacy_count == 0,
        "legacy_count": legacy_count,
        "verified_count": verified_count,
        "message": message
    }


# =====================================
# 11. VERIFY AUDIT CHAIN
# =====================================

def verify_audit_chain():

    print(
        "\n========== AUDIT VERIFICATION STARTED ==========",
        flush=True
    )

    try:

        result = audit_chain_status()

        print(
            "Audit verification result:",
            result["message"],
            flush=True
        )

        print(
            "Legacy records:",
            result["legacy_count"],
            flush=True
        )

        print(
            "Verified new records:",
            result["verified_count"],
            flush=True
        )

        print(
            "Chain links valid:",
            result["chain_ok"],
            flush=True
        )

        print(
            "Fully verified:",
            result["fully_verified"],
            flush=True
        )

        return result["fully_verified"]

    except Exception:

        app.logger.exception(
            "Audit verification failed."
        )

        return False


# =====================================
# 12. ADD AUDIT RECORD
# =====================================

def add_audit(action, document_id=None):

    if not current_user.is_authenticated:
        return False

    try:

        status = audit_chain_status()

        if not status["chain_ok"]:

            app.logger.error(
                "Existing audit chain is damaged. "
                "New record was not added: %s",
                status["message"]
            )

            return False

        timestamp = utc_now()
        timestamp_string = timestamp.isoformat()

        previous = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).first()

        previous_hash = (
            previous.entry_hash
            if previous
            else "GENESIS"
        )

        actor_id = current_user.id

        entry_hash = make_audit_hash(
            actor_id,
            document_id,
            action,
            previous_hash,
            timestamp_string
        )

        log = AuditLog(
            actor_id=actor_id,
            document_id=document_id,
            action=action,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            created_at=timestamp,
            hash_version=1,
            hash_timestamp=timestamp_string
        )

        db.session.add(log)
        db.session.commit()

        print(
            "AUDIT RECORD CREATED:",
            log.id,
            action,
            "HASH:",
            entry_hash,
            flush=True
        )

        return True

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Unable to create audit record."
        )

        return False


# =====================================
# 13. ROLE AND PERMISSION CHECKING
# =====================================

def can_read(document):

    if not current_user.is_authenticated:
        return False

    if current_user.role == "Admin":
        return True

    if document.owner_id == current_user.id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    return permission is not None


def can_edit(document):

    if not current_user.is_authenticated:
        return False

    if current_user.role == "Admin":
        return True

    if current_user.role == "Viewer":
        return False

    if document.owner_id == current_user.id:
        return True

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    return (
        permission is not None
        and permission.can_edit
    )


def can_manage_document(document):

    if not current_user.is_authenticated:
        return False

    if current_user.role == "Admin":
        return True

    return (
        current_user.role == "Owner"
        and document.owner_id == current_user.id
    )


# =====================================
# 14. FILE VALIDATION
# =====================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def valid_file_content(filename, file_data):

    if "." not in filename:
        return False

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    if extension == "pdf":

        return file_data.startswith(b"%PDF-")

    if extension == "png":

        return file_data.startswith(
            b"\x89PNG\r\n\x1a\n"
        )

    if extension in ("jpg", "jpeg"):

        return file_data.startswith(b"\xff\xd8\xff")

    if extension == "txt":

        if b"\x00" in file_data:
            return False

        try:
            file_data.decode("utf-8")
            return True

        except UnicodeDecodeError:
            return False

    if extension == "docx":

        try:

            with zipfile.ZipFile(
                io.BytesIO(file_data)
            ) as docx_file:

                if docx_file.testzip() is not None:
                    return False

                names = docx_file.namelist()

                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                )

        except (
            zipfile.BadZipFile,
            OSError
        ):
            return False

    return False


# =====================================
# 15. HOME PAGE
# =====================================

@app.route("/")
def home():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =====================================
# 16. REGISTRATION
# =====================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

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

        if not username or not email or not password:

            flash("Please fill in all fields.")

            return redirect(
                url_for("register")
            )

        if len(username) > 100 or len(email) > 150:

            flash("Username or email is too long.")

            return redirect(
                url_for("register")
            )

        if "@" not in email or "." not in email:

            flash("Please enter a valid email address.")

            return redirect(
                url_for("register")
            )

        if not strong_password(password):

            flash(
                "Password must be 8 to 128 characters "
                "and include an uppercase letter, "
                "a lowercase letter, a number, "
                "and a special character."
            )

            return redirect(
                url_for("register")
            )

        existing = User.query.filter(
            (User.username == username)
            | (User.email == email)
        ).first()

        if existing:

            flash(
                "Username or email already exists."
            )

            return redirect(
                url_for("register")
            )

        # New accounts always start as Viewer.

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role="Viewer"
        )

        try:

            db.session.add(user)
            db.session.commit()

        except Exception:

            db.session.rollback()

            app.logger.exception(
                "Registration failed."
            )

            flash(
                "Unable to register. Please try again."
            )

            return redirect(
                url_for("register")
            )

        flash(
            "Registration successful. Please log in."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =====================================
# 17. LOGIN
# =====================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            add_audit("LOGIN")

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password."
        )

    return render_template(
        "login.html"
    )


# =====================================
# 18. FORGOT PASSWORD
# =====================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        user = User.query.filter_by(
            email=email
        ).first()

        # Same message whether account exists or not.

        flash(
            "If an account exists for that email, "
            "password reset instructions have been sent."
        )

        if user:

            token = password_reset_serializer().dumps(
                {
                    "user_id": user.id,
                    "password_hash": user.password
                }
            )

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            try:

                sent = send_password_reset_email(
                    user,
                    reset_url
                )

                if not sent and not SHOW_RESET_LINK_IN_TERMINAL:

                    app.logger.warning(
                        "Reset email could not be sent."
                    )

            except Exception:

                app.logger.exception(
                    "Unable to send password reset email."
                )

        return redirect(
            url_for("login")
        )

    return render_template(
        "forgot_password.html"
    )


# =====================================
# 19. RESET PASSWORD
# =====================================

@app.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    try:

        data = password_reset_serializer().loads(
            token,
            max_age=PASSWORD_RESET_MAX_AGE
        )

    except SignatureExpired:

        flash(
            "This password reset link has expired. "
            "Request a new one."
        )

        return redirect(
            url_for("forgot_password")
        )

    except BadSignature:

        flash(
            "This password reset link is invalid."
        )

        return redirect(
            url_for("forgot_password")
        )

    user_id = data.get("user_id")

    if not isinstance(user_id, int):

        flash("This password reset link is invalid.")

        return redirect(
            url_for("forgot_password")
        )

    user = db.session.get(
        User,
        user_id
    )

    if (
        not user
        or data.get("password_hash") != user.password
    ):

        flash(
            "This password reset link is invalid "
            "or has already been used."
        )

        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not strong_password(password):

            flash(
                "Password must be 8 to 128 characters "
                "and include an uppercase letter, "
                "a lowercase letter, a number, "
                "and a special character."
            )

            return render_template(
                "reset_password.html",
                token=token
            )

        if password != confirm_password:

            flash(
                "The passwords do not match."
            )

            return render_template(
                "reset_password.html",
                token=token
            )

        try:

            user.password = generate_password_hash(password)

            db.session.commit()

        except Exception:

            db.session.rollback()

            app.logger.exception(
                "Password reset failed."
            )

            flash(
                "Unable to reset password. Please try again."
            )

            return render_template(
                "reset_password.html",
                token=token
            )

        flash(
            "Password reset successful. Please log in."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "reset_password.html",
        token=token
    )


# =====================================
# 20. LOGOUT
# =====================================

@app.route(
    "/logout",
    methods=["POST"]
)
@login_required
def logout():

    add_audit("LOGOUT")

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =====================================
# 21. DASHBOARD
# =====================================

@app.route("/dashboard")
@login_required
def dashboard():

    documents = Document.query.order_by(
        Document.created_at.desc()
    ).all()

    visible_documents = [
        doc for doc in documents
        if can_read(doc)
    ]

    search = request.args.get(
        "search",
        ""
    ).strip().lower()

    if search:

        visible_documents = [
            doc for doc in visible_documents
            if search in doc.title.lower()
            or search in (
                doc.description or ""
            ).lower()
        ]

    return render_template(
        "dashboard.html",
        documents=visible_documents,
        can_upload=current_user.role in ("Admin", "Owner")
    )


# =====================================
# 22. UPLOAD DOCUMENT
# =====================================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
@login_required
def upload():

    if current_user.role not in ("Admin", "Owner"):
        abort(403)

    if request.method == "POST":

        file = request.files.get("file")

        title = request.form.get(
            "title",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        )

        if not file or file.filename == "":

            flash("Please select a file.")

            return redirect(
                url_for("upload")
            )

        if not title or len(title) > 150:

            flash("Enter a valid document title.")

            return redirect(
                url_for("upload")
            )

        if not allowed_file(file.filename):

            flash("Choose an allowed file type.")

            return redirect(
                url_for("upload")
            )

        original_name = secure_filename(
            file.filename
        )

        if not original_name:

            flash("Invalid file name.")

            return redirect(
                url_for("upload")
            )

        file_data = file.read()

        if not file_data:

            flash("The selected file is empty.")

            return redirect(
                url_for("upload")
            )

        if not valid_file_content(
            original_name,
            file_data
        ):

            flash(
                "The file content does not match its extension."
            )

            return redirect(
                url_for("upload")
            )

        stored_name = (
            secrets.token_hex(16)
            + "_"
            + original_name
        )

        file_hash = hashlib.sha256(
            file_data
        ).hexdigest()

        file_path = UPLOAD_FOLDER / stored_name

        try:

            with open(file_path, "xb") as saved_file:
                saved_file.write(file_data)

            document = Document(
                title=title,
                description=description,
                filename=stored_name,
                original_name=original_name,
                file_hash=file_hash,
                owner_id=current_user.id
            )

            db.session.add(document)
            db.session.commit()

            add_audit(
                "DOCUMENT_UPLOADED",
                document.id
            )

            flash(
                "Document uploaded successfully."
            )

        except Exception:

            db.session.rollback()

            if file_path.exists():
                file_path.unlink()

            app.logger.exception(
                "Document upload failed."
            )

            flash(
                "Unable to upload the document."
            )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "upload.html"
    )


# =====================================
# 23. VIEW DOCUMENT
# =====================================

@app.route(
    "/documents/<int:document_id>"
)
@login_required
def document_detail(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    if not can_read(document):
        abort(403)

    permissions = Permission.query.filter_by(
        document_id=document.id
    ).all()

    add_audit(
        "DOCUMENT_VIEWED",
        document.id
    )

    return render_template(
        "document.html",
        document=document,
        permissions=permissions,
        can_edit_document=can_edit(document),
        can_manage=can_manage_document(document)
    )


# =====================================
# 24. DOWNLOAD DOCUMENT
# =====================================

@app.route(
    "/documents/<int:document_id>/download"
)
@login_required
def download(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    if not can_read(document):
        abort(403)

    # Stored filenames are generated by the application.
    file_path = UPLOAD_FOLDER / document.filename

    if not file_path.is_file():
        abort(404)

    try:

        with open(file_path, "rb") as stored_file:
            file_data = stored_file.read()

    except OSError:

        app.logger.exception(
            "Unable to read stored document."
        )

        abort(404)

    current_hash = hashlib.sha256(
        file_data
    ).hexdigest()

    if not secrets.compare_digest(
        current_hash,
        document.file_hash
    ):

        app.logger.error(
            "Document integrity check failed for document %s",
            document.id
        )

        abort(403)

    add_audit(
        "DOCUMENT_DOWNLOADED",
        document.id
    )

    return send_from_directory(
        UPLOAD_FOLDER,
        document.filename,
        as_attachment=True,
        download_name=document.original_name
    )


# =====================================
# 25. SHARE DOCUMENT
# =====================================

@app.route(
    "/documents/<int:document_id>/share",
    methods=["POST"]
)
@login_required
def share_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    if not can_manage_document(document):
        abort(403)

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    access = request.form.get(
        "access",
        "read"
    ).lower()

    if access not in ("read", "edit"):

        flash("Invalid permission selected.")

        return redirect(
            url_for(
                "document_detail",
                document_id=document.id
            )
        )

    user = User.query.filter_by(
        email=email
    ).first()

    if not user or user.id == current_user.id:

        flash(
            "Enter a valid registered user's email."
        )

        return redirect(
            url_for(
                "document_detail",
                document_id=document.id
            )
        )

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()

    try:

        if permission:

            permission.can_edit = (access == "edit")

        else:

            permission = Permission(
                document_id=document.id,
                user_id=user.id,
                can_edit=(access == "edit")
            )

            db.session.add(permission)

        db.session.commit()

        add_audit(
            "PERMISSION_GRANTED",
            document.id
        )

        flash("Document permission updated.")

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Unable to update document permission."
        )

        flash(
            "Unable to update permission."
        )

    return redirect(
        url_for(
            "document_detail",
            document_id=document.id
        )
    )


# =====================================
# 26. REVOKE PERMISSION
# =====================================

@app.route(
    "/documents/<int:document_id>/revoke/<int:user_id>",
    methods=["POST"]
)
@login_required
def revoke_permission(document_id, user_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    if not can_manage_document(document):
        abort(403)

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=user_id
    ).first()

    if permission:

        try:

            db.session.delete(permission)
            db.session.commit()

            add_audit(
                "PERMISSION_REVOKED",
                document.id
            )

            flash("Permission revoked.")

        except Exception:

            db.session.rollback()

            app.logger.exception(
                "Unable to revoke permission."
            )

            flash(
                "Unable to revoke permission."
            )

    return redirect(
        url_for(
            "document_detail",
            document_id=document.id
        )
    )


# =====================================
# 27. EDIT DOCUMENT
# =====================================

@app.route(
    "/documents/<int:document_id>/edit",
    methods=["POST"]
)
@login_required
def edit_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    if not can_edit(document):
        abort(403)

    title = request.form.get(
        "title",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    )

    if not title or len(title) > 150:

        flash("Enter a valid document title.")

        return redirect(
            url_for(
                "document_detail",
                document_id=document.id
            )
        )

    try:

        document.title = title
        document.description = description

        db.session.commit()

        add_audit(
            "DOCUMENT_UPDATED",
            document.id
        )

        flash("Document updated.")

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Document update failed."
        )

        flash(
            "Unable to update document."
        )

    return redirect(
        url_for(
            "document_detail",
            document_id=document.id
        )
    )


# =====================================
# 28. ADMIN DASHBOARD
# =====================================

@app.route("/admin")
@login_required
def admin():

    if current_user.role != "Admin":
        abort(403)

    users = User.query.order_by(
        User.id.asc()
    ).all()

    documents = Document.query.order_by(
        Document.id.desc()
    ).all()

    logs = AuditLog.query.order_by(
        AuditLog.id.desc()
    ).limit(100).all()

    return render_template(
        "admin.html",
        users=users,
        documents=documents,
        logs=logs,
        valid_roles=VALID_ROLES
    )


# =====================================
# 29. ADMIN CHANGE USER ROLE
# =====================================

@app.route(
    "/admin/users/<int:user_id>/role",
    methods=["POST"]
)
@login_required
def change_user_role(user_id):

    if current_user.role != "Admin":
        abort(403)

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        abort(404)

    new_role = request.form.get(
        "role",
        ""
    ).strip()

    if new_role not in VALID_ROLES:

        flash(
            "Invalid role selected.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    if user.id == current_user.id:

        flash(
            "You cannot change your own role.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    if (
        user.role == "Admin"
        and new_role != "Admin"
    ):

        admin_count = User.query.filter_by(
            role="Admin"
        ).count()

        if admin_count <= 1:

            flash(
                "You cannot remove the last Admin account.",
                "error"
            )

            return redirect(
                url_for("admin")
            )

    if user.role == new_role:

        flash(
            "The user already has this role.",
            "info"
        )

        return redirect(
            url_for("admin")
        )

    try:

        old_role = user.role
        user.role = new_role

        db.session.commit()

        audit_action = (
            "USER_ROLE_UPDATED "
            + "user_id=" + str(user.id)
            + " old=" + str(old_role)
            + " new=" + str(new_role)
        )

        add_audit(audit_action)

        flash(
            "Role changed from "
            + old_role
            + " to "
            + new_role
            + " successfully.",
            "success"
        )

    except Exception:

        db.session.rollback()

        app.logger.exception(
            "Role update failed."
        )

        flash(
            "Unable to update user role.",
            "error"
        )

    return redirect(
        url_for("admin")
    )


# =====================================
# 30. AUDIT TRAIL PAGE
# =====================================

@app.route("/audit")
@login_required
def audit_trail():

    print(
        "\nAUDIT PAGE FUNCTION CALLED",
        flush=True
    )

    if current_user.role == "Admin":

        logs = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).all()

    else:

        owned_documents = Document.query.filter_by(
            owner_id=current_user.id
        ).all()

        document_ids = [
            document.id
            for document in owned_documents
        ]

        all_logs = AuditLog.query.order_by(
            AuditLog.id.desc()
        ).all()

        logs = [
            log for log in all_logs
            if (
                log.actor_id == current_user.id
                or log.document_id in document_ids
            )
        ]

    status = audit_chain_status()

    print(
        "AUDIT PAGE RESULT:",
        status["message"],
        flush=True
    )

    return render_template(
        "audit.html",
        logs=logs,
        chain_valid=status["fully_verified"],
        chain_status=status
    )


# =====================================
# 31. ADMIN AUDIT VERIFICATION
# =====================================

@app.route("/admin/audit/verify")
@login_required
def verify_audit():

    if current_user.role != "Admin":
        abort(403)

    try:

        status = audit_chain_status()

        if not status["chain_ok"]:

            result_message = (
                "Audit chain integrity failed: "
                + status["message"]
            )

            result_status = "Failed"

        elif status["legacy_count"] > 0:

            result_message = (
                "Audit chain links are intact. "
                + str(status["verified_count"])
                + " new records verified. "
                + str(status["legacy_count"])
                + " legacy records cannot be independently verified."
            )

            result_status = "Partially Verified"

        else:

            result_message = (
                "All audit records verified successfully."
            )

            result_status = "Verified"

        return render_template(
            "verify_audit.html",
            message=result_message,
            result_status=result_status,
            status=status
        )

    except Exception:

        app.logger.exception(
            "Audit verification page failed."
        )

        return render_template(
            "error.html",
            message="Unable to verify audit records."
        ), 500


# =====================================
# 32. ERROR HANDLERS
# =====================================

@app.errorhandler(400)
def bad_request(error):

    return render_template(
        "error.html",
        message="Bad request."
    ), 400


@app.errorhandler(403)
def forbidden(error):

    return render_template(
        "error.html",
        message="Access denied."
    ), 403


@app.errorhandler(404)
def not_found(error):

    return render_template(
        "error.html",
        message="Page not found."
    ), 404


@app.errorhandler(413)
def file_too_large(error):

    return render_template(
        "error.html",
        message="File is larger than 10 MB."
    ), 413


# =====================================
# 33. DATABASE CREATION AND MIGRATION
# =====================================

with app.app_context():

    db.create_all()

    with db.engine.begin() as connection:

        # User table migration.

        user_columns = [
            row[1]
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(user)"
            ).fetchall()
        ]

        if "role" not in user_columns:

            connection.exec_driver_sql(
                "ALTER TABLE user "
                "ADD COLUMN role VARCHAR(20) "
                "NOT NULL DEFAULT 'Viewer'"
            )

        # Preserve valid existing roles.

        connection.exec_driver_sql(
            """
            UPDATE user
            SET role = 'Viewer'
            WHERE role IS NULL
            OR role NOT IN ('Admin', 'Owner', 'Viewer')
            """
        )

        # Audit table migration.

        audit_columns = [
            row[1]
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(audit_log)"
            ).fetchall()
        ]

        if "hash_version" not in audit_columns:

            connection.exec_driver_sql(
                "ALTER TABLE audit_log "
                "ADD COLUMN hash_version INTEGER "
                "NOT NULL DEFAULT 0"
            )

        if "hash_timestamp" not in audit_columns:

            connection.exec_driver_sql(
                "ALTER TABLE audit_log "
                "ADD COLUMN hash_timestamp VARCHAR(40)"
            )

    # =================================
    # INITIAL ADMIN ACCOUNT
    # =================================

    admin_email = os.environ.get(
        "ADMIN_EMAIL"
    )

    admin_password = os.environ.get(
        "ADMIN_PASSWORD"
    )

    if admin_email and admin_password:

        admin_email = admin_email.strip().lower()

        existing_admin_user = User.query.filter_by(
            email=admin_email
        ).first()

        if existing_admin_user:

            # Promote only when the configured bootstrap password
            # matches the existing account's password.

            if check_password_hash(
                existing_admin_user.password,
                admin_password
            ):

                if existing_admin_user.role != "Admin":

                    existing_admin_user.role = "Admin"
                    db.session.commit()

                    print(
                        "Existing account promoted to Admin "
                        "using matching bootstrap credentials.",
                        flush=True
                    )

                else:

                    print(
                        "Configured account is already an Admin.",
                        flush=True
                    )

            else:

                print(
                    "ADMIN_EMAIL already exists, but the "
                    "ADMIN_PASSWORD does not match. "
                    "Existing role was not changed.",
                    flush=True
                )

        else:

            if not strong_password(admin_password):

                print(
                    "Initial Admin was not created. "
                    "ADMIN_PASSWORD must contain at least 8 characters, "
                    "uppercase, lowercase, number and special character.",
                    flush=True
                )

            else:

                admin_username = (
                    "Administrator_"
                    + secrets.token_hex(4)
                )

                admin_user = User(
                    username=admin_username,
                    email=admin_email,
                    password=generate_password_hash(
                        admin_password
                    ),
                    role="Admin"
                )

                try:

                    db.session.add(admin_user)
                    db.session.commit()

                    print(
                        "Initial Admin account created.",
                        flush=True
                    )

                except Exception:

                    db.session.rollback()

                    app.logger.exception(
                        "Initial Admin creation failed."
                    )

    else:

        print(
            "ADMIN_EMAIL and ADMIN_PASSWORD are not configured. "
            "No initial Admin account was created.",
            flush=True
        )


# =====================================
# 34. RUN APPLICATION
# =====================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )