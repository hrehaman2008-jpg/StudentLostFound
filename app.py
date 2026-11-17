r"""
Student Lost and Found Portal - Phase 10 (secure admin dashboard)

A simple Flask application with student registration, login, logout,
a protected dashboard and lost/found reports backed by SQLite.

Phases 1-2 (kept):
    - User model (Flask-SQLAlchemy) stored at instance/lost_found.db
    - Registration with validation and Werkzeug password hashing
    - Login / logout using Flask-Login sessions
    - CSRF protection on every form (Flask-WTF)
    - Protected /dashboard page

Phases 3-4 scope:
    - ItemReport model (owner, type, category, location, date, status)
    - /report page for logged-in students
    - /browse page with search (title/description/location) + type,
      category and status filters, all driven by GET query parameters
    - /my-reports page showing only the student's own reports
    - Owners can mark their own active report as Returned (POST + CSRF)
    - Real dashboard counters for the logged-in student

Phase 6 scope:
    - /reports/<id>/edit lets the owner change the title, description,
      category, report type, location and date (status and owner are kept)
    - /reports/<id>/delete removes the owner's report (POST + CSRF)
    - Both are owner-only and never touch another student's report

Phase 7 scope:
    - Optional JPG/PNG/WEBP photograph per report (maximum 5 MB)
    - Files stored in static/uploads/reports with random UUID names
    - File extension AND the file's own signature are checked
    - Replacing or deleting a report removes the old file too

Phase 8 scope:
    - Claim model linking a student to a Found report (Pending/Approved/Rejected)
    - Students can claim active Found reports they do not own (CSRF + login)
    - Owners review claims on /incoming-claims and approve or reject them
    - Approving marks the report Returned and rejects the other pending claims
    - /my-claims shows every claim a student has sent, with its status

Phase 9 scope:
    - Notification model (recipient, optional claim/report, type, read flag)
    - Claims, approvals, rejections and automatic rejections create them
    - Navbar bell with an unread counter, /notifications page
    - Mark one / mark all as read with CSRF, always scoped to the owner

Phase 10 scope:
    - User.is_admin and User.is_active (safe, idempotent SQLite migration)
    - admin_required guard on /admin, /admin/users, /admin/reports, /admin/claims
    - Real dashboard counters and a recent-activity feed
    - Account deactivation (never yourself, never the last active admin)
    - Report moderation that removes the photo, claims and notifications
    - Read-only claim oversight; students still own their own decisions
    - The first administrator is created locally with: flask --app app
      promote-admin <email> (never hardcoded, never automatic)

Deliberately not implemented (out of scope for this college project):
    - Image uploads, messaging, email notifications, admin features

Run locally (Windows):
    py -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    python app.py
"""

import os
import re
import uuid
from datetime import datetime, timezone
from functools import wraps

import click

from flask import (
    Flask,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import inspect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Resolve the project folder (the folder that contains this file).
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# The SQLite database always lives in the project's instance folder.
DATABASE_PATH = os.path.join(BASE_DIR, "instance", "lost_found.db")

# Very small and readable email check (good enough for a college demo).
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Allowed values for an item report (server-side validation).
REPORT_TYPES = ["Lost", "Found"]
CATEGORIES = ["Electronics", "ID Card", "Books", "Accessories", "Keys", "Other"]
STATUSES = ["Active", "Returned"]

# Dates arrive from <input type="date"> as YYYY-MM-DD.
DATE_FORMAT = "%Y-%m-%d"

# --- Uploaded photographs ----------------------------------------------
# Extensions we accept, and the real size limit (checked on the server).
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB

# Claim states an administrator may filter the overview by.
CLAIM_STATUSES = ["Pending", "Approved", "Rejected"]

# --- Extensions (initialised once, bound to the app in create_app) ----
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


# --- Database model ---------------------------------------------------


class User(UserMixin, db.Model):
    """A registered student account. Passwords are stored as hashes only.

    UserMixin gives Flask-Login the is_active / is_authenticated flags.
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # Phase 10: administrators are promoted deliberately (never automatically)
    # and every existing student stays an ordinary, active account.
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<User {self.email}>"


class ItemReport(db.Model):
    """A lost or found item posted by a student.

    status starts as "Active" and becomes "Returned" once the item has
    been reunited with its owner (a later phase updates it).
    """

    __tablename__ = "item_report"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(40), nullable=False)
    report_type = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    date_lost_found = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Active")
    # Phase 7: file name of the optional photograph (None = no photo).
    image_filename = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    @property
    def image_path(self):
        """Absolute path of the stored photograph, or None when there is none."""
        if not self.image_filename:
            return None
        safe_name = os.path.basename(self.image_filename)
        return os.path.join(current_app.config["UPLOAD_FOLDER"], safe_name)

    @property
    def image_url(self):
        """Public URL of the photograph, or None if the file is missing."""
        path = self.image_path
        if path and os.path.isfile(path):
            filename = os.path.basename(self.image_filename)
            if current_app.config.get("VERCEL_RUNTIME"):
                return url_for("report_image", filename=filename)
            return url_for("static", filename="uploads/reports/" + filename)
        return None

    # "author" is the student who created the report; User.reports is the list.
    author = db.relationship("User", backref=db.backref("reports", lazy=True))

    def __repr__(self):
        return f"<ItemReport {self.id} {self.report_type}: {self.title}>"


class Claim(db.Model):
    """A student's request to be given a found item.

    One student can claim a given report only once (unique constraint), and
    the owner decides between Pending, Approved and Rejected.
    """

    __tablename__ = "claim"
    __table_args__ = (
        db.UniqueConstraint("report_id", "claimant_id", name="uq_claim_report_claimant"),
    )

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("item_report.id"), nullable=False, index=True
    )
    claimant_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Pending", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Deleting a report also deletes its claims.
    report = db.relationship(
        "ItemReport",
        backref=db.backref("claims", lazy=True, cascade="all, delete-orphan"),
    )
    claimant = db.relationship("User", backref=db.backref("claims", lazy=True))

    def __repr__(self):
        return f"<Claim {self.id} report={self.report_id} status={self.status}>"


class Notification(db.Model):
    """A short message for one student about their claims or reports."""

    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    claim_id = db.Column(db.Integer, db.ForeignKey("claim.id"), nullable=True, index=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("item_report.id"), nullable=True, index=True
    )
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(30), nullable=False, index=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    recipient = db.relationship("User", backref=db.backref("notifications", lazy=True))
    claim = db.relationship("Claim")
    report = db.relationship("ItemReport")

    def __repr__(self):
        return f"<Notification {self.id} {self.notification_type} read={self.is_read}>"


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login callback: reload the logged-in user from the session."""
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    """Send protected-page visitors to the login page with a friendly note."""
    flash("Please log in to access that page.", "info")
    return redirect(url_for("login", next=request.path))


def _ensure_user_columns():
    """Add the Phase 10 administrator and status columns in place.

    db.create_all() cannot add columns to an existing table, so each one is
    added with ALTER TABLE only when it is really missing. Existing students
    keep is_admin = 0 and is_active = 1, so nobody is ever promoted by the
    migration itself.
    """
    inspector = inspect(db.engine)
    if not inspector.has_table("user"):
        return
    columns = {column["name"] for column in inspector.get_columns("user")}
    if "is_admin" not in columns:
        db.session.execute(
            db.text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE')
        )
    if "is_active" not in columns:
        db.session.execute(
            db.text('ALTER TABLE "user" ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE')
        )
    db.session.commit()


def _ensure_notification_schema():
    """Create the notification table and its unread index when missing.

    Idempotent: existing databases are upgraded in place, and running this on
    every start never adds anything twice.
    """
    inspector = inspect(db.engine)
    if not inspector.has_table("notification"):
        Notification.__table__.create(db.engine, checkfirst=True)
    db.session.execute(
        db.text(
            "CREATE INDEX IF NOT EXISTS ix_notification_user_unread "
            "ON notification (user_id, is_read)"
        )
    )
    db.session.commit()


def _ensure_claim_schema():
    """Create the claim table and its unique index when they are missing.

    db.create_all() already creates new tables, but this runs the same checks
    explicitly so an older database that was created before Phase 8 is
    upgraded safely. Running it any number of times changes nothing.
    """
    inspector = inspect(db.engine)
    if not inspector.has_table("claim"):
        Claim.__table__.create(db.engine, checkfirst=True)
    # One claim per student per report, whatever the table came from.
    db.session.execute(
        db.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_claim_report_claimant "
            "ON claim (report_id, claimant_id)"
        )
    )
    db.session.commit()


def _ensure_image_column():
    """Add the optional photo column to an existing item_report table.

    db.create_all() only creates missing tables, so a database made in an
    earlier phase needs this one small ALTER TABLE. It is idempotent: the
    column is added only when it is really missing, so starting the app many
    times is safe and no data is ever touched.
    """
    inspector = inspect(db.engine)
    if not inspector.has_table("item_report"):
        return
    columns = {column["name"] for column in inspector.get_columns("item_report")}
    if "image_filename" not in columns:
        db.session.execute(
            db.text("ALTER TABLE item_report ADD COLUMN image_filename VARCHAR(120)")
        )
        db.session.commit()


# --- Application factory ----------------------------------------------


def create_app(test_config=None):
    """Create and configure the Flask application."""
    is_vercel = bool(os.environ.get("VERCEL"))
    instance_path = os.environ.get("INSTANCE_PATH")
    if not instance_path:
        instance_path = (
            "/tmp/student_lost_found_instance"
            if is_vercel
            else os.path.join(BASE_DIR, "instance")
        )
    app = Flask(
        __name__,
        instance_relative_config=True,
        instance_path=instance_path,
    )

    # Ensure the instance folder exists so the SQLite database file
    # can be created inside it.
    os.makedirs(app.instance_path, exist_ok=True)

    # --- Application configuration -------------------------------------
    # The secret key is read from an environment variable when available.
    #
    # Development-only fallback: the hardcoded value below is ONLY for
    # running the app locally during development/demonstration.
    # NEVER use it in production and never commit a real secret key.
    #
    # Windows (cmd):    set SECRET_KEY=your-random-secret
    # Windows (PS):     $env:SECRET_KEY="your-random-secret"
    # Linux/macOS:      export SECRET_KEY=your-random-secret
    secret_key = os.environ.get("SECRET_KEY")
    if is_vercel and not secret_key:
        raise RuntimeError("Set SECRET_KEY in the Vercel project environment before deploying.")
    app.config["SECRET_KEY"] = secret_key or "dev-only-insecure-secret-key-change-me"
    app.config["SESSION_COOKIE_SECURE"] = is_vercel

    # Local development keeps SQLite. Vercel can use DATABASE_URL for durable
    # PostgreSQL; /tmp is only a non-persistent fallback for short demos.
    database_url = os.environ.get("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif database_url and database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if not database_url:
        database_path = "/tmp/student_lost_found.db" if is_vercel else DATABASE_PATH
        database_url = "sqlite:///" + database_path
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["VERCEL_RUNTIME"] = is_vercel

    # Vercel's filesystem is read-only apart from temporary /tmp storage.
    # Use it for a demo; production uploads need durable object storage.
    upload_folder = os.environ.get("UPLOAD_FOLDER")
    if not upload_folder:
        upload_folder = (
            "/tmp/student_lost_found_uploads"
            if is_vercel
            else os.path.join(BASE_DIR, "static", "uploads", "reports")
        )
    app.config["UPLOAD_FOLDER"] = upload_folder
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    # Hard cap for a whole request (5 MB photo plus the normal form fields).
    app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

    # Tests may point the app at a temporary database.
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "login"

    # Create missing tables only - this never drops or resets existing data.
    with app.app_context():
        db.create_all()
        _ensure_user_columns()
        _ensure_image_column()
        _ensure_claim_schema()
        _ensure_notification_schema()

    register_routes(app)

    if is_vercel:
        @app.route("/uploads/reports/<path:filename>")
        def report_image(filename):
            return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    return app


# --- Validation helpers -----------------------------------------------


def _validate_registration(form):
    """Return a list of friendly error messages for the registration form."""
    errors = []

    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    password = form.get("password") or ""
    confirm = form.get("confirm_password") or ""

    if not name:
        errors.append("Please enter your full name.")
    if not email:
        errors.append("Please enter your college email.")
    elif not EMAIL_RE.match(email):
        errors.append("That email address does not look valid. Example: you@college.edu.")
    if not password:
        errors.append("Please enter a password.")
    elif len(password) < 8:
        errors.append("Your password must be at least 8 characters long.")
    elif password != confirm:
        errors.append("The passwords do not match. Please try again.")

    return errors


def _read_filters(args, default_status="Active"):
    """Read and sanitise the search/filter query parameters.

    Anything unexpected falls back to "All" so a hand-edited URL can never
    break the page or leak invalid values into the query.
    """
    report_type = (args.get("report_type") or "All").strip()
    category = (args.get("category") or "All").strip()
    status = (args.get("status") or default_status).strip()

    return {
        "q": (args.get("q") or "").strip(),
        "report_type": report_type if report_type in REPORT_TYPES else "All",
        "category": category if category in CATEGORIES else "All",
        "status": status if status in STATUSES else "All",
    }


def _apply_filters(filters, query=None):
    """Apply the search text and filters to an ItemReport query."""
    if query is None:
        query = ItemReport.query

    if filters["q"]:
        # Case-insensitive match on title, description or location.
        pattern = "%" + filters["q"].lower() + "%"
        query = query.filter(
            db.or_(
                db.func.lower(ItemReport.title).like(pattern),
                db.func.lower(ItemReport.description).like(pattern),
                db.func.lower(ItemReport.location).like(pattern),
            )
        )

    if filters["report_type"] != "All":
        query = query.filter(ItemReport.report_type == filters["report_type"])
    if filters["category"] != "All":
        query = query.filter(ItemReport.category == filters["category"])
    if filters["status"] != "All":
        query = query.filter(ItemReport.status == filters["status"])

    return query


def _back_to(fallback_url):
    """Redirect to the page the button was pressed on, if it is local.

    Only same-site paths are accepted, so the hidden "next" field can never
    be used to bounce a student to another website.
    """
    target = (request.form.get("next") or "").strip()
    if target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    return redirect(fallback_url)


def _validate_report(form):
    """Return friendly error messages for the report form."""
    errors = []

    title = (form.get("title") or "").strip()
    report_type = (form.get("report_type") or "").strip()
    category = (form.get("category") or "").strip()
    description = (form.get("description") or "").strip()
    location = (form.get("location") or "").strip()
    raw_date = (form.get("date_lost_found") or "").strip()

    if not title:
        errors.append("Please enter the item name.")
    if report_type not in REPORT_TYPES:
        errors.append("Please choose whether the item is Lost or Found.")
    if category not in CATEGORIES:
        errors.append("Please choose one of the allowed categories.")
    if not description:
        errors.append("Please describe the item.")
    if not location:
        errors.append("Please tell us where the item was lost or found.")
    if not raw_date:
        errors.append("Please enter the date the item was lost or found.")
    else:
        try:
            datetime.strptime(raw_date, DATE_FORMAT)
        except ValueError:
            errors.append("Please enter a valid date (YYYY-MM-DD).")

    return errors


def _detect_image_extension(data):
    """Return the extension implied by the file's own bytes, or None.

    Only three real image signatures are accepted. SVG, HTML, scripts and
    renamed text files all fail here, whatever their name or MIME type says.
    """
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _save_upload(file_storage):
    """Validate an optional upload and save it. Returns (filename, error).

    (None, None) means "no image chosen", which is always allowed.
    """
    if file_storage is None or not file_storage.filename:
        return None, None

    # The student's file name is only used to read an extension; the file on
    # disk gets a random name, so no user-supplied path is ever trusted.
    safe_name = secure_filename(file_storage.filename)
    extension = os.path.splitext(safe_name)[1].lower().lstrip(".")
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        # secure_filename() can strip unusual characters, so retry on the raw name.
        extension = os.path.splitext(file_storage.filename)[1].lower().lstrip(".")
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return None, (
            "That file type is not supported. Please upload a JPG, PNG or WEBP photograph."
        )

    data = file_storage.read()
    if not data:
        return None, "That file is empty. Please choose a photograph or leave the field blank."
    if len(data) > MAX_IMAGE_BYTES:
        return None, "That image is larger than 5 MB. Please choose a smaller photograph."

    detected = _detect_image_extension(data)
    if detected is None:
        return None, (
            "That file does not look like a real image. "
            "Please upload a JPG, PNG or WEBP photograph."
        )

    filename = f"{uuid.uuid4().hex}.{detected}"
    folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, filename), "wb") as handle:
        handle.write(data)
    return filename, None


def _delete_image(filename):
    """Remove a stored photograph; a missing file is not an error."""
    if not filename:
        return
    folder = current_app.config["UPLOAD_FOLDER"]
    path = os.path.join(folder, os.path.basename(filename))
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        # A locked or already deleted file must never break the request.
        pass


def _validate_claim(form):
    """Return friendly error messages for the claim explanation."""
    errors = []
    message = (form.get("message") or "").strip()

    if not message:
        errors.append("Please explain why you believe this item is yours.")
    elif len(message) < 10:
        errors.append(
            "Please write a little more (at least 10 characters) so the owner can recognise you."
        )
    elif len(message) > 500:
        errors.append("Please keep your explanation under 500 characters.")

    return errors


def _claim_problem(item):
    """Return a reason why this student cannot claim this report, or None."""
    if item.user_id == current_user.id:
        return "You cannot claim your own report."
    if item.report_type != "Found":
        return "Only found items can be claimed. Lost reports are for the owner to track."
    if item.status != "Active":
        return "This item has already been returned to its owner."
    existing = Claim.query.filter_by(report_id=item.id, claimant_id=current_user.id).first()
    if existing is not None:
        return "You have already claimed this item."
    return None


def _notify(user_id, title, message, notification_type, claim=None, report=None):
    """Queue one notification for a student (the caller commits).

    Only ever called from POST handlers, so refreshing a page can never
    create duplicates, and the actor is never notified about their own action.
    """
    if user_id is None:
        return None
    notification = Notification(
        user_id=user_id,
        claim_id=claim.id if claim is not None else None,
        report_id=report.id if report is not None else None,
        title=title,
        message=message,
        notification_type=notification_type,
        is_read=False,
    )
    db.session.add(notification)
    return notification


def _pending_claims_for(report_id):
    """Every still-pending claim on one report."""
    return Claim.query.filter_by(report_id=report_id, status="Pending").all()


def admin_required(view):
    """Allow only signed-in administrators.

    Anonymous visitors are sent to the login page, signed-in students get a
    friendly refusal and are returned to their own dashboard, so no admin page
    or action is ever reachable without the server-side is_admin check.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            flash("Administrator access is required for that page.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def _remove_report(item):
    """Delete a report together with its photo, claims and notifications.

    Used by both the owner's delete route and administrator moderation, so
    there is exactly one place that knows how to remove a report without
    leaving orphaned records behind. Returns the removed title.
    """
    title = item.title
    image_filename = item.image_filename
    claim_ids = [claim.id for claim in item.claims]

    # Notifications about this report (or its claims) go with it, so no
    # notification can ever point at a row that no longer exists.
    note_query = Notification.query.filter(Notification.report_id == item.id)
    if claim_ids:
        note_query = Notification.query.filter(
            db.or_(
                Notification.report_id == item.id,
                Notification.claim_id.in_(claim_ids),
            )
        )
    note_query.delete(synchronize_session=False)

    db.session.delete(item)
    db.session.commit()
    _delete_image(image_filename)
    return title


# --- Routes -----------------------------------------------------------


def register_routes(app):
    """Define every route for the application."""

    @app.before_request
    def block_deactivated_students():
        """A deactivated account is signed out on its very next request."""
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            flash(
                "Your account has been deactivated. Please contact an administrator.",
                "danger",
            )
            return redirect(url_for("login"))
        return None

    @app.route("/")
    def index():
        """Home page: title, introduction, navigation and main buttons."""
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """Create a new student account (password is hashed, never plain text)."""
        if request.method == "GET":
            return render_template("register.html")

        errors = _validate_registration(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("register.html")

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists. Please log in instead.", "warning")
            return redirect(url_for("login"))

        user = User(name=name, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        flash("Your account has been created! Please log in to continue.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Sign a student in with email + password."""
        if request.method == "GET":
            return render_template("login.html")

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password_hash, password):
            flash("Incorrect email or password. Please try again.", "danger")
            return render_template("login.html")

        if not user.is_active:
            flash(
                "This account has been deactivated. Please contact an administrator.",
                "danger",
            )
            return render_template("login.html")

        login_user(user)
        flash(f"Welcome back, {user.name}!", "success")
        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        """Log out (POST only, protected by CSRF)."""
        logout_user()
        flash("You have been logged out. See you soon!", "info")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """Protected page shown after a student signs in."""
        # Real counters for the logged-in student only.
        mine = ItemReport.query.filter_by(user_id=current_user.id)
        stats = {
            "total": mine.count(),
            "lost": mine.filter_by(report_type="Lost").count(),
            "found": mine.filter_by(report_type="Found").count(),
            "returned": mine.filter_by(status="Returned").count(),
        }
        return render_template("dashboard.html", stats=stats)

    @app.route("/report", methods=["GET", "POST"])
    @login_required
    def report():
        """Post a new lost/found report (logged-in students only)."""
        if request.method == "GET":
            return render_template(
                "report.html",
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
                form={},
            )

        errors = _validate_report(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "report.html",
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
                form=request.form,
            )

        image_filename, image_error = _save_upload(request.files.get("image"))
        if image_error:
            flash(image_error, "danger")
            return render_template(
                "report.html",
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
                form=request.form,
            )

        item = ItemReport(
            user_id=current_user.id,
            title=request.form.get("title", "").strip(),
            description=request.form.get("description", "").strip(),
            category=request.form.get("category", "").strip(),
            report_type=request.form.get("report_type", "").strip(),
            location=request.form.get("location", "").strip(),
            date_lost_found=datetime.strptime(
                request.form.get("date_lost_found", "").strip(), DATE_FORMAT
            ).date(),
            status="Active",
            image_filename=image_filename,
        )
        db.session.add(item)
        db.session.commit()

        flash("Your report has been posted. Thank you for helping other students!", "success")
        return redirect(url_for("browse"))

    @app.route("/browse")
    def browse():
        """Public list of reports with search and filters (GET parameters).

        Defaults to showing only Active reports; choosing the "All" or
        "Returned" status filter reveals reports that have been returned.
        """
        filters = _read_filters(request.args, default_status="Active")
        items = (
            _apply_filters(filters)
            .order_by(ItemReport.created_at.desc())
            .all()
        )
        return render_template(
            "browse.html",
            items=items,
            filters=filters,
            report_types=REPORT_TYPES,
            categories=CATEGORIES,
            statuses=STATUSES,
        )

    @app.route("/my-reports")
    @login_required
    def my_reports():
        """Only the reports owned by the logged-in student.

        Accepts the same query parameters as /browse so the dashboard counters
        can link straight to a filtered view (e.g. ?status=Returned).
        """
        filters = _read_filters(request.args, default_status="All")
        items = (
            _apply_filters(filters, ItemReport.query.filter_by(user_id=current_user.id))
            .order_by(ItemReport.created_at.desc())
            .all()
        )
        return render_template("my_reports.html", items=items, filters=filters)

    @app.route("/reports/<int:item_id>/return", methods=["POST"])
    @login_required
    def mark_returned(item_id):
        """Owner-only: flip one of the student's reports to Returned."""
        item = db.session.get(ItemReport, item_id)
        if item is None:
            flash("That report could not be found.", "warning")
            return _back_to(url_for("my_reports"))

        # Only the student who created the report may change it.
        if item.user_id != current_user.id:
            flash("You can only update your own reports.", "danger")
            return _back_to(url_for("browse"))

        if item.status == "Returned":
            # Returned reports can never be changed back to Active.
            flash("That report is already marked as returned.", "info")
        else:
            item.status = "Returned"
            db.session.commit()
            flash(f"\u201c{item.title}\u201d is marked as returned. Nice work!", "success")

        return _back_to(url_for("my_reports"))

    @app.route("/reports/<int:item_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_report(item_id):
        """Owner-only: change the details of one of the student's reports.

        Only the fields the student wrote can change. The owner (user_id) and
        the current status are deliberately left alone, so editing a returned
        report cannot put it back on the active list.
        """
        item = db.session.get(ItemReport, item_id)
        if item is None:
            flash("That report could not be found.", "warning")
            return redirect(url_for("my_reports"))

        # Only the student who created the report may edit it.
        if item.user_id != current_user.id:
            flash("You can only edit your own reports.", "danger")
            return redirect(url_for("browse"))

        if request.method == "GET":
            form = {
                "title": item.title,
                "report_type": item.report_type,
                "category": item.category,
                "description": item.description,
                "location": item.location,
                "date_lost_found": item.date_lost_found.strftime(DATE_FORMAT),
            }
            return render_template(
                "edit_report.html",
                item=item,
                form=form,
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
            )

        errors = _validate_report(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "edit_report.html",
                item=item,
                form=request.form,
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
            )

        new_image, image_error = _save_upload(request.files.get("image"))
        if image_error:
            # Nothing was written, so the current photograph is untouched.
            flash(image_error, "danger")
            return render_template(
                "edit_report.html",
                item=item,
                form=request.form,
                report_types=REPORT_TYPES,
                categories=CATEGORIES,
            )

        previous_image = item.image_filename
        if new_image:
            item.image_filename = new_image

        item.title = request.form.get("title", "").strip()
        item.description = request.form.get("description", "").strip()
        item.category = request.form.get("category", "").strip()
        item.report_type = request.form.get("report_type", "").strip()
        item.location = request.form.get("location", "").strip()
        item.date_lost_found = datetime.strptime(
            request.form.get("date_lost_found", "").strip(), DATE_FORMAT
        ).date()
        # item.user_id and item.status are intentionally unchanged.
        db.session.commit()

        # Only after a successful save is the replaced file removed.
        if new_image and previous_image and previous_image != new_image:
            _delete_image(previous_image)

        flash(f"\u201c{item.title}\u201d has been updated.", "success")
        return redirect(url_for("my_reports"))

    @app.route("/reports/<int:item_id>/delete", methods=["POST"])
    @login_required
    def delete_report(item_id):
        """Owner-only: permanently delete one of the student's reports."""
        item = db.session.get(ItemReport, item_id)
        if item is None:
            flash("That report could not be found.", "warning")
            return redirect(url_for("my_reports"))

        # Only the student who created the report may delete it.
        if item.user_id != current_user.id:
            flash("You can only delete your own reports.", "danger")
            return redirect(url_for("browse"))

        title = _remove_report(item)

        flash(f"\u201c{title}\u201d has been deleted.", "success")
        return redirect(url_for("my_reports"))

    @app.route("/reports/<int:item_id>/claim", methods=["GET", "POST"])
    @login_required
    def claim_report(item_id):
        """Send a claim request for someone else's active Found report."""
        item = db.session.get(ItemReport, item_id)
        if item is None:
            flash("That report could not be found.", "warning")
            return redirect(url_for("browse"))

        problem = _claim_problem(item)
        if problem:
            flash(problem, "warning")
            return redirect(url_for("browse"))

        if request.method == "GET":
            return render_template("claim_form.html", item=item, form={})

        errors = _validate_claim(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("claim_form.html", item=item, form=request.form)

        claim = Claim(
            report_id=item.id,
            claimant_id=current_user.id,
            message=request.form.get("message", "").strip(),
            status="Pending",
        )
        db.session.add(claim)
        db.session.flush()  # gives us claim.id for the notification link

        # Tell the owner about the new claim (never about their own action).
        _notify(
            item.user_id,
            "New claim on your found item",
            f"{current_user.name} claimed \u201c{item.title}\u201d. "
            "Open Incoming Claims to review it.",
            "claim_received",
            claim=claim,
            report=item,
        )
        db.session.commit()

        flash(
            f"Your claim for \u201c{item.title}\u201d has been sent to the owner.",
            "success",
        )
        return redirect(url_for("my_claims"))

    @app.route("/my-claims")
    @login_required
    def my_claims():
        """Every claim this student has sent, newest first."""
        claims = (
            Claim.query.filter_by(claimant_id=current_user.id)
            .order_by(Claim.created_at.desc())
            .all()
        )
        return render_template("my_claims.html", claims=claims)

    @app.route("/incoming-claims")
    @login_required
    def incoming_claims():
        """Claims other students sent for this student's own reports."""
        claims = (
            Claim.query.join(ItemReport, Claim.report_id == ItemReport.id)
            .filter(ItemReport.user_id == current_user.id)
            .order_by(Claim.status != "Pending", Claim.created_at.desc())
            .all()
        )
        pending = sum(1 for claim in claims if claim.status == "Pending")
        return render_template("incoming_claims.html", claims=claims, pending=pending)

    @app.route("/claims/<int:claim_id>/approve", methods=["POST"])
    @login_required
    def approve_claim(claim_id):
        """Owner-only: accept a claim, mark the item returned, close the rest."""
        claim = db.session.get(Claim, claim_id)
        if claim is None:
            flash("That claim could not be found.", "warning")
            return redirect(url_for("incoming_claims"))

        if claim.report.user_id != current_user.id:
            flash("You can only manage claims on your own reports.", "danger")
            return redirect(url_for("browse"))

        if claim.status != "Pending":
            flash("That claim has already been decided.", "info")
            return redirect(url_for("incoming_claims"))

        # One transaction: the approved claim, the report and the other
        # still-pending claims are all saved together.
        claim.status = "Approved"
        claim.report.status = "Returned"

        # Tell the successful claimant; the owner already knows.
        _notify(
            claim.claimant_id,
            "Your claim was approved",
            f"{current_user.name} approved your claim for \u201c{claim.report.title}\u201d. "
            "Arrange a handover with them.",
            "claim_approved",
            claim=claim,
            report=claim.report,
        )

        for other in _pending_claims_for(claim.report_id):
            if other.id != claim.id:
                other.status = "Rejected"
                _notify(
                    other.claimant_id,
                    "Your claim was closed",
                    f"Another student's claim for \u201c{claim.report.title}\u201d was approved "
                    "first, so your claim has been closed.",
                    "claim_rejected_auto",
                    claim=other,
                    report=claim.report,
                )
        db.session.commit()

        flash(
            f"You approved {claim.claimant.name}'s claim. "
            f"\u201c{claim.report.title}\u201d is now marked as returned.",
            "success",
        )
        return redirect(url_for("incoming_claims"))

    @app.route("/claims/<int:claim_id>/reject", methods=["POST"])
    @login_required
    def reject_claim(claim_id):
        """Owner-only: decline a claim; the item stays active."""
        claim = db.session.get(Claim, claim_id)
        if claim is None:
            flash("That claim could not be found.", "warning")
            return redirect(url_for("incoming_claims"))

        if claim.report.user_id != current_user.id:
            flash("You can only manage claims on your own reports.", "danger")
            return redirect(url_for("browse"))

        if claim.status != "Pending":
            flash("That claim has already been decided.", "info")
            return redirect(url_for("incoming_claims"))

        claim.status = "Rejected"
        _notify(
            claim.claimant_id,
            "Your claim was rejected",
            f"{current_user.name} rejected your claim for \u201c{claim.report.title}\u201d. "
            "The item is still available.",
            "claim_rejected",
            claim=claim,
            report=claim.report,
        )
        db.session.commit()

        flash(
            f"You rejected {claim.claimant.name}'s claim. The item stays active.",
            "info",
        )
        return redirect(url_for("incoming_claims"))

    @app.route("/notifications")
    @login_required
    def notifications():
        """The signed-in student's own notifications, newest first."""
        items = (
            Notification.query.filter_by(user_id=current_user.id)
            .order_by(Notification.created_at.desc(), Notification.id.desc())
            .all()
        )
        unread = sum(1 for notification in items if not notification.is_read)
        return render_template("notifications.html", notifications=items, unread=unread)

    @app.route("/notifications/<int:notification_id>/read", methods=["POST"])
    @login_required
    def mark_notification_read(notification_id):
        """Mark one of your own notifications as read."""
        note = db.session.get(Notification, notification_id)
        if note is None or note.user_id != current_user.id:
            # Same answer for "missing" and "someone else's" so nothing leaks.
            flash("That notification could not be found.", "warning")
            return redirect(url_for("notifications"))

        if not note.is_read:
            note.is_read = True
            db.session.commit()

        return redirect(url_for("notifications"))

    @app.route("/notifications/read-all", methods=["POST"])
    @login_required
    def mark_all_notifications_read():
        """Mark every unread notification of the signed-in student as read."""
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update(
            {"is_read": True}, synchronize_session=False
        )
        db.session.commit()
        flash("All your notifications are marked as read.", "success")
        return redirect(url_for("notifications"))

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        """Administrator overview with real counters and recent activity."""
        stats = {
            "students": User.query.count(),
            "lost": ItemReport.query.filter_by(report_type="Lost").count(),
            "found": ItemReport.query.filter_by(report_type="Found").count(),
            "active": ItemReport.query.filter_by(status="Active").count(),
            "returned": ItemReport.query.filter_by(status="Returned").count(),
            "claims": Claim.query.count(),
            "pending": Claim.query.filter_by(status="Pending").count(),
            "notifications": Notification.query.count(),
        }
        recent_users = (
            User.query.order_by(User.created_at.desc(), User.id.desc()).limit(5).all()
        )
        recent_reports = (
            ItemReport.query.order_by(ItemReport.created_at.desc(), ItemReport.id.desc())
            .limit(5)
            .all()
        )
        recent_claims = (
            Claim.query.order_by(Claim.created_at.desc(), Claim.id.desc()).limit(5).all()
        )
        return render_template(
            "admin_dashboard.html",
            stats=stats,
            recent_users=recent_users,
            recent_reports=recent_reports,
            recent_claims=recent_claims,
        )

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        """Every account with its role and status."""
        users = User.query.order_by(User.created_at.desc(), User.id.desc()).all()
        active_admins = User.query.filter_by(is_admin=True, is_active=True).count()
        return render_template(
            "admin_users.html", users=users, active_admins=active_admins
        )

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @admin_required
    def admin_toggle_user(user_id):
        """Deactivate or reactivate one account. Roles are never changed here."""
        target = db.session.get(User, user_id)
        if target is None:
            flash("That account could not be found.", "warning")
            return redirect(url_for("admin_users"))

        if target.is_active and target.is_admin:
            active_admins = User.query.filter_by(is_admin=True, is_active=True).count()
            if active_admins <= 1:
                flash("The last active administrator cannot be deactivated.", "danger")
                return redirect(url_for("admin_users"))

        if target.id == current_user.id:
            flash("You cannot deactivate your own account.", "danger")
            return redirect(url_for("admin_users"))

        # Only the active flag changes: is_admin is never read from a form.
        target.is_active = not target.is_active
        db.session.commit()

        if target.is_active:
            flash(f"{target.name}'s account has been reactivated.", "success")
        else:
            flash(f"{target.name}'s account has been deactivated.", "info")
        return redirect(url_for("admin_users"))

    @app.route("/admin/reports")
    @admin_required
    def admin_reports():
        """Moderation list of every report in the portal."""
        reports = ItemReport.query.order_by(
            ItemReport.created_at.desc(), ItemReport.id.desc()
        ).all()
        return render_template("admin_reports.html", reports=reports)

    @app.route("/admin/reports/<int:item_id>/delete", methods=["POST"])
    @admin_required
    def admin_delete_report(item_id):
        """Remove an inappropriate report with its photo, claims and alerts."""
        item = db.session.get(ItemReport, item_id)
        if item is None:
            flash("That report could not be found.", "warning")
            return redirect(url_for("admin_reports"))

        title = _remove_report(item)
        flash(f"\u201c{title}\u201d has been removed from the portal.", "success")
        return redirect(url_for("admin_reports"))

    @app.route("/admin/claims")
    @admin_required
    def admin_claims():
        """Read-only oversight of claims; owners still make the decisions."""
        status = (request.args.get("status") or "All").strip()
        if status not in CLAIM_STATUSES:
            status = "All"

        query = Claim.query
        if status != "All":
            query = query.filter_by(status=status)
        claims = query.order_by(Claim.created_at.desc(), Claim.id.desc()).all()
        counts = {
            state: Claim.query.filter_by(status=state).count()
            for state in CLAIM_STATUSES
        }
        return render_template(
            "admin_claims.html",
            claims=claims,
            status=status,
            statuses=CLAIM_STATUSES,
            counts=counts,
        )

    @app.cli.command("promote-admin")
    @click.argument("email")
    def promote_admin_command(email):
        """Give an existing account administrator rights.

        Example: flask --app app promote-admin student@college.edu
        """
        account = User.query.filter_by(email=email.strip().lower()).first()
        if account is None:
            click.echo(f"No account found for {email}. Register the account first.")
            return
        if account.is_admin:
            click.echo(f"{account.email} is already an administrator.")
            return
        account.is_admin = True
        db.session.commit()
        click.echo(f"{account.email} is now an administrator.")

    @app.errorhandler(413)
    def upload_too_large(error):
        """A request beyond the hard cap: explain it instead of showing a 413."""
        flash("That upload is too large. The maximum image size is 5 MB.", "danger")
        return redirect(url_for("report"))

    @app.context_processor
    def inject_phase_note():
        """Expose the phase label and the student's unread notification count."""
        unread = 0
        if current_user.is_authenticated:
            unread = Notification.query.filter_by(
                user_id=current_user.id, is_read=False
            ).count()
        return {"PHASE": 10, "unread_notifications": unread}


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
