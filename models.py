from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin


db = SQLAlchemy()


# --------------------------------
# USER MODEL
# --------------------------------

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

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )


# --------------------------------
# SECURE FILE MODEL
# --------------------------------

class SecureFile(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    encrypted_filename = db.Column(
        db.String(255),
        nullable=False
    )

    file_hash = db.Column(
        db.String(64),
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref="secure_files"
    )


# --------------------------------
# ACTIVITY LOG MODEL
# --------------------------------

class ActivityLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    action = db.Column(
        db.String(255),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref="activity_logs"
    )