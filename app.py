from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import os
import csv
from io import BytesIO, StringIO
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_, text
from sqlalchemy.exc import IntegrityError
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pageant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Default admin credentials (override with environment variables)
DEFAULT_ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'adminITD2026')
APP_TITLE = 'MSEUF Catanauan Tabulation System'

DIVISION_VALUES = ['male', 'female', 'unspecified']
DIVISION_LABELS = {
    'male': 'Male',
    'female': 'Female',
    'unspecified': 'Unassigned'
}

db = SQLAlchemy(app)

ROLE_ADMIN = 'admin'
ROLE_TABULATOR = 'tabulator'

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Please login to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            if session.get('role') not in roles:
                flash('You do not have access to that page.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

def admin_required(f):
    return role_required(ROLE_ADMIN)(f)

def scoring_required(f):
    return role_required(ROLE_TABULATOR)(f)

def scoring_view_required(f):
    return role_required(ROLE_ADMIN, ROLE_TABULATOR)(f)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(30), nullable=False, default=ROLE_ADMIN)
    portal_id = db.Column(db.Integer, db.ForeignKey('competition_portal.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    portal = db.relationship('CompetitionPortal')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    portal_id = db.Column(db.Integer, db.ForeignKey('competition_portal.id'), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
    round = db.Column(db.String(20), nullable=False, default='round1')
    order = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    criteria = db.relationship('Criteria', backref='category', lazy=True, cascade='all, delete-orphan')
    scores = db.relationship('Score', backref='category', lazy=True, cascade='all, delete-orphan')

class Criteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    order = db.Column(db.Integer)

class Contestant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    portal_id = db.Column(db.Integer, db.ForeignKey('competition_portal.id'), nullable=True)
    number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    division = db.Column(db.String(20), nullable=False, default='unspecified')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='contestant', lazy=True, cascade='all, delete-orphan')

class Judge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    portal_id = db.Column(db.Integer, db.ForeignKey('competition_portal.id'), nullable=True)
    number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='judge', lazy=True, cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('portal_id', 'number', name='uq_judge_portal_number'),
    )

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contestant_id = db.Column(db.Integer, db.ForeignKey('contestant.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'), nullable=False)
    judge_id = db.Column(db.Integer, db.ForeignKey('judge.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    criteria_ref = db.relationship('Criteria')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    competition_title = db.Column(db.String(200), nullable=False, default=APP_TITLE)
    event_title = db.Column(db.String(200), nullable=True)
    show_category_winners = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CompetitionPortal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EventHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_title = db.Column(db.String(200), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('competition_portal.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    portal = db.relationship('CompetitionPortal')

class ArchivedEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    closed_at = db.Column(db.DateTime, default=datetime.utcnow)

class ArchivedPortal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)

    event = db.relationship('ArchivedEvent')

class ArchivedCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('archived_portal.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
    round = db.Column(db.String(20), nullable=False, default='round1')
    order = db.Column(db.Integer)

    portal = db.relationship('ArchivedPortal')

class ArchivedCriteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('archived_portal.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('archived_category.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    order = db.Column(db.Integer)

class ArchivedContestant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('archived_portal.id'), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    division = db.Column(db.String(20), nullable=False, default='unspecified')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ArchivedJudge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('archived_portal.id'), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ArchivedScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('archived_event.id'), nullable=False)
    portal_id = db.Column(db.Integer, db.ForeignKey('archived_portal.id'), nullable=False)
    contestant_id = db.Column(db.Integer, db.ForeignKey('archived_contestant.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('archived_category.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('archived_criteria.id'), nullable=False)
    judge_id = db.Column(db.Integer, db.ForeignKey('archived_judge.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Ensure there is at least one admin user
def ensure_default_admin():
    if User.query.first() is None:
        admin_user = User(username=DEFAULT_ADMIN_USERNAME)
        admin_user.role = ROLE_ADMIN
        admin_user.set_password(DEFAULT_ADMIN_PASSWORD)
        db.session.add(admin_user)
        db.session.commit()

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return User.query.get(user_id)

_schema_checked = False

def ensure_schema_updates():
    columns = db.session.execute(text('PRAGMA table_info(category)')).all()
    column_names = {col[1] for col in columns}
    if 'round' not in column_names:
        db.session.execute(text("ALTER TABLE category ADD COLUMN round TEXT DEFAULT 'round1'"))
        db.session.execute(text("UPDATE category SET round='round1' WHERE round IS NULL"))
        db.session.commit()

    user_columns = db.session.execute(text('PRAGMA table_info(user)')).all()
    user_column_names = {col[1] for col in user_columns}
    if 'role' not in user_column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'admin'"))
        db.session.execute(text("UPDATE user SET role='admin' WHERE role IS NULL"))
        db.session.commit()
    if 'portal_id' not in user_column_names:
        db.session.execute(text('ALTER TABLE user ADD COLUMN portal_id INTEGER'))
        db.session.commit()

    contestant_columns = db.session.execute(text('PRAGMA table_info(contestant)')).all()
    contestant_column_names = {col[1] for col in contestant_columns}
    if 'division' not in contestant_column_names:
        db.session.execute(text("ALTER TABLE contestant ADD COLUMN division TEXT DEFAULT 'unspecified'"))
        db.session.execute(text("UPDATE contestant SET division='unspecified' WHERE division IS NULL"))
        db.session.commit()
    else:
        db.session.execute(text(
            "UPDATE contestant "
            "SET division = CASE lower(division) "
            "WHEN 'male' THEN 'male' "
            "WHEN 'female' THEN 'female' "
            "WHEN 'unspecified' THEN 'unspecified' "
            "ELSE 'unspecified' "
            "END"
        ))
        db.session.commit()

    index_rows = db.session.execute(text("PRAGMA index_list('contestant')")).all()
    rebuild_contestant = False
    for index in index_rows:
        if not index[2]:
            continue
        index_name = index[1]
        index_info = db.session.execute(text(f"PRAGMA index_info('{index_name}')")).all()
        index_columns = [row[2] for row in index_info]
        if index_columns == ['number']:
            if index_name.startswith('sqlite_autoindex'):
                rebuild_contestant = True
            else:
                try:
                    db.session.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    if rebuild_contestant:
        try:
            db.session.execute(text('PRAGMA foreign_keys=off'))
            db.session.execute(text('ALTER TABLE contestant RENAME TO contestant_old'))
            db.session.execute(text(
                "CREATE TABLE contestant ("
                "id INTEGER PRIMARY KEY, "
                "number INTEGER NOT NULL, "
                "name TEXT NOT NULL, "
                "division TEXT NOT NULL DEFAULT 'unspecified', "
                "created_at DATETIME"
                ")"
            ))
            db.session.execute(text(
                "INSERT INTO contestant (id, number, name, division, created_at) "
                "SELECT id, number, name, COALESCE(division, 'unspecified'), created_at FROM contestant_old"
            ))
            db.session.execute(text('DROP TABLE contestant_old'))
            db.session.execute(text('PRAGMA foreign_keys=on'))
            db.session.commit()
        except Exception:
            db.session.rollback()

    category_columns = db.session.execute(text('PRAGMA table_info(category)')).all()
    category_column_names = {col[1] for col in category_columns}
    if 'portal_id' not in category_column_names:
        db.session.execute(text('ALTER TABLE category ADD COLUMN portal_id INTEGER'))
        db.session.commit()

    if 'portal_id' not in contestant_column_names:
        db.session.execute(text('ALTER TABLE contestant ADD COLUMN portal_id INTEGER'))
        db.session.commit()

    judge_columns = db.session.execute(text('PRAGMA table_info(judge)')).all()
    judge_column_names = {col[1] for col in judge_columns}
    if 'portal_id' not in judge_column_names:
        db.session.execute(text('ALTER TABLE judge ADD COLUMN portal_id INTEGER'))
        db.session.commit()

    index_rows = db.session.execute(text("PRAGMA index_list('judge')")).all()
    rebuild_judge = False
    for index in index_rows:
        if not index[2]:
            continue
        index_name = index[1]
        index_info = db.session.execute(text(f"PRAGMA index_info('{index_name}')")).all()
        index_columns = [row[2] for row in index_info]
        if index_columns == ['number']:
            if index_name.startswith('sqlite_autoindex'):
                rebuild_judge = True
            else:
                try:
                    db.session.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    if rebuild_judge:
        try:
            db.session.execute(text('PRAGMA foreign_keys=off'))
            db.session.execute(text('ALTER TABLE judge RENAME TO judge_old'))
            db.session.execute(text(
                "CREATE TABLE judge ("
                "id INTEGER PRIMARY KEY, "
                "portal_id INTEGER, "
                "number INTEGER NOT NULL, "
                "name TEXT NOT NULL, "
                "created_at DATETIME, "
                "UNIQUE (portal_id, number)"
                ")"
            ))
            db.session.execute(text(
                "INSERT INTO judge (id, portal_id, number, name, created_at) "
                "SELECT id, portal_id, number, name, created_at FROM judge_old"
            ))
            db.session.execute(text('DROP TABLE judge_old'))
            db.session.execute(text('PRAGMA foreign_keys=on'))
            db.session.commit()
        except Exception:
            db.session.rollback()

    settings_columns = db.session.execute(text('PRAGMA table_info(settings)')).all()
    settings_column_names = {col[1] for col in settings_columns}
    if 'event_title' not in settings_column_names:
        db.session.execute(text('ALTER TABLE settings ADD COLUMN event_title TEXT'))
        db.session.commit()

@app.before_request
def ensure_schema_once():
    global _schema_checked
    if _schema_checked:
        return
    try:
        ensure_schema_updates()
    finally:
        _schema_checked = True

def get_round_categories(round_name, portal_id=None):
    query = Category.query.filter_by(round=round_name)
    if portal_id is not None:
        query = query.filter_by(portal_id=portal_id)
    return query.order_by(Category.order).all()

def get_active_portal_id():
    user = get_current_user()
    if user and user.role == ROLE_TABULATOR:
        return user.portal_id
    return session.get('portal_id')

def require_active_portal(redirect_endpoint):
    portal_id = get_active_portal_id()
    if portal_id:
        return portal_id
    if session.get('role') == ROLE_TABULATOR:
        flash('No portal assigned. Please contact an administrator.', 'error')
        return None
    flash('Select a competition portal first.', 'warning')
    return None

def normalize_division(value):
    value = (value or '').strip().lower()
    if value in DIVISION_VALUES:
        return value
    return 'unspecified'

def get_divisions(portal_id=None):
    query = db.session.query(Contestant.division)
    if portal_id is not None:
        query = query.filter(Contestant.portal_id == portal_id)
    raw_divisions = [row[0] for row in query.distinct().all() if row[0]]
    divisions = list({normalize_division(value) for value in raw_divisions})
    if not divisions:
        return []
    ordered = [value for value in DIVISION_VALUES if value in divisions]
    extras = sorted(value for value in divisions if value not in DIVISION_VALUES)
    return ordered + extras

def get_contestants_by_division(division, portal_id=None):
    query = Contestant.query.filter_by(division=division)
    if portal_id is not None:
        query = query.filter(Contestant.portal_id == portal_id)
    return query.order_by(Contestant.number).all()

def get_archived_round_categories(round_name, event_id, portal_id):
    return ArchivedCategory.query.filter_by(
        event_id=event_id,
        portal_id=portal_id,
        round=round_name
    ).order_by(ArchivedCategory.order).all()

def get_archived_divisions(event_id, portal_id):
    query = db.session.query(ArchivedContestant.division).filter_by(
        event_id=event_id,
        portal_id=portal_id
    )
    raw_divisions = [row[0] for row in query.distinct().all() if row[0]]
    divisions = list({normalize_division(value) for value in raw_divisions})
    if not divisions:
        return []
    ordered = [value for value in DIVISION_VALUES if value in divisions]
    extras = sorted(value for value in divisions if value not in DIVISION_VALUES)
    return ordered + extras

def get_archived_contestants_by_division(division, event_id, portal_id):
    return ArchivedContestant.query.filter_by(
        event_id=event_id,
        portal_id=portal_id,
        division=division
    ).order_by(ArchivedContestant.number).all()

def compute_archived_results_for_categories(categories, contestants):
    results_data = []
    for contestant in contestants:
        total_score = 0
        category_scores = {}

        for category in categories:
            criteria = ArchivedCriteria.query.filter_by(category_id=category.id).all()
            category_total = 0

            for criterion in criteria:
                scores = ArchivedScore.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    criteria_id=criterion.id
                ).all()

                if scores:
                    avg_score = sum(s.score for s in scores) / len(scores) if scores else 0
                    weighted_score = (avg_score * 10) * (criterion.percentage / 100)
                    category_total += weighted_score

            final_category_score = category_total * (category.percentage / 100)
            category_scores[category.name] = {
                'raw': category_total,
                'weighted': final_category_score,
                'locked': category.is_locked
            }
            total_score += final_category_score

        results_data.append({
            'contestant': contestant,
            'category_scores': category_scores,
            'total_score': total_score
        })

    results_data.sort(key=lambda x: x['total_score'], reverse=True)
    for idx, result in enumerate(results_data, 1):
        result['rank'] = idx

    return results_data

def compute_archived_results_by_division(categories, contestants_by_division):
    results_by_division = {}
    for division, contestants in contestants_by_division.items():
        if categories and contestants:
            results_by_division[division] = compute_archived_results_for_categories(categories, contestants)
        else:
            results_by_division[division] = []
    return results_by_division

def compute_archived_judge_breakdown(categories, contestants, judges):
    breakdown = {}
    for category in categories:
        criteria = ArchivedCriteria.query.filter_by(category_id=category.id).all()
        if not criteria:
            continue
        category_breakdown = {}
        for contestant in contestants:
            per_judge = {}
            for judge in judges:
                scores = ArchivedScore.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    judge_id=judge.id
                ).all()
                if scores:
                    score_map = {s.criteria_id: s.score for s in scores}
                    total = 0
                    for criterion in criteria:
                        score_value = score_map.get(criterion.id)
                        if score_value is None:
                            continue
                        total += (score_value * 10) * (criterion.percentage / 100)
                else:
                    total = 0
                per_judge[judge.id] = total
            category_breakdown[contestant.id] = per_judge
        breakdown[category.id] = category_breakdown
    return breakdown

def compute_live_judge_breakdown(categories, contestants, judges):
    breakdown = {}
    for category in categories:
        criteria = Criteria.query.filter_by(category_id=category.id).all()
        if not criteria:
            continue
        category_breakdown = {}
        for contestant in contestants:
            per_judge = {}
            for judge in judges:
                scores = Score.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    judge_id=judge.id
                ).all()
                if scores:
                    score_map = {s.criteria_id: s.score for s in scores}
                    total = 0
                    for criterion in criteria:
                        score_value = score_map.get(criterion.id)
                        if score_value is None:
                            continue
                        total += (score_value * 10) * (criterion.percentage / 100)
                else:
                    total = 0
                per_judge[judge.id] = total
            category_breakdown[contestant.id] = per_judge
        breakdown[category.id] = category_breakdown
    return breakdown

def compute_results_by_division(categories, contestants_by_division):
    results_by_division = {}
    for division, contestants in contestants_by_division.items():
        if categories and contestants:
            results_by_division[division] = compute_results_for_categories(categories, contestants)
        else:
            results_by_division[division] = []
    return results_by_division

def get_top_contestants_by_division(results_by_division, limit):
    top_by_division = {}
    for division, results in results_by_division.items():
        top_by_division[division] = [r['contestant'] for r in results[:limit]]
    return top_by_division

def flatten_contestants(contestants_by_division):
    return [contestant for contestants in contestants_by_division.values() for contestant in contestants]

def compute_results_for_categories(categories, contestants):
    results_data = []
    for contestant in contestants:
        total_score = 0
        category_scores = {}

        for category in categories:
            criteria = Criteria.query.filter_by(category_id=category.id).all()
            category_total = 0

            for criterion in criteria:
                scores = Score.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    criteria_id=criterion.id
                ).all()

                if scores:
                    avg_score = sum(s.score for s in scores) / len(scores) if scores else 0
                    weighted_score = (avg_score * 10) * (criterion.percentage / 100)
                    category_total += weighted_score

            final_category_score = category_total * (category.percentage / 100)
            category_scores[category.name] = {
                'raw': category_total,
                'weighted': final_category_score,
                'locked': category.is_locked
            }
            total_score += final_category_score

        results_data.append({
            'contestant': contestant,
            'category_scores': category_scores,
            'total_score': total_score
        })

    results_data.sort(key=lambda x: x['total_score'], reverse=True)
    for idx, result in enumerate(results_data, 1):
        result['rank'] = idx

    return results_data

def log_event(action, details=None, user=None):
    try:
        username = None
        user_id = None
        if user:
            user_id = user.id
            username = user.username
        else:
            user_id = session.get('user_id')
            username = session.get('username')
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        entry = AuditLog(
            user_id=user_id,
            username=username or 'anonymous',
            action=action,
            details=details,
            ip_address=ip_address
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

def parse_date(value, end_of_day=False):
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, '%Y-%m-%d')
        if end_of_day:
            return parsed.replace(hour=23, minute=59, second=59)
        return parsed
    except ValueError:
        return None

def build_log_query(params):
    query = AuditLog.query
    username = params.get('username')
    action = params.get('action')
    search = params.get('q')
    start_date = parse_date(params.get('start_date'))
    end_date = parse_date(params.get('end_date'), end_of_day=True)

    if username:
        query = query.filter(AuditLog.username == username)
    if action:
        query = query.filter(AuditLog.action == action)
    if search:
        like_term = f"%{search}%"
        query = query.filter(or_(
            AuditLog.username.ilike(like_term),
            AuditLog.action.ilike(like_term),
            AuditLog.details.ilike(like_term)
        ))
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)

    return query

# Context processor to make competition title available to all templates
@app.context_processor
def inject_competition_title():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title=APP_TITLE, event_title=APP_TITLE)
        db.session.add(settings)
        db.session.commit()
    portals = []
    selected_portal = None
    if session.get('role') == ROLE_ADMIN:
        portals = CompetitionPortal.query.order_by(CompetitionPortal.name.asc()).all()
        selected_portal_id = session.get('portal_id')
        if selected_portal_id:
            selected_portal = CompetitionPortal.query.get(selected_portal_id)
    return dict(
        competition_title=APP_TITLE,
        nav_portals=portals,
        nav_selected_portal=selected_portal
    )

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        ensure_default_admin()
        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!', 'success')
            log_event('login_success', f'username={username}', user=user)
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            if user.role == ROLE_TABULATOR:
                return redirect(url_for('tabulator_dashboard'))
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            log_event('login_failed', f'username={username}')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_event('logout', f'username={user.username}', user=user)
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    params = request.args.to_dict()
    logs = build_log_query(params).order_by(AuditLog.created_at.desc()).limit(200).all()
    usernames = [row[0] for row in db.session.query(AuditLog.username).distinct().order_by(AuditLog.username.asc()).all() if row[0]]
    actions = [row[0] for row in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action.asc()).all() if row[0]]
    return render_template('admin_logs.html', logs=logs, usernames=usernames, actions=actions, filters=params)

@app.route('/admin/logs.csv')
@admin_required
def admin_logs_csv():
    params = request.args.to_dict()
    logs = build_log_query(params).order_by(AuditLog.created_at.desc()).all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Time', 'User', 'Action', 'Details', 'IP'])
    for log in logs:
        writer.writerow([
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.username,
            log.action,
            log.details or '',
            log.ip_address or ''
        ])

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    return response

@app.route('/admin/logs.pdf')
@admin_required
def admin_logs_pdf():
    params = request.args.to_dict()
    logs = build_log_query(params).order_by(AuditLog.created_at.desc()).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    styles = getSampleStyleSheet()

    title = Paragraph('<b>Audit Logs</b>', styles['Heading2'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    table_data = [['Time', 'User', 'Action', 'Details', 'IP']]
    for log in logs:
        table_data.append([
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.username,
            log.action,
            (log.details or '-')[:120],
            log.ip_address or '-'
        ])

    table = Table(table_data, colWidths=[1.4*inch, 1.1*inch, 1.3*inch, 2.6*inch, 1.1*inch])
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER')
    ]))
    elements.append(table)

    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.pdf'
    return response

@app.route('/admin/users')
@admin_required
def admin_users():
    ensure_default_admin()
    current_user = get_current_user()
    users = User.query.order_by(User.username.asc()).all()
    portals = CompetitionPortal.query.order_by(CompetitionPortal.name.asc()).all()
    return render_template(
        'admin_users.html',
        users=users,
        portals=portals,
        current_user=current_user,
        default_admin_username=DEFAULT_ADMIN_USERNAME
    )

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_users_create():
    ensure_default_admin()
    current_user = get_current_user()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin_users'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('admin_users'))

    role = request.form.get('role', ROLE_ADMIN)
    portal_id_raw = request.form.get('portal_id')
    portal_id = int(portal_id_raw) if portal_id_raw else None

    if role not in [ROLE_ADMIN, ROLE_TABULATOR]:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('admin_users'))

    if role == ROLE_TABULATOR and not portal_id:
        flash('Tabulator accounts must be assigned to a competition portal.', 'error')
        return redirect(url_for('admin_users'))

    if portal_id and not CompetitionPortal.query.get(portal_id):
        flash('Selected portal does not exist.', 'error')
        return redirect(url_for('admin_users'))

    user = User(username=username, role=role, portal_id=portal_id)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    log_event('admin_user_created', f'created_username={username}', user=current_user)
    flash('User created successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/reset', methods=['POST'])
@admin_required
def admin_users_reset(user_id):
    ensure_default_admin()
    current_user = get_current_user()
    new_password = request.form.get('new_password', '')
    if not new_password:
        flash('New password is required.', 'error')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    user.set_password(new_password)
    db.session.commit()
    log_event('admin_user_password_reset', f'reset_username={user.username}', user=current_user)
    flash('Password reset successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_users_toggle(user_id):
    ensure_default_admin()
    current_user = get_current_user()
    if current_user and current_user.id == user_id:
        flash('You cannot deactivate your own account.', 'error')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    log_event('admin_user_status_toggled', f'target_username={user.username} status={user.is_active}', user=current_user)
    flash('User status updated.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_users_delete(user_id):
    ensure_default_admin()
    current_user = get_current_user()
    if current_user and current_user.id == user_id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    if user.username == DEFAULT_ADMIN_USERNAME:
        flash('You cannot delete the main admin account.', 'error')
        return redirect(url_for('admin_users'))

    if user.role == ROLE_ADMIN:
        remaining_admins = User.query.filter(User.role == ROLE_ADMIN, User.id != user.id).count()
        if remaining_admins == 0:
            flash('At least one admin account must remain.', 'error')
            return redirect(url_for('admin_users'))

    AuditLog.query.filter_by(user_id=user.id).update({AuditLog.user_id: None})
    EventHistory.query.filter_by(created_by=user.id).update({EventHistory.created_by: None})

    db.session.delete(user)
    db.session.commit()
    log_event('admin_user_deleted', f'deleted_username={user.username}', user=current_user)
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/password', methods=['GET', 'POST'])
@admin_required
def change_password():
    user = get_current_user()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_settings'))

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required.', 'error')
            return redirect(url_for('change_password'))

        if not user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))

        user.set_password(new_password)
        db.session.commit()
        log_event('password_changed', f'username={user.username}', user=user)
        flash('Password updated successfully.', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('change_password.html')

@app.route('/')
def index():
    if session.get('logged_in') and session.get('role') == ROLE_TABULATOR:
        return redirect(url_for('tabulator_dashboard'))
    portals = CompetitionPortal.query.filter_by(is_active=True).order_by(CompetitionPortal.name.asc()).all()
    return render_template('index.html', portals=portals)

@app.route('/portal/<int:portal_id>')
def portal_public(portal_id):
    portal = CompetitionPortal.query.get_or_404(portal_id)
    if not portal.is_active:
        flash('This competition portal is not active.', 'warning')
        return redirect(url_for('index'))
    return render_template('portal_public.html', portal=portal)

@app.route('/tabulator')
@scoring_required
def tabulator_dashboard():
    user = get_current_user()
    if not user or user.role != ROLE_TABULATOR:
        return redirect(url_for('index'))
    portal = CompetitionPortal.query.get(user.portal_id) if user.portal_id else None
    return render_template('tabulator_dashboard.html', portal=portal)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(
            competition_title=APP_TITLE,
            event_title=APP_TITLE,
            show_category_winners=False
        )
        db.session.add(settings)
        db.session.commit()
    return render_template('admin_settings.html', show_category_winners=settings.show_category_winners)

@app.route('/admin/competition', methods=['GET', 'POST'])
@admin_required
def manage_competition():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Competition name is required.', 'error')
        elif CompetitionPortal.query.filter_by(name=name).first():
            flash('Competition name already exists.', 'error')
        else:
            portal = CompetitionPortal(name=name)
            db.session.add(portal)
            db.session.commit()
            flash('Competition portal created successfully.', 'success')
            return redirect(url_for('manage_competition'))

    portals = CompetitionPortal.query.order_by(CompetitionPortal.created_at.desc()).all()
    settings = Settings.query.first()
    event_title = None
    if settings:
        event_title = settings.event_title or APP_TITLE
    return render_template('manage_competition.html', portals=portals, event_title=event_title)

@app.route('/admin/event/close', methods=['POST'])
@admin_required
def close_event():
    settings = Settings.query.first()
    if not settings:
        flash('Event settings not found.', 'error')
        return redirect(url_for('manage_competition'))

    event_title = (settings.event_title or APP_TITLE or '').strip()
    if not event_title:
        flash('Event title is required before closing.', 'error')
        return redirect(url_for('competition_settings'))

    portals = CompetitionPortal.query.order_by(CompetitionPortal.created_at.asc()).all()
    if not portals:
        flash('No competition portals to archive.', 'error')
        return redirect(url_for('manage_competition'))

    archived_event = ArchivedEvent(title=event_title)
    db.session.add(archived_event)
    db.session.flush()

    portal_map = {}
    for portal in portals:
        archived_portal = ArchivedPortal(event_id=archived_event.id, name=portal.name)
        db.session.add(archived_portal)
        db.session.flush()
        portal_map[portal.id] = archived_portal.id

    category_map = {}
    criteria_map = {}
    contestant_map = {}
    judge_map = {}
    category_portal_map = {}

    categories = Category.query.order_by(Category.order).all()
    for category in categories:
        category_portal_map[category.id] = category.portal_id
        archived_category = ArchivedCategory(
            event_id=archived_event.id,
            portal_id=portal_map.get(category.portal_id),
            name=category.name,
            percentage=category.percentage,
            is_locked=category.is_locked,
            round=category.round,
            order=category.order
        )
        db.session.add(archived_category)
        db.session.flush()
        category_map[category.id] = archived_category.id

    criteria_rows = Criteria.query.order_by(Criteria.order).all()
    for criterion in criteria_rows:
        category_portal_id = category_portal_map.get(criterion.category_id)
        archived_criteria = ArchivedCriteria(
            event_id=archived_event.id,
            portal_id=portal_map.get(category_portal_id),
            category_id=category_map.get(criterion.category_id),
            name=criterion.name,
            percentage=criterion.percentage,
            order=criterion.order
        )
        db.session.add(archived_criteria)
        db.session.flush()
        criteria_map[criterion.id] = archived_criteria.id

    contestants = Contestant.query.order_by(Contestant.number).all()
    for contestant in contestants:
        archived_contestant = ArchivedContestant(
            event_id=archived_event.id,
            portal_id=portal_map.get(contestant.portal_id),
            number=contestant.number,
            name=contestant.name,
            division=contestant.division,
            created_at=contestant.created_at
        )
        db.session.add(archived_contestant)
        db.session.flush()
        contestant_map[contestant.id] = archived_contestant.id

    judges = Judge.query.order_by(Judge.number).all()
    for judge in judges:
        archived_judge = ArchivedJudge(
            event_id=archived_event.id,
            portal_id=portal_map.get(judge.portal_id),
            number=judge.number,
            name=judge.name,
            created_at=judge.created_at
        )
        db.session.add(archived_judge)
        db.session.flush()
        judge_map[judge.id] = archived_judge.id

    scores = Score.query.all()
    for score in scores:
        category_portal_id = category_portal_map.get(score.category_id)
        archived_score = ArchivedScore(
            event_id=archived_event.id,
            portal_id=portal_map.get(category_portal_id),
            contestant_id=contestant_map.get(score.contestant_id),
            category_id=category_map.get(score.category_id),
            criteria_id=criteria_map.get(score.criteria_id),
            judge_id=judge_map.get(score.judge_id),
            score=score.score,
            created_at=score.created_at
        )
        db.session.add(archived_score)

    db.session.commit()

    Score.query.delete()
    Criteria.query.delete()
    Category.query.delete()
    Contestant.query.delete()
    Judge.query.delete()
    CompetitionPortal.query.delete()
    db.session.commit()

    session.pop('portal_id', None)
    log_event('event_closed', f'event_title={event_title} event_id={archived_event.id}')
    flash('Event closed and archived. All portals were cleared.', 'success')
    return redirect(url_for('admin_history'))

@app.route('/admin/portal/select', methods=['POST'])
@admin_required
def select_portal():
    portal_id_raw = request.form.get('portal_id', '').strip()
    if not portal_id_raw:
        session.pop('portal_id', None)
        flash('Portal selection cleared.', 'success')
        return redirect(request.referrer or url_for('index'))

    try:
        portal_id = int(portal_id_raw)
    except ValueError:
        flash('Invalid portal selection.', 'error')
        return redirect(request.referrer or url_for('manage_competition'))

    portal = CompetitionPortal.query.get(portal_id)
    if not portal:
        flash('Selected portal does not exist.', 'error')
        return redirect(request.referrer or url_for('manage_competition'))

    session['portal_id'] = portal.id
    flash(f'Active portal set to {portal.name}.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/competition/<int:portal_id>/toggle', methods=['POST'])
@admin_required
def toggle_competition_portal(portal_id):
    portal = CompetitionPortal.query.get_or_404(portal_id)
    portal.is_active = not portal.is_active
    db.session.commit()
    status = 'active' if portal.is_active else 'inactive'
    log_event('competition_portal_toggled', f'portal_id={portal.id} status={status}')
    flash(f'Competition portal set to {status}.', 'success')
    return redirect(url_for('manage_competition'))

@app.route('/admin/history')
@admin_required
def admin_history():
    events = ArchivedEvent.query.order_by(ArchivedEvent.closed_at.desc()).all()
    portal_map = {}
    if events:
        event_ids = [event.id for event in events]
        portals = ArchivedPortal.query.filter(ArchivedPortal.event_id.in_(event_ids)).order_by(ArchivedPortal.name.asc()).all()
        for portal in portals:
            portal_map.setdefault(portal.event_id, []).append(portal)
    return render_template('admin_history.html', events=events, portal_map=portal_map)

@app.route('/history/<int:event_id>/portal/<int:portal_id>/results')
@admin_required
def history_results(event_id, portal_id):
    event = ArchivedEvent.query.get_or_404(event_id)
    portal = ArchivedPortal.query.filter_by(id=portal_id, event_id=event_id).first_or_404()

    categories = ArchivedCategory.query.filter_by(event_id=event_id, portal_id=portal_id).order_by(ArchivedCategory.order).all()
    judges = ArchivedJudge.query.filter_by(event_id=event_id, portal_id=portal_id).order_by(ArchivedJudge.number).all()

    round1_categories = get_archived_round_categories('round1', event_id, portal_id)
    round2_categories = get_archived_round_categories('round2', event_id, portal_id)
    round3_categories = get_archived_round_categories('round3', event_id, portal_id)

    round1_locked = bool(round1_categories) and all(cat.is_locked for cat in round1_categories)
    round2_locked = bool(round2_categories) and all(cat.is_locked for cat in round2_categories)
    round3_locked = bool(round3_categories) and all(cat.is_locked for cat in round3_categories)
    all_locked = bool(categories) and all(cat.is_locked for cat in categories)

    divisions = get_archived_divisions(event_id, portal_id)
    contestants_by_division = {
        division: get_archived_contestants_by_division(division, event_id, portal_id)
        for division in divisions
    }

    round1_results_by_division = compute_archived_results_by_division(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)

    round2_results_by_division = compute_archived_results_by_division(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)

    round3_results_by_division = compute_archived_results_by_division(round3_categories, top3_by_division)

    judge_breakdown = {}
    judge_breakdown_contestants = {}
    for category in categories:
        if category.round == 'round2':
            eligible = flatten_contestants(top5_by_division)
        elif category.round == 'round3':
            eligible = flatten_contestants(top3_by_division)
        else:
            eligible = flatten_contestants(contestants_by_division)
        judge_breakdown_contestants[category.id] = eligible
        judge_breakdown[category.id] = compute_archived_judge_breakdown([category], eligible, judges).get(category.id, {})

    return render_template(
        'results.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        round1_results_by_division=round1_results_by_division,
        round2_results_by_division=round2_results_by_division,
        round3_results_by_division=round3_results_by_division,
        round1_categories=round1_categories,
        round2_categories=round2_categories,
        round3_categories=round3_categories,
        all_locked=all_locked,
        round1_locked=round1_locked,
        round2_locked=round2_locked,
        round3_locked=round3_locked,
        judges_count=len(judges),
        category_winners_by_division={},
        show_category_winners=False,
        active_portal_id=None,
        history_mode=True,
        history_event_title=event.title,
        history_portal_name=portal.name,
        judge_breakdown=judge_breakdown,
        judge_breakdown_contestants=judge_breakdown_contestants,
        judges=judges,
        categories=categories,
        event_id=event.id,
        portal_id=portal.id
    )
@app.route('/competition-settings', methods=['GET', 'POST'])
@admin_required
def competition_settings():
    """Manage competition settings like title"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title=APP_TITLE, event_title=APP_TITLE)
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        event_title = request.form.get('event_title', '').strip()
        settings.competition_title = APP_TITLE
        settings.event_title = event_title or APP_TITLE
        settings.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Competition settings updated successfully!', 'success')
        return redirect(url_for('competition_settings'))
    
    return render_template('competition_settings.html', settings=settings)

@app.route('/toggle-category-winners', methods=['POST'])
@admin_required
def toggle_category_winners():
    """Toggle the display of category winners in results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(
            competition_title=APP_TITLE,
            event_title=APP_TITLE,
            show_category_winners=False
        )
        db.session.add(settings)
    
    # Toggle the setting
    settings.show_category_winners = not settings.show_category_winners
    settings.updated_at = datetime.utcnow()
    db.session.commit()
    
    status = "enabled" if settings.show_category_winners else "disabled"
    flash(f'Category winners display has been {status}!', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/categories')
@admin_required
def categories():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to manage categories.', 'warning')
    query = Category.query
    if portal_id:
        query = query.filter_by(portal_id=portal_id)
    all_categories = query.order_by(Category.order).all()
    total_query = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1')
    if portal_id:
        total_query = total_query.filter(Category.portal_id == portal_id)
    round1_total = total_query.scalar() or 0
    portals = CompetitionPortal.query.order_by(CompetitionPortal.name.asc()).all()
    return render_template(
        'categories.html',
        categories=all_categories,
        round1_total=round1_total,
        portals=portals,
        active_portal_id=portal_id
    )

@app.route('/category/add', methods=['GET', 'POST'])
@admin_required
def add_category():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to add categories.', 'warning')
        return redirect(url_for('manage_competition'))

    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        round_name = request.form.get('round', 'round1')

        if round_name in ['round2', 'round3']:
            existing_round = Category.query.filter_by(round=round_name, portal_id=portal_id).first()
            if existing_round:
                flash(f'Only one category is allowed for {round_name.title()}.', 'error')
                return render_template('add_category.html')
            if percentage != 100:
                flash('Round 2 and Round 3 categories must be 100%.', 'error')
                return render_template('add_category.html')
        
        # Check total percentage for Round 1 only
        if round_name == 'round1':
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(
                Category.round == 'round1', Category.portal_id == portal_id
            ).scalar() or 0
            new_total = current_total + percentage

            if new_total > 100:
                flash(f'Cannot add category. Round 1 total would be {new_total}%. Categories must total 100%.', 'error')
                return render_template('add_category.html')
        
        # Get the next order number
        max_order = db.session.query(db.func.max(Category.order)).filter(Category.portal_id == portal_id).scalar() or 0
        
        category = Category(
            name=name,
            percentage=percentage,
            order=max_order + 1,
            round=round_name,
            portal_id=portal_id
        )
        db.session.add(category)
        db.session.commit()

        if round_name == 'round1':
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(
                Category.round == 'round1', Category.portal_id == portal_id
            ).scalar() or 0
            flash(f'Category "{name}" added successfully! Round 1 total: {current_total}%', 'success')
            if current_total < 100:
                flash(f'Note: Round 1 categories total {current_total}%. Add {100 - current_total}% more to reach 100%.', 'warning')
        else:
            flash(f'Category "{name}" added successfully for {round_name.title()}.', 'success')
        return redirect(url_for('categories'))
    
    return render_template('add_category.html')

@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if category.portal_id != portal_id:
            flash('Select the correct competition portal to edit this category.', 'warning')
            return redirect(url_for('categories'))
    elif category.portal_id is not None:
        flash('Select a competition portal to edit this category.', 'warning')
        return redirect(url_for('categories'))
    
    # Safety check: don't allow editing if category is locked
    if category.is_locked:
        flash('Cannot edit a locked category. Unlock it first.', 'error')
        return redirect(url_for('categories'))
    
    if request.method == 'POST':
        new_percentage = float(request.form.get('percentage'))
        new_round = request.form.get('round', category.round)

        if new_round in ['round2', 'round3']:
            existing_round = Category.query.filter_by(round=new_round, portal_id=portal_id).filter(Category.id != category_id).first()
            if existing_round:
                flash(f'Only one category is allowed for {new_round.title()}.', 'error')
                return render_template('edit_category.html', category=category)
            if new_percentage != 100:
                flash('Round 2 and Round 3 categories must be 100%.', 'error')
                return render_template('edit_category.html', category=category)
        
        # Check total percentage for Round 1 only
        if new_round == 'round1':
            other_categories_total = db.session.query(db.func.sum(Category.percentage)).filter(
                Category.round == 'round1', Category.portal_id == portal_id, Category.id != category_id
            ).scalar() or 0
            new_total = other_categories_total + new_percentage

            if new_total > 100:
                flash(f'Cannot update category. Round 1 total would be {new_total}%. Categories must total 100%.', 'error')
                return render_template('edit_category.html', category=category)
        
        category.name = request.form.get('name')
        category.percentage = new_percentage
        category.round = new_round
        
        db.session.commit()

        if new_round == 'round1':
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(
                Category.round == 'round1', Category.portal_id == portal_id
            ).scalar() or 0
            flash(f'Category "{category.name}" updated successfully! Round 1 total: {current_total}%', 'success')
            if current_total < 100:
                flash(f'Note: Round 1 categories total {current_total}%. Add {100 - current_total}% more to reach 100%.', 'warning')
        else:
            flash(f'Category "{category.name}" updated successfully for {new_round.title()}.', 'success')
        return redirect(url_for('categories'))
    
    return render_template('edit_category.html', category=category)

@app.route('/category/<int:category_id>/criteria', methods=['GET', 'POST'])
@admin_required
def manage_criteria(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if category.portal_id != portal_id:
            flash('Select the correct competition portal to manage criteria.', 'warning')
            return redirect(url_for('categories'))
    elif category.portal_id is not None:
        flash('Select a competition portal to manage criteria.', 'warning')
        return redirect(url_for('categories'))
    
    if category.is_locked:
        flash('This category is locked and cannot be modified.', 'error')
        return redirect(url_for('categories'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        
        # Check total percentage for criteria in this category
        current_total = db.session.query(db.func.sum(Criteria.percentage)).filter_by(category_id=category_id).scalar() or 0
        new_total = current_total + percentage
        
        if new_total > 100:
            flash(f'Cannot add criteria. Total percentage would be {new_total}%. Criteria must total 100%.', 'error')
            criteria_list = Criteria.query.filter_by(category_id=category_id).order_by(Criteria.order).all()
            return render_template('manage_criteria.html', category=category, criteria=criteria_list)
        
        # Get the next order number for this category
        max_order = db.session.query(db.func.max(Criteria.order)).filter_by(category_id=category_id).scalar() or 0
        
        criteria = Criteria(category_id=category_id, name=name, percentage=percentage, order=max_order + 1)
        db.session.add(criteria)
        db.session.commit()
        
        flash(f'Criteria "{name}" added successfully! Total: {new_total}%', 'success')
        if new_total < 100:
            flash(f'Note: Criteria total {new_total}%. Add {100 - new_total}% more to reach 100%.', 'warning')
        return redirect(url_for('manage_criteria', category_id=category_id))
    
    criteria_list = Criteria.query.filter_by(category_id=category_id).order_by(Criteria.order).all()
    return render_template('manage_criteria.html', category=category, criteria=criteria_list)

@app.route('/contestants')
@admin_required
def contestants():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to manage contestants.', 'warning')

    divisions = get_divisions(portal_id=portal_id) if portal_id else get_divisions()
    contestants_by_division = {
        division: get_contestants_by_division(division, portal_id=portal_id)
        for division in divisions
    }
    total_contestants = sum(len(items) for items in contestants_by_division.values())
    portals = CompetitionPortal.query.order_by(CompetitionPortal.name.asc()).all()
    return render_template(
        'contestants.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        contestants_by_division=contestants_by_division,
        total_contestants=total_contestants,
        portals=portals,
        active_portal_id=portal_id
    )


@app.route('/contestant/<int:contestant_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_contestant(contestant_id):
    contestant = Contestant.query.get_or_404(contestant_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if contestant.portal_id != portal_id:
            flash('Select the correct competition portal to edit this contestant.', 'warning')
            return redirect(url_for('contestants'))
    elif contestant.portal_id is not None:
        flash('Select a competition portal to edit this contestant.', 'warning')
        return redirect(url_for('contestants'))
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        new_division = normalize_division(request.form.get('division'))
        
        # Safety check: if number or division changed, make sure it's not already taken
        if new_number != contestant.number or new_division != contestant.division:
            existing = Contestant.query.filter_by(
                number=new_number,
                division=new_division,
                portal_id=portal_id
            ).first()
            if existing and existing.id != contestant.id:
                flash(f'Contestant number {new_number} already exists in {DIVISION_LABELS.get(new_division, new_division)} division!', 'error')
                return render_template('edit_contestant.html', contestant=contestant, division_labels=DIVISION_LABELS)
        
        contestant.number = new_number
        contestant.name = new_name
        contestant.division = new_division
        db.session.commit()
        
        flash(f'Contestant #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('edit_contestant.html', contestant=contestant, division_labels=DIVISION_LABELS)

@app.route('/judges')
@admin_required
def judges():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to manage judges.', 'warning')

    query = Judge.query
    if portal_id:
        query = query.filter_by(portal_id=portal_id)
    all_judges = query.order_by(Judge.number).all()
    portals = CompetitionPortal.query.order_by(CompetitionPortal.name.asc()).all()
    return render_template(
        'judges.html',
        judges=all_judges,
        portals=portals,
        active_portal_id=portal_id
    )

@app.route('/judge/add', methods=['GET', 'POST'])
@admin_required
def add_judge():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to add judges.', 'warning')
        return redirect(url_for('manage_competition'))

    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        
        # Enforce per-portal uniqueness
        existing = Judge.query.filter_by(number=number, portal_id=portal_id).first()
        if existing:
            flash(f'Judge number {number} already exists for this portal. Choose a different number.', 'error')
            return render_template('add_judge.html')

        judge = Judge(number=number, name=name, portal_id=portal_id)
        db.session.add(judge)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(f'Judge number {number} already exists for this portal. Choose a different number.', 'error')
            return render_template('add_judge.html')
        
        flash(f'Judge #{number} - {name} added successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('add_judge.html')

@app.route('/judge/<int:judge_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if judge.portal_id != portal_id:
            flash('Select the correct competition portal to edit this judge.', 'warning')
            return redirect(url_for('judges'))
    elif judge.portal_id is not None:
        flash('Select a competition portal to edit this judge.', 'warning')
        return redirect(url_for('judges'))
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        
        # Safety check: if number changed, make sure it's not already taken
        if new_number != judge.number:
            existing = Judge.query.filter_by(number=new_number, portal_id=portal_id).first()
            if existing and existing.id != judge.id:
                flash(f'Judge number {new_number} is already taken for this portal!', 'error')
                return render_template('edit_judge.html', judge=judge)
        
        judge.number = new_number
        judge.name = new_name
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(f'Judge number {new_number} is already taken for this portal!', 'error')
            return render_template('edit_judge.html', judge=judge)
        
        flash(f'Judge #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('edit_judge.html', judge=judge)

@app.route('/judge/<int:judge_id>/delete', methods=['POST'])
@admin_required
def delete_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if judge.portal_id != portal_id:
            flash('Select the correct competition portal to delete this judge.', 'warning')
            return redirect(url_for('judges'))
    elif judge.portal_id is not None:
        flash('Select a competition portal to delete this judge.', 'warning')
        return redirect(url_for('judges'))
    
    # Safety check: warn if judge has scores
    score_count = Score.query.filter_by(judge_id=judge_id).count()
    if score_count > 0:
        flash(f'Warning: Deleted judge #{judge.number} - {judge.name} who had {score_count} scores.', 'warning')
    
    judge_info = f"#{judge.number} - {judge.name}"
    db.session.delete(judge)
    db.session.commit()
    
    flash(f'Judge {judge_info} deleted successfully!', 'success')
    return redirect(url_for('judges'))

@app.route('/contestant/add', methods=['GET', 'POST'])
@admin_required
def add_contestant():
    portal_id = get_active_portal_id()
    if not portal_id:
        flash('Select a competition portal to add contestants.', 'warning')
        return redirect(url_for('manage_competition'))

    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        division_raw = request.form.get('division')
        if not division_raw:
            flash('Division is required.', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)
        division = normalize_division(division_raw)
        
        # Check if number already exists
        existing = Contestant.query.filter_by(
            number=number,
            division=division,
            portal_id=portal_id
        ).first()
        if existing:
            flash(f'Contestant number {number} already exists in {DIVISION_LABELS.get(division, division)} division!', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)

        contestant = Contestant(number=number, name=name, division=division, portal_id=portal_id)
        db.session.add(contestant)
        db.session.commit()
        
        flash(f'Contestant #{number} - {name} added successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('add_contestant.html', division_labels=DIVISION_LABELS)

@app.route('/scoring')
@scoring_view_required
def scoring_menu():
    portal_id = get_active_portal_id()
    if not portal_id:
        if session.get('role') == ROLE_TABULATOR:
            flash('No portal assigned. Please contact an administrator.', 'error')
            return redirect(url_for('tabulator_dashboard'))
        flash('Select a competition portal to score.', 'warning')
        return redirect(url_for('manage_competition'))

    categories = Category.query.filter_by(portal_id=portal_id).order_by(Category.order).all()
    contestants_count = Contestant.query.filter_by(portal_id=portal_id).count()
    judges_count = Judge.query.filter_by(portal_id=portal_id).count()

    round1_categories = get_round_categories('round1', portal_id=portal_id)
    round2_categories = get_round_categories('round2', portal_id=portal_id)
    divisions = get_divisions(portal_id=portal_id)

    contestants_by_division = {
        division: get_contestants_by_division(division, portal_id=portal_id)
        for division in divisions
    }
    round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
    top5_contestants = flatten_contestants(top5_by_division)

    round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
    top3_contestants = flatten_contestants(top3_by_division)
    
    # Check which categories are ready for scoring
    for category in categories:
        category.criteria_count = Criteria.query.filter_by(category_id=category.id).count()
        category.ready = category.criteria_count > 0 and contestants_count > 0 and judges_count > 0
        if category.round == 'round2' and divisions:
            for division in divisions:
                if contestants_by_division.get(division) and len(top5_by_division.get(division, [])) < 5:
                    category.ready = False
                    break
        if category.round == 'round2' and not divisions:
            category.ready = False
        if category.round == 'round3' and divisions:
            for division in divisions:
                if contestants_by_division.get(division) and len(top3_by_division.get(division, [])) < 3:
                    category.ready = False
                    break
        if category.round == 'round3' and not divisions:
            category.ready = False
    
    round1_list = [c for c in categories if c.round == 'round1']
    round2_list = [c for c in categories if c.round == 'round2']
    round3_list = [c for c in categories if c.round == 'round3']

    return render_template(
        'scoring_menu.html',
        round1_categories=round1_list,
        round2_categories=round2_list,
        round3_categories=round3_list,
        contestants_count=contestants_count,
        judges_count=judges_count
    )

@app.route('/scoring/<int:category_id>')
@scoring_view_required
def scoring(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if not portal_id or category.portal_id != portal_id:
        flash('Select the correct competition portal to score this category.', 'warning')
        return redirect(url_for('scoring_menu'))
    
    if category.is_locked and session.get('role') != ROLE_ADMIN:
        flash('This category is already locked!', 'warning')
        return redirect(url_for('scoring_menu'))
    
    round1_categories = get_round_categories('round1', portal_id=portal_id)
    round2_categories = get_round_categories('round2', portal_id=portal_id)

    divisions = get_divisions(portal_id=portal_id)
    contestants_by_division = {
        division: get_contestants_by_division(division, portal_id=portal_id)
        for division in divisions
    }
    contestants = flatten_contestants(contestants_by_division)
    if category.round == 'round2':
        if round1_categories:
            round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
            top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
            contestants = flatten_contestants(top5_by_division)
        else:
            contestants = []
    elif category.round == 'round3':
        if round2_categories:
            round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
            top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
            round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
            top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
            contestants = flatten_contestants(top3_by_division)
        else:
            contestants = []
    criteria = Criteria.query.filter_by(category_id=category_id).order_by(Criteria.order).all()
    judges = Judge.query.filter_by(portal_id=portal_id).order_by(Judge.number).all()
    
    if not contestants:
        flash('Please add contestants first before scoring.', 'warning')
        return redirect(url_for('scoring_menu'))
    
    if not criteria:
        flash('Please add criteria to this category before scoring.', 'warning')
        return redirect(url_for('scoring_menu'))
    
    if not judges:
        flash('Please add judges first before scoring.', 'warning')
        return redirect(url_for('scoring_menu'))
    
    # Get existing scores organized by judge, contestant, and criteria
    existing_scores = {}
    for score in Score.query.filter_by(category_id=category_id).all():
        key = f"{score.judge_id}_{score.contestant_id}_{score.criteria_id}"
        existing_scores[key] = score.score
    
    return render_template('scoring.html', category=category, contestants=contestants, 
                         criteria=criteria, judges=judges, existing_scores=existing_scores)

@app.route('/scoring/<int:category_id>/save', methods=['POST'])
@scoring_required
def save_scores(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if not portal_id or category.portal_id != portal_id:
        return jsonify({'success': False, 'message': 'Invalid portal for this category'}), 403
    
    if category.is_locked:
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    data = request.get_json()
    scores_data = data.get('scores', [])
    judge_id = data.get('judge_id')
    
    if not judge_id:
        return jsonify({'success': False, 'message': 'Judge ID is required'}), 400

    judge = Judge.query.filter_by(id=judge_id, portal_id=portal_id).first()
    if not judge:
        return jsonify({'success': False, 'message': 'Judge not found for this portal'}), 400

    contestant_ids = [entry.get('contestant_id') for entry in scores_data if entry.get('contestant_id')]
    if contestant_ids:
        portal_contestants = Contestant.query.filter(
            Contestant.portal_id == portal_id,
            Contestant.id.in_(contestant_ids)
        ).count()
        if portal_contestants != len(set(contestant_ids)):
            return jsonify({'success': False, 'message': 'One or more contestants are not in this portal'}), 400
    
    # Delete existing scores for this category and judge
    Score.query.filter_by(category_id=category_id, judge_id=judge_id).delete()
    
    # Add new scores
    for score_entry in scores_data:
        score = Score(
            contestant_id=score_entry['contestant_id'],
            category_id=category_id,
            criteria_id=score_entry['criteria_id'],
            judge_id=judge_id,
            score=score_entry['score']
        )
        db.session.add(score)
    
    db.session.commit()

    log_event(
        'scores_submitted',
        f'category_id={category_id} judge_id={judge_id} scores_count={len(scores_data)}'
    )
    
    return jsonify({'success': True, 'message': 'Scores saved successfully'})

@app.route('/category/<int:category_id>/lock', methods=['POST'])
@scoring_required
def lock_category(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if not portal_id or category.portal_id != portal_id:
        return jsonify({'success': False, 'message': 'Invalid portal for this category'}), 403
    
    if category.is_locked:
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    # Check if criteria percentages total 100%
    criteria_total = db.session.query(db.func.sum(Criteria.percentage)).filter_by(category_id=category_id).scalar() or 0
    if criteria_total != 100:
        return jsonify({'success': False, 'message': f'Cannot lock category. Criteria percentages total {criteria_total}%. Must equal 100%.'}), 400
    
    # Check if all Round 1 category percentages total 100%
    if category.round == 'round1':
        all_categories_total = db.session.query(db.func.sum(Category.percentage)).filter(
            Category.round == 'round1', Category.portal_id == portal_id
        ).scalar() or 0
        if all_categories_total != 100:
            return jsonify({'success': False, 'message': f'Cannot lock category. Round 1 categories total {all_categories_total}%. Must equal 100%.'}), 400
    
    # Check if all required contestants have scores for all criteria from all judges
    divisions = get_divisions(portal_id=portal_id)
    contestants_by_division = {
        division: get_contestants_by_division(division, portal_id=portal_id)
        for division in divisions
    }
    contestants = flatten_contestants(contestants_by_division)
    if category.round == 'round2':
        round1_categories = get_round_categories('round1', portal_id=portal_id)
        if not round1_categories:
            return jsonify({'success': False, 'message': 'Round 1 categories are required before locking Round 2.'}), 400
        round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
        top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
        contestants = flatten_contestants(top5_by_division)
    elif category.round == 'round3':
        round1_categories = get_round_categories('round1', portal_id=portal_id)
        round2_categories = get_round_categories('round2', portal_id=portal_id)
        if not round1_categories or not round2_categories:
            return jsonify({'success': False, 'message': 'Round 1 and Round 2 categories are required before locking Round 3.'}), 400
        round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
        top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
        round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
        top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
        contestants = flatten_contestants(top3_by_division)

    if not contestants:
        return jsonify({'success': False, 'message': 'No eligible contestants found for this round.'}), 400
    criteria = Criteria.query.filter_by(category_id=category_id).all()
    judges = Judge.query.filter_by(portal_id=portal_id).all()

    contestant_ids = [c.id for c in contestants]
    expected_scores = len(contestants) * len(criteria) * len(judges)
    actual_scores = Score.query.filter_by(category_id=category_id).filter(Score.contestant_id.in_(contestant_ids)).count()
    
    if actual_scores < expected_scores:
        return jsonify({'success': False, 'message': f'Please ensure all {len(judges)} judges have scored all contestants before locking'}), 400
    
    category.is_locked = True
    db.session.commit()

    log_event('category_locked', f'category_id={category_id} category_name={category.name}')
    
    return jsonify({'success': True, 'message': f'Category "{category.name}" has been locked'})


@app.route('/results')
@admin_required
def results():
    portal_id_raw = request.args.get('portal_id')
    portal_id = int(portal_id_raw) if portal_id_raw else get_active_portal_id()
    if portal_id_raw:
        session['portal_id'] = portal_id

    categories_query = Category.query
    judges_query = Judge.query
    if portal_id:
        categories_query = categories_query.filter_by(portal_id=portal_id)
        judges_query = judges_query.filter_by(portal_id=portal_id)

    categories = categories_query.order_by(Category.order).all()
    judges = judges_query.all()
    
    # Get settings
    settings = Settings.query.first()
    if not settings:
        settings = Settings(
            competition_title=APP_TITLE,
            event_title=APP_TITLE,
            show_category_winners=False
        )
        db.session.add(settings)
        db.session.commit()
    
    all_locked = bool(categories) and all(cat.is_locked for cat in categories)
    
    round1_categories = get_round_categories('round1', portal_id=portal_id)
    round2_categories = get_round_categories('round2', portal_id=portal_id)
    round3_categories = get_round_categories('round3', portal_id=portal_id)

    round1_categories_locked = [cat for cat in round1_categories if cat.is_locked]
    round2_categories_locked = [cat for cat in round2_categories if cat.is_locked]
    round3_categories_locked = [cat for cat in round3_categories if cat.is_locked]

    round1_locked = bool(round1_categories_locked)
    round2_locked = bool(round2_categories_locked)
    round3_locked = bool(round3_categories_locked)

    divisions = get_divisions(portal_id=portal_id) if portal_id else get_divisions()
    contestants_by_division = {
        division: get_contestants_by_division(division, portal_id=portal_id)
        for division in divisions
    }

    round1_results_by_division = compute_results_by_division(round1_categories_locked, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)

    round2_results_by_division = compute_results_by_division(round2_categories_locked, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)

    round3_results_by_division = compute_results_by_division(round3_categories_locked, top3_by_division)
    
    # Calculate category winners if the setting is enabled
    category_winners_by_division = {}
    if settings.show_category_winners:
        score_tolerance = 1e-9
        for division in divisions:
            division_results = round1_results_by_division.get(division, [])
            if not division_results:
                continue
            division_winners = {}
            for category in round1_categories_locked:
                best_contestants = []
                best_score = -1

                for result in division_results:
                    if category.name in result['category_scores']:
                        score = result['category_scores'][category.name]['raw']
                        if score > best_score:
                            best_score = score
                            best_contestants = [result['contestant']]
                        elif abs(score - best_score) <= score_tolerance:
                            best_contestants.append(result['contestant'])

                if best_contestants:
                    division_winners[category.name] = {
                        'contestants': best_contestants,
                        'score': best_score
                    }
            if division_winners:
                category_winners_by_division[division] = division_winners

    breakdown_categories = round1_categories_locked + round2_categories_locked + round3_categories_locked
    judge_breakdown = {}
    judge_breakdown_contestants = {}
    if judges and breakdown_categories:
        for category in breakdown_categories:
            if category.round == 'round2':
                eligible = flatten_contestants(top5_by_division)
            elif category.round == 'round3':
                eligible = flatten_contestants(top3_by_division)
            else:
                eligible = flatten_contestants(contestants_by_division)
            judge_breakdown_contestants[category.id] = eligible
            judge_breakdown[category.id] = compute_live_judge_breakdown([category], eligible, judges).get(category.id, {})

    return render_template(
        'results.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        round1_results_by_division=round1_results_by_division,
        round2_results_by_division=round2_results_by_division,
        round3_results_by_division=round3_results_by_division,
        round1_categories=round1_categories_locked,
        round2_categories=round2_categories_locked,
        round3_categories=round3_categories_locked,
        all_locked=all_locked,
        round1_locked=round1_locked,
        round2_locked=round2_locked,
        round3_locked=round3_locked,
        has_live_results=round1_locked or round2_locked or round3_locked,
        judges_count=len(judges),
        category_winners_by_division=category_winners_by_division,
        show_category_winners=settings.show_category_winners,
        active_portal_id=portal_id,
        judge_breakdown=judge_breakdown,
        judge_breakdown_contestants=judge_breakdown_contestants,
        judges=judges,
        categories=breakdown_categories
    )

@app.route('/results/download-pdf')
def download_results_pdf():
    """Generate and download PDF of competition results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title=APP_TITLE, event_title=APP_TITLE)
        db.session.add(settings)
        db.session.commit()

    portal_id_raw = request.args.get('portal_id')
    portal_id = int(portal_id_raw) if portal_id_raw else get_active_portal_id()
    raw_division = request.args.get('division')
    division = normalize_division(raw_division) if raw_division else None
    if raw_division and raw_division.lower() not in DIVISION_VALUES:
        flash('Invalid division selected for download.', 'error')
        return redirect(url_for('results', portal_id=portal_id) if portal_id else url_for('results'))
    categories_query = Category.query
    contestants_query = Contestant.query
    if portal_id:
        categories_query = categories_query.filter_by(portal_id=portal_id)
        contestants_query = contestants_query.filter_by(portal_id=portal_id)
    categories = categories_query.order_by(Category.order).all()
    if division:
        contestants = get_contestants_by_division(division, portal_id=portal_id)
    else:
        contestants = contestants_query.order_by(Contestant.division, Contestant.number).all()

    all_locked = bool(categories) and all(cat.is_locked for cat in categories)
    if not all_locked:
        flash('Final results PDF is available only when all categories are locked.', 'warning')
        return redirect(url_for('results', portal_id=portal_id) if portal_id else url_for('results'))

    portal_title = None
    if portal_id:
        portal = CompetitionPortal.query.get(portal_id)
        if portal:
            portal_title = portal.name
    results_data = compute_results_for_categories(categories, contestants)

    header_label = 'FINAL RESULTS'
    if division:
        division_label = DIVISION_LABELS.get(division, division.title())
        header_label = f"{header_label} - {division_label.upper()}"

    return build_results_pdf_response(
        categories=categories,
        results_data=results_data,
        settings=settings,
        header_label=header_label,
        include_winners=settings.show_category_winners,
        include_division_column=not division,
        title_override=portal_title
    )


@app.route('/results/download-pdf/<round_name>')
def download_results_pdf_round(round_name):
    """Generate and download PDF of results for a specific round"""
    portal_id_raw = request.args.get('portal_id')
    portal_id = int(portal_id_raw) if portal_id_raw else get_active_portal_id()
    results_redirect = url_for('results', portal_id=portal_id) if portal_id else url_for('results')

    if round_name not in ('round1', 'round2', 'round3'):
        flash('Invalid round selected for download.', 'error')
        return redirect(results_redirect)

    raw_division = request.args.get('division')
    division = normalize_division(raw_division) if raw_division else None
    if raw_division and raw_division.lower() not in DIVISION_VALUES:
        flash('Invalid division selected for download.', 'error')
        return redirect(results_redirect)

    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title=APP_TITLE, event_title=APP_TITLE)
        db.session.add(settings)
        db.session.commit()

    round_categories = get_round_categories(round_name, portal_id=portal_id)
    if not round_categories:
        flash('No categories found for that round.', 'warning')
        return redirect(results_redirect)

    if not all(cat.is_locked for cat in round_categories):
        flash('That round is not locked yet.', 'warning')
        return redirect(results_redirect)

    contestants_query = Contestant.query
    if portal_id:
        contestants_query = contestants_query.filter_by(portal_id=portal_id)
    contestants = contestants_query.order_by(Contestant.division, Contestant.number).all()
    if division:
        contestants = get_contestants_by_division(division, portal_id=portal_id)
        if not contestants:
            flash('No contestants found for the selected division.', 'warning')
            return redirect(results_redirect)
    if round_name == 'round2':
        round1_categories = get_round_categories('round1', portal_id=portal_id)
        if division:
            round1_results = compute_results_for_categories(round1_categories, contestants) if round1_categories else []
            contestants = [r['contestant'] for r in round1_results[:5]]
        else:
            divisions = get_divisions(portal_id=portal_id) if portal_id else get_divisions()
            contestants_by_division = {
                value: get_contestants_by_division(value, portal_id=portal_id)
                for value in divisions
            }
            round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
            top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
            contestants = flatten_contestants(top5_by_division)
    elif round_name == 'round3':
        round1_categories = get_round_categories('round1', portal_id=portal_id)
        round2_categories = get_round_categories('round2', portal_id=portal_id)
        if division:
            round1_results = compute_results_for_categories(round1_categories, contestants) if round1_categories else []
            top5_contestants = [r['contestant'] for r in round1_results[:5]]
            round2_results = compute_results_for_categories(round2_categories, top5_contestants) if round2_categories else []
            contestants = [r['contestant'] for r in round2_results[:3]]
        else:
            divisions = get_divisions(portal_id=portal_id) if portal_id else get_divisions()
            contestants_by_division = {
                value: get_contestants_by_division(value, portal_id=portal_id)
                for value in divisions
            }
            round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
            top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
            round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
            top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
            contestants = flatten_contestants(top3_by_division)

    results_data = compute_results_for_categories(round_categories, contestants)

    if round_name == 'round1':
        header_label = 'ROUND 1 RESULTS'
    elif round_name == 'round2':
        header_label = 'TOP 5 RESULTS'
    else:
        header_label = 'FINAL RESULTS (TOP 3)'

    if division:
        division_label = DIVISION_LABELS.get(division, division.title())
        header_label = f"{header_label} - {division_label.upper()}"

    portal_title = None
    if portal_id:
        portal = CompetitionPortal.query.get(portal_id)
        if portal:
            portal_title = portal.name

    return build_results_pdf_response(
        categories=round_categories,
        results_data=results_data,
        settings=settings,
        header_label=header_label,
        include_winners=settings.show_category_winners and round_name == 'round1',
        filename_suffix=f"{round_name}_{division}" if division else round_name,
        title_override=portal_title
    )


def build_results_pdf_response(categories, results_data, settings, header_label, include_winners=False, filename_suffix=None, include_division_column=False, title_override=None):
    """Build a PDF response for provided results data."""
    num_categories = len(categories)
    base_columns = 4 + (1 if include_division_column else 0)
    total_columns = base_columns + num_categories
    row_count = len(results_data)
    use_landscape = True
    dense_layout = total_columns > 9 or row_count > 10

    # Create PDF
    buffer = BytesIO()
    page_size = landscape(letter)
    margin = 18 if dense_layout else 30
    doc = SimpleDocTemplate(buffer, pagesize=page_size, rightMargin=margin, leftMargin=margin, topMargin=margin, bottomMargin=margin)
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Header with logo and university name
    logo_path = os.path.join('static', 'images', 'MseufCatLogo.png')
    
    # Create header table with logo and university name
    header_data = []
    header_row = []
    
    # Add logo if it exists
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=0.8*inch, height=0.8*inch)
        header_row.append(logo)
    else:
        header_row.append('')
    
    # University name
    university_style = ParagraphStyle(
        'University',
        parent=styles['Normal'],
        fontSize=12,
        alignment=TA_CENTER,
        spaceAfter=5
    )
    university_text = Paragraph("Manuel S. Enverga University Foundation - Catanauan Inc", university_style)
    header_row.append(university_text)
    
    # Add empty cell for right side to balance
    header_row.append('')
    
    header_data.append(header_row)
    header_table = Table(header_data, colWidths=[1*inch, 4.5*inch, 1*inch])
    header_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(header_table)
    elements.append(Spacer(1, 6 if dense_layout else 10))
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=14 if dense_layout else 18,
        textColor=colors.maroon,
        spaceAfter=3 if dense_layout else 5,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    title_source = title_override or APP_TITLE
    title_text = f"<b>{title_source.upper()} RESULTS</b>"
    title = Paragraph(title_text, title_style)
    elements.append(title)
    
    elements.append(Spacer(1, 8 if dense_layout else 20))
    
    # Add FINAL RESULTS header
    final_results_style = ParagraphStyle(
        'FinalResults',
        parent=styles['Heading2'],
        fontSize=12 if dense_layout else 14,
        textColor=colors.black,
        spaceAfter=8 if dense_layout else 15,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    final_results_header = Paragraph(f"<b>{header_label}</b>", final_results_style)
    elements.append(final_results_header)
    
    # Create table data
    table_data = []
    header_row = ['Rank', 'Contestant No.']
    if include_division_column:
        header_row.append('Division')
    header_row.append('Name')

    # Add category headers
    for category in categories:
        header_row.append(f"{category.name}\n({category.percentage}%)")
    header_row.append('Total Score')

    header_font_size = 9
    body_font_size = 8
    if total_columns > 10:
        header_font_size = 8
        body_font_size = 7
    if total_columns > 14:
        header_font_size = 7
        body_font_size = 6
    if row_count > 10:
        header_font_size -= 1
        body_font_size -= 1
    if row_count > 15:
        body_font_size -= 1

    header_font_size = max(header_font_size, 6)
    body_font_size = max(body_font_size, 5)

    header_cell_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=header_font_size,
        leading=header_font_size + 1,
        alignment=TA_CENTER,
        textColor=colors.black
    )

    header_row = [Paragraph(text, header_cell_style) for text in header_row]
    table_data.append(header_row)
    
    # Add contestant rows
    for result in results_data:
        row = [
            str(result['rank']),
            str(result['contestant'].number)
        ]
        if include_division_column:
            division_label = DIVISION_LABELS.get(result['contestant'].division, result['contestant'].division)
            row.append(division_label)
        row.append(result['contestant'].name)
        
        for category in categories:
            if result['category_scores'][category.name]:
                weighted = result['category_scores'][category.name]['weighted']
                raw = result['category_scores'][category.name]['raw']
                row.append(f"{weighted:.4f}\\n({raw:.4f})")
            else:
                row.append('-')
        
        row.append(f"{result['total_score']:.4f}")
        table_data.append(row)
    
    # Create table sized to available page width
    available_width = doc.width

    rank_width = 0.5 * inch
    number_width = 0.9 * inch
    total_width = 0.9 * inch
    division_width = 0.9 * inch if include_division_column else 0
    name_width = 2.0 * inch
    if total_columns > 10:
        name_width = 1.6 * inch
    if total_columns > 14:
        name_width = 1.3 * inch
    if dense_layout:
        name_width = min(name_width, 1.2 * inch)
    fixed_width = rank_width + number_width + division_width + name_width + total_width

    remaining_width = max(available_width - fixed_width, 0.5 * inch * max(num_categories, 1))
    category_width = remaining_width / max(num_categories, 1)
    col_widths = [rank_width, number_width]
    if include_division_column:
        col_widths.append(division_width)
    col_widths += [name_width] + [category_width] * num_categories + [total_width]

    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    # Style the table - simple black and white
    table_style = TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), header_font_size),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6 if dense_layout else 12),
        ('TOPPADDING', (0, 0), (-1, -1), 2 if dense_layout else 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 2 if dense_layout else 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 2 if dense_layout else 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 2 if dense_layout else 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), body_font_size),
    ])
    
    table.setStyle(table_style)
    elements.append(table)
    
    elements.append(Spacer(1, 8 if dense_layout else 20))
    
    # Add category winners if enabled
    if include_winners:
        # Calculate category winners
        category_winners = {}
        score_tolerance = 1e-9
        for category in categories:
            best_contestants = []
            best_score = -1
            
            for result in results_data:
                if category.name in result['category_scores']:
                    score = result['category_scores'][category.name]['raw']
                    if score > best_score:
                        best_score = score
                        best_contestants = [result['contestant']]
                    elif abs(score - best_score) <= score_tolerance:
                        best_contestants.append(result['contestant'])
            
            if best_contestants:
                category_winners[category.name] = {
                    'contestants': best_contestants,
                    'score': best_score
                }
        
        # Add category winners section
        if category_winners:
            elements.append(Spacer(1, 10))
            
            winner_title_style = ParagraphStyle(
                'WinnerTitle',
                parent=styles['Heading2'],
                fontSize=12 if dense_layout else 14,
                textColor=colors.black,
                spaceAfter=8 if dense_layout else 15,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            
            winner_title = Paragraph("<b>CATEGORY WINNERS</b>", winner_title_style)
            elements.append(winner_title)
            
            # Create category winners table
            winner_data = [['Category', 'Winner', 'Contestant #', 'Score']]
            
            for category in categories:
                if category.name in category_winners:
                    winner_info = category_winners[category.name]
                    winner_names = " / ".join([c.name for c in winner_info['contestants']])
                    winner_numbers = " / ".join([str(c.number) for c in winner_info['contestants']])
                    winner_data.append([
                        category.name,
                        winner_names,
                        winner_numbers,
                        f"{winner_info['score']:.4f}"
                    ])
            
            winner_table = Table(winner_data, colWidths=[2*inch, 2.5*inch, 1*inch, 1*inch])
            
            winner_table_style = TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9 if dense_layout else 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6 if dense_layout else 12),
                ('TOPPADDING', (0, 0), (-1, -1), 2 if dense_layout else 4),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 2 if dense_layout else 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8 if dense_layout else 9),
            ])
            
            winner_table.setStyle(winner_table_style)
            elements.append(winner_table)
            
            elements.append(Spacer(1, 6 if dense_layout else 15))
    
    # Legend
    legend_style = ParagraphStyle(
        'Legend',
        parent=styles['Normal'],
        fontSize=6 if dense_layout else 8,
        spaceAfter=2 if dense_layout else 3
    )
    
    legend = Paragraph("<b>Score Breakdown:</b> Weighted Score (Raw Score) - Raw scores shown in parentheses", legend_style)
    elements.append(legend)
    
    elements.append(Spacer(1, 8 if dense_layout else 20))
    
    # Footer credit
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=6 if dense_layout else 8,
        alignment=TA_CENTER,
        textColor=colors.grey
    )
    
    footer = Paragraph("Developed by MSEUF Catanauan | Information Technology Department", footer_style)
    elements.append(footer)
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF from buffer
    pdf = buffer.getvalue()
    buffer.close()
    
    # Create safe filename from competition title
    safe_filename = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in title_source)
    safe_filename = safe_filename.replace(' ', '_')
    if not safe_filename:
        safe_filename = 'pageant_results'
    if filename_suffix:
        safe_filename = f"{safe_filename}_{filename_suffix}"
    
    # Create response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={safe_filename}.pdf'
    
    return response

@app.route('/category/<int:category_id>/delete', methods=['POST'])
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if category.portal_id != portal_id:
            flash('Select the correct competition portal to delete this category.', 'warning')
            return redirect(url_for('categories'))
    elif category.portal_id is not None:
        flash('Select a competition portal to delete this category.', 'warning')
        return redirect(url_for('categories'))
    
    # Safety check: don't allow deletion if category is locked
    if category.is_locked:
        flash('Cannot delete a locked category. Unlock it first.', 'error')
        return redirect(url_for('categories'))
    
    # Safety check: warn if category has scores
    score_count = Score.query.filter_by(category_id=category_id).count()
    if score_count > 0:
        flash(f'Warning: Deleted category "{category.name}" which had {score_count} scores.', 'warning')
    
    category_name = category.name
    db.session.delete(category)
    db.session.commit()
    
    flash(f'Category "{category_name}" deleted successfully!', 'success')
    return redirect(url_for('categories'))

@app.route('/contestant/<int:contestant_id>/delete', methods=['POST'])
@admin_required
def delete_contestant(contestant_id):
    contestant = Contestant.query.get_or_404(contestant_id)
    portal_id = get_active_portal_id()
    if portal_id:
        if contestant.portal_id != portal_id:
            flash('Select the correct competition portal to delete this contestant.', 'warning')
            return redirect(url_for('contestants'))
    elif contestant.portal_id is not None:
        flash('Select a competition portal to delete this contestant.', 'warning')
        return redirect(url_for('contestants'))
    
    # Safety check: warn if contestant has scores
    score_count = Score.query.filter_by(contestant_id=contestant_id).count()
    if score_count > 0:
        flash(f'Warning: Deleted contestant #{contestant.number} - {contestant.name} who had {score_count} scores.', 'warning')
    
    contestant_info = f"#{contestant.number} - {contestant.name}"
    db.session.delete(contestant)
    db.session.commit()
    
    flash(f'Contestant {contestant_info} deleted successfully!', 'success')
    return redirect(url_for('contestants'))

@app.route('/reset', methods=['POST'])
@admin_required
def reset_database():
    """Reset scoring data while keeping admin accounts"""
    try:
        reset_history = bool(request.form.get('reset_history'))
        Score.query.delete()
        Criteria.query.delete()
        Category.query.delete()
        Contestant.query.delete()
        Judge.query.delete()

        if reset_history:
            ArchivedScore.query.delete()
            ArchivedCriteria.query.delete()
            ArchivedCategory.query.delete()
            ArchivedContestant.query.delete()
            ArchivedJudge.query.delete()
            ArchivedPortal.query.delete()
            ArchivedEvent.query.delete()
            EventHistory.query.delete()

        db.session.commit()
        log_event(
            'data_reset',
            'contestants, categories, criteria, judges, scores cleared'
            + ('; history cleared' if reset_history else '')
        )
        if reset_history:
            flash('Database reset successfully! Scoring data and admin history were cleared.', 'success')
        else:
            flash('Database reset successfully! Contestants, categories, judges, criteria, and scores were cleared.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting database: {str(e)}', 'error')
    
    return redirect(url_for('admin_settings'))

if __name__ == '__main__':
    with app.app_context():
        ensure_schema_updates()
        db.create_all()
        # Initialize settings if not exists
        if not Settings.query.first():
            default_settings = Settings(
                competition_title=APP_TITLE,
                event_title=APP_TITLE
            )
            db.session.add(default_settings)
            db.session.commit()
    app.run(debug=True)
