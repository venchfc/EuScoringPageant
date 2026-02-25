from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
import os
import uuid
import base64
import csv
import json
from types import SimpleNamespace
from io import BytesIO, StringIO
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_, text, func
from sqlalchemy import or_
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

def build_database_uri():
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        return database_url

    db_user = os.getenv('DB_USER')
    db_pass = os.getenv('DB_PASS')
    db_name = os.getenv('DB_NAME')
    instance = os.getenv('INSTANCE_CONNECTION_NAME')
    if all([db_user, db_pass, db_name, instance]):
        return (
            f"postgresql+psycopg2://{db_user}:{db_pass}@/{db_name}"
            f"?host=/cloudsql/{instance}"
        )

    return 'sqlite:///pageant.db'


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = build_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'images', 'contestants')

socketio = SocketIO(app, async_mode='threading')

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Default admin credentials (override with environment variables)
DEFAULT_ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
DEFAULT_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'adminITD2026')

DIVISION_VALUES = ['male', 'female', 'unspecified']
DIVISION_LABELS = {
    'male': 'Male',
    'female': 'Female',
    'unspecified': 'Unassigned'
}

db = SQLAlchemy(app)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        role = session.get('role')
        if role not in {'admin', 'tabulator'}:
            flash('You do not have access to that page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def judge_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('judge_logged_in'):
            flash('Please login as judge to access this page.', 'warning')
            return redirect(url_for('judge_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default='admin')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
    number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    division = db.Column(db.String(20), nullable=False, default='unspecified')
    photo_filename = db.Column(db.String(255), nullable=True)
    photo_data = db.Column(db.LargeBinary, nullable=True)
    photo_mime = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='contestant', lazy=True, cascade='all, delete-orphan')

class Judge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_logged_in = db.Column(db.Boolean, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_portal_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='judge', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contestant_id = db.Column(db.Integer, db.ForeignKey('contestant.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'), nullable=False)
    judge_id = db.Column(db.Integer, db.ForeignKey('judge.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    criteria_ref = db.relationship('Criteria')

class JudgeSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judge_id = db.Column(db.Integer, db.ForeignKey('judge.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('judge_id', 'category_id', name='uq_judge_category_submission'),)

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
    competition_title = db.Column(db.String(200), nullable=False, default='Pageant Competition')
    show_category_winners = db.Column(db.Boolean, default=False)
    active_category_id = db.Column(db.Integer, nullable=True)
    active_set_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CompetitionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    competition_title = db.Column(db.String(200), nullable=False)
    closed_at = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=False)
    breakdown_json = db.Column(db.Text, nullable=False)

# Ensure there is at least one admin user
def ensure_default_admin():
    if User.query.first() is None:
        admin_user = User(username=DEFAULT_ADMIN_USERNAME)
        admin_user.set_password(DEFAULT_ADMIN_PASSWORD)
        admin_user.role = 'admin'
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

    contestant_columns = db.session.execute(text('PRAGMA table_info(contestant)')).all()
    contestant_column_names = {col[1] for col in contestant_columns}
    if 'division' not in contestant_column_names:
        db.session.execute(text("ALTER TABLE contestant ADD COLUMN division TEXT DEFAULT 'unspecified'"))
        db.session.execute(text("UPDATE contestant SET division='unspecified' WHERE division IS NULL"))
        db.session.commit()
    if 'photo_filename' not in contestant_column_names:
        db.session.execute(text("ALTER TABLE contestant ADD COLUMN photo_filename TEXT"))
        db.session.commit()
    if 'photo_data' not in contestant_column_names:
        db.session.execute(text("ALTER TABLE contestant ADD COLUMN photo_data BLOB"))
        db.session.commit()
    if 'photo_mime' not in contestant_column_names:
        db.session.execute(text("ALTER TABLE contestant ADD COLUMN photo_mime TEXT"))
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
            base_columns = [
                ('id', 'INTEGER PRIMARY KEY'),
                ('number', 'INTEGER NOT NULL'),
                ('name', 'TEXT NOT NULL'),
                ("division", "TEXT NOT NULL DEFAULT 'unspecified'"),
                ('created_at', 'DATETIME')
            ]
            optional_columns = [
                ('photo_filename', 'TEXT'),
                ('photo_data', 'BLOB'),
                ('photo_mime', 'TEXT')
            ]

            create_columns = base_columns + optional_columns
            create_sql = "CREATE TABLE contestant (" + ", ".join(
                f"{name} {col_type}" for name, col_type in create_columns
            ) + ")"
            db.session.execute(text(create_sql))

            insert_columns = [name for name, _ in base_columns + optional_columns]
            select_columns = []
            for name in insert_columns:
                if name == 'division':
                    select_columns.append("COALESCE(division, 'unspecified') AS division")
                elif name in contestant_column_names:
                    select_columns.append(name)
                else:
                    select_columns.append(f"NULL AS {name}")
            insert_sql = (
                "INSERT INTO contestant (" + ", ".join(insert_columns) + ") "
                "SELECT " + ", ".join(select_columns) + " FROM contestant_old"
            )
            db.session.execute(text(insert_sql))
            db.session.execute(text('DROP TABLE contestant_old'))
            db.session.execute(text('PRAGMA foreign_keys=on'))
            db.session.commit()
        except Exception:
            db.session.rollback()

    judge_columns = db.session.execute(text('PRAGMA table_info(judge)')).all()
    judge_column_names = {col[1] for col in judge_columns}
    if 'username' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN username TEXT"))
        db.session.commit()
    if 'password_hash' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN password_hash TEXT"))
        db.session.commit()
    if 'is_active' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN is_active BOOLEAN DEFAULT 1"))
        db.session.execute(text("UPDATE judge SET is_active=1 WHERE is_active IS NULL"))
        db.session.commit()
    if 'is_logged_in' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN is_logged_in BOOLEAN DEFAULT 0"))
        db.session.execute(text("UPDATE judge SET is_logged_in=0 WHERE is_logged_in IS NULL"))
        db.session.commit()
    if 'last_login_at' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN last_login_at DATETIME"))
        db.session.commit()
    if 'last_portal_at' not in judge_column_names:
        db.session.execute(text("ALTER TABLE judge ADD COLUMN last_portal_at DATETIME"))
        db.session.commit()

    user_columns = db.session.execute(text('PRAGMA table_info(user)')).all()
    user_column_names = {col[1] for col in user_columns}
    if 'role' not in user_column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN role TEXT DEFAULT 'admin'"))
        db.session.execute(text("UPDATE user SET role='admin' WHERE role IS NULL OR role=''"))
        db.session.commit()

    settings_columns = db.session.execute(text('PRAGMA table_info(settings)')).all()
    settings_column_names = {col[1] for col in settings_columns}
    if 'active_category_id' not in settings_column_names:
        db.session.execute(text("ALTER TABLE settings ADD COLUMN active_category_id INTEGER"))
        db.session.commit()
    if 'active_set_at' not in settings_column_names:
        db.session.execute(text("ALTER TABLE settings ADD COLUMN active_set_at DATETIME"))
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

def get_round_categories(round_name):
    return Category.query.filter_by(round=round_name).order_by(Category.order).all()

def normalize_division(value):
    value = (value or '').strip().lower()
    if value in DIVISION_VALUES:
        return value
    return 'unspecified'

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def read_contestant_photo(file_storage):
    if not file_storage or not file_storage.filename:
        return None, None
    if not allowed_image_file(file_storage.filename):
        return None, None
    file_bytes = file_storage.read()
    if not file_bytes:
        return None, None
    mime_type = file_storage.mimetype or 'image/jpeg'
    return file_bytes, mime_type

def build_photo_data_url(contestant):
    if not contestant.photo_data or not contestant.photo_mime:
        return None
    encoded = base64.b64encode(contestant.photo_data).decode('ascii')
    return f"data:{contestant.photo_mime};base64,{encoded}"

def get_divisions():
    raw_divisions = [row[0] for row in db.session.query(Contestant.division).distinct().all() if row[0]]
    divisions = list({normalize_division(value) for value in raw_divisions})
    if not divisions:
        return []
    ordered = [value for value in DIVISION_VALUES if value in divisions]
    extras = sorted(value for value in divisions if value not in DIVISION_VALUES)
    return ordered + extras

def get_contestants_by_division(division):
    return Contestant.query.filter_by(division=division).order_by(Contestant.number).all()

def get_eligible_contestants_by_category(category):
    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}

    if category.round == 'round1':
        return flatten_contestants(contestants_by_division)

    round1_categories = get_round_categories('round1')
    round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)

    if category.round == 'round2':
        return flatten_contestants(top5_by_division)

    round2_categories = get_round_categories('round2')
    round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
    return flatten_contestants(top3_by_division)

def get_category_score_completion(category, judges_count):
    criteria = Criteria.query.filter_by(category_id=category.id).all()
    if not criteria or judges_count == 0:
        return 0, 0, False
    contestants = get_eligible_contestants_by_category(category)
    contestant_ids = [contestant.id for contestant in contestants]
    expected_scores = len(contestant_ids) * len(criteria) * judges_count
    if expected_scores == 0:
        return 0, 0, False
    actual_scores = 0
    if contestant_ids:
        actual_scores = Score.query.filter_by(category_id=category.id) \
            .filter(Score.contestant_id.in_(contestant_ids)).count()
    return actual_scores, expected_scores, actual_scores >= expected_scores

def all_judges_transmitted_for_categories(categories, judges_count):
    if not categories or judges_count == 0:
        return False
    category_ids = [category.id for category in categories]
    transmitted = JudgeSubmission.query.filter(JudgeSubmission.category_id.in_(category_ids)).all()
    submissions_by_category = {}
    for submission in transmitted:
        submissions_by_category.setdefault(submission.category_id, set()).add(submission.judge_id)
    for category_id in category_ids:
        if len(submissions_by_category.get(category_id, set())) < judges_count:
            return False
    return True

def get_completed_categories_by_submission(categories, judges_count):
    if not categories or judges_count == 0:
        return []
    category_ids = [category.id for category in categories]
    transmitted = JudgeSubmission.query.filter(JudgeSubmission.category_id.in_(category_ids)).all()
    submissions_by_category = {}
    for submission in transmitted:
        submissions_by_category.setdefault(submission.category_id, set()).add(submission.judge_id)
    completed = []
    for category in categories:
        if len(submissions_by_category.get(category.id, set())) >= judges_count:
            completed.append(category)
    return completed

def build_results_payload(round_categories, contestants_by_division):
    results_by_division = compute_results_by_division(round_categories, contestants_by_division)
    divisions_payload = {}
    for division, results in results_by_division.items():
        divisions_payload[division] = [
            {
                'rank': result['rank'],
                'contestant': {
                    'number': result['contestant'].number,
                    'name': result['contestant'].name,
                    'division': result['contestant'].division
                },
                'category_scores': result['category_scores'],
                'total_score': result['total_score']
            }
            for result in results
        ]
    return divisions_payload

def build_category_payload(categories):
    return [{'name': category.name, 'percentage': category.percentage} for category in categories]

def build_judge_breakdown(categories):
    breakdown = {}
    judges = Judge.query.order_by(Judge.number).all()
    judges_payload = {judge.id: {'number': judge.number, 'name': judge.name} for judge in judges}

    for category in categories:
        criteria_list = Criteria.query.filter_by(category_id=category.id).order_by(Criteria.order).all()
        category_entry = {}
        contestants = get_eligible_contestants_by_category(category)
        contestant_lookup = {contestant.id: contestant for contestant in contestants}

        for criterion in criteria_list:
            judge_scores = {}
            scores = Score.query.filter_by(category_id=category.id, criteria_id=criterion.id).all()
            for score in scores:
                judge_info = judges_payload.get(score.judge_id)
                contestant = contestant_lookup.get(score.contestant_id)
                if not judge_info or not contestant:
                    continue
                judge_key = f"{judge_info['number']} - {judge_info['name']}"
                judge_scores.setdefault(judge_key, []).append({
                    'contestant_number': contestant.number,
                    'contestant_name': contestant.name,
                    'score': score.score
                })
            category_entry[criterion.name] = judge_scores

        breakdown[category.name] = category_entry
    return breakdown

def build_judge_scores_overview(categories, criteria_by_category):
    judges = Judge.query.order_by(Judge.number).all()
    judge_map = {judge.id: {'judge': judge, 'contestants': {}} for judge in judges}

    score_rows = db.session.query(Score, Contestant, Category, Criteria) \
        .join(Contestant, Score.contestant_id == Contestant.id) \
        .join(Category, Score.category_id == Category.id) \
        .join(Criteria, Score.criteria_id == Criteria.id) \
        .order_by(Score.judge_id, Category.order, Criteria.order, Contestant.number) \
        .all()

    for score, contestant, category, criteria in score_rows:
        judge_entry = judge_map.get(score.judge_id)
        if not judge_entry:
            continue
        contestant_entry = judge_entry['contestants'].setdefault(
            contestant.id,
            {'contestant': contestant, 'categories': {}}
        )
        category_entry = contestant_entry['categories'].setdefault(
            category.id,
            {'category': category, 'criteria_scores': {}}
        )
        category_entry['criteria_scores'][criteria.id] = score.score

    judge_entries = []
    for judge in judges:
        contestant_entries = list(judge_map[judge.id]['contestants'].values())
        contestant_entries.sort(key=lambda entry: entry['contestant'].number)
        judge_entries.append({
            'judge': judge,
            'contestants': contestant_entries
        })

    return judge_entries

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
        if not results:
            top_by_division[division] = []
            continue
        if len(results) <= limit:
            top_by_division[division] = [r['contestant'] for r in results]
            continue
        cutoff_score = results[limit - 1]['total_score']
        tied_results = [r for r in results if r['total_score'] >= cutoff_score]
        top_by_division[division] = [r['contestant'] for r in tied_results]
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

def emit_realtime_update(event_name, payload=None):
    try:
        socketio.emit(event_name, payload or {})
    except Exception:
        pass

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
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()
    return dict(competition_title=settings.competition_title)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        ensure_default_admin()
        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            session.clear()
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role or 'admin'
            flash('Login successful!', 'success')
            log_event('login_success', f'username={user.username}', user=user)
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        judge = Judge.query.filter_by(username=username).first()
        if judge and judge.is_active and judge.check_password(password):
            session.clear()
            session['judge_logged_in'] = True
            session['judge_id'] = judge.id
            session['judge_username'] = judge.username
            judge.is_logged_in = True
            judge.last_login_at = datetime.utcnow()
            db.session.commit()
            emit_realtime_update('portal_update', {'judge_id': judge.id, 'logged_in': True})
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('judge_portal'))

        flash('Invalid username or password.', 'error')
        log_event('login_failed', f'username={username}')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_event('logout', f'username={user.username}', user=user)
    judge_id = session.get('judge_id')
    if judge_id:
        judge = Judge.query.get(judge_id)
        if judge:
            judge.is_logged_in = False
            db.session.commit()
            emit_realtime_update('portal_update', {'judge_id': judge.id, 'logged_in': False})
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/judge/login', methods=['GET', 'POST'])
def judge_login():
    return login()

@app.route('/judge/logout')
def judge_logout():
    judge_id = session.get('judge_id')
    if judge_id:
        judge = Judge.query.get(judge_id)
        if judge:
            judge.is_logged_in = False
            db.session.commit()
            emit_realtime_update('portal_update', {'judge_id': judge.id, 'logged_in': False})
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/judge/portal')
@judge_login_required
def judge_portal():
    judge = Judge.query.get_or_404(session.get('judge_id'))
    judge.last_portal_at = datetime.utcnow()
    db.session.commit()
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    categories = Category.query.order_by(Category.order).all()
    if not categories:
        return render_template(
            'judge_portal.html',
            judge=judge,
            categories=[],
            category=None,
            criteria=[],
            active_criteria=None,
            contestants=[],
            scores={},
            score_matrix={},
            all_scored=False,
            submitted=False,
            category_locked=False,
            active_category_id=settings.active_category_id,
            active_category_name=None,
            scoring_enabled=False
        )

    active_category_id = settings.active_category_id
    if not active_category_id:
        return render_template(
            'judge_portal.html',
            judge=judge,
            categories=categories,
            category=None,
            criteria=[],
            active_criteria=None,
            contestants=[],
            scores={},
            score_matrix={},
            all_scored=False,
            submitted=False,
            category_locked=False,
            active_category_id=None,
            active_category_name=None,
            scoring_enabled=False
        )

    category = Category.query.get_or_404(active_category_id)
    criteria = Criteria.query.filter_by(category_id=category.id).order_by(Criteria.order).all()
    if not criteria:
        return render_template(
            'judge_portal.html',
            judge=judge,
            categories=categories,
            category=category,
            criteria=[],
            active_criteria=None,
            contestants=[],
            scores={},
            score_matrix={},
            all_scored=False,
            submitted=False,
            category_locked=category.is_locked,
            active_category_id=active_category_id,
            active_category_name=category.name,
            scoring_enabled=False
        )

    criteria_id = request.args.get('criteria_id', type=int) or criteria[0].id
    active_criteria = next((c for c in criteria if c.id == criteria_id), criteria[0])

    contestants = get_eligible_contestants_by_category(category)
    for contestant in contestants:
        contestant.photo_data_url = build_photo_data_url(contestant)
    contestant_ids = [contestant.id for contestant in contestants]
    score_rows = Score.query.filter_by(
        judge_id=judge.id,
        category_id=category.id
    )
    if contestant_ids:
        score_rows = score_rows.filter(Score.contestant_id.in_(contestant_ids))
    score_rows = score_rows.all()
    score_matrix = {}
    for row in score_rows:
        score_matrix.setdefault(row.criteria_id, {})[row.contestant_id] = row.score
    scores = score_matrix.get(active_criteria.id, {})

    submission = JudgeSubmission.query.filter_by(judge_id=judge.id, category_id=category.id).first()
    submitted = bool(submission)

    expected_scores = len(contestants) * len(criteria)
    actual_scores = 0
    if contestant_ids:
        actual_scores = Score.query.filter_by(judge_id=judge.id, category_id=category.id) \
            .filter(Score.contestant_id.in_(contestant_ids)).count()
    all_scored = expected_scores > 0 and actual_scores >= expected_scores

    return render_template(
        'judge_portal.html',
        judge=judge,
        categories=categories,
        category=category,
        criteria=criteria,
        active_criteria=active_criteria,
        contestants=contestants,
        scores=scores,
        score_matrix=score_matrix,
        all_scored=all_scored,
        submitted=submitted,
        category_locked=category.is_locked,
        active_category_id=active_category_id,
        active_category_name=category.name,
        scoring_enabled=True
    )

@app.route('/judge/score', methods=['POST'])
@judge_login_required
def judge_score():
    data = request.get_json(silent=True) or {}
    contestant_id = data.get('contestant_id')
    criteria_id = data.get('criteria_id')
    score_value = data.get('score')

    if contestant_id is None or criteria_id is None or score_value is None:
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400

    try:
        score_value = float(score_value)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid score value.'}), 400

    if score_value < 0 or score_value > 10:
        return jsonify({'success': False, 'message': 'Score must be between 0 and 10.'}), 400

    judge_id = session.get('judge_id')
    criteria = Criteria.query.get_or_404(criteria_id)
    category = Category.query.get_or_404(criteria.category_id)
    settings = Settings.query.first()
    if not settings or settings.active_category_id != category.id:
        return jsonify({'success': False, 'message': 'No active category for scoring.'}), 400

    if category.is_locked:
        return jsonify({'success': False, 'message': 'This category is locked.'}), 400

    submission = JudgeSubmission.query.filter_by(judge_id=judge_id, category_id=category.id).first()
    if submission:
        return jsonify({'success': False, 'message': 'Scores already transmitted.'}), 400

    contestants = get_eligible_contestants_by_category(category)
    contestant_ids = {contestant.id for contestant in contestants}
    if contestant_id not in contestant_ids:
        return jsonify({'success': False, 'message': 'Contestant not eligible for this round.'}), 400

    existing = Score.query.filter_by(
        judge_id=judge_id,
        contestant_id=contestant_id,
        category_id=category.id,
        criteria_id=criteria.id
    ).first()

    if existing:
        existing.score = score_value
    else:
        db.session.add(Score(
            judge_id=judge_id,
            contestant_id=contestant_id,
            category_id=category.id,
            criteria_id=criteria.id,
            score=score_value
        ))

    db.session.commit()
    emit_realtime_update('scores_update', {'category_id': category.id})
    return jsonify({'success': True, 'score': score_value})

@app.route('/judge/transmit', methods=['POST'])
@judge_login_required
def judge_transmit():
    data = request.get_json(silent=True) or {}
    category_id = data.get('category_id')
    if category_id is None:
        return jsonify({'success': False, 'message': 'Category is required.'}), 400

    judge_id = session.get('judge_id')
    category = Category.query.get_or_404(category_id)
    settings = Settings.query.first()
    if not settings or settings.active_category_id != category.id:
        return jsonify({'success': False, 'message': 'No active category for scoring.'}), 400
    if category.is_locked:
        return jsonify({'success': False, 'message': 'This category is locked.'}), 400

    criteria = Criteria.query.filter_by(category_id=category.id).all()
    contestants = get_eligible_contestants_by_category(category)
    contestant_ids = [contestant.id for contestant in contestants]
    expected_scores = len(contestants) * len(criteria)
    actual_scores = 0
    if contestant_ids:
        actual_scores = Score.query.filter_by(judge_id=judge_id, category_id=category.id) \
            .filter(Score.contestant_id.in_(contestant_ids)).count()

    if expected_scores == 0 or actual_scores < expected_scores:
        return jsonify({'success': False, 'message': 'Complete all scores before transmitting.'}), 400

    existing = JudgeSubmission.query.filter_by(judge_id=judge_id, category_id=category.id).first()
    if existing:
        return jsonify({'success': False, 'message': 'Scores already transmitted.'}), 400

    db.session.add(JudgeSubmission(judge_id=judge_id, category_id=category.id))
    db.session.commit()
    emit_realtime_update('scores_update', {'category_id': category.id, 'transmit': True})
    return jsonify({'success': True})

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

@app.route('/admin/live-monitoring')
@admin_required
def live_monitoring():
    categories = Category.query.order_by(Category.order).all()
    active_judges = Judge.query.filter_by(is_active=True).order_by(Judge.number.asc()).all()
    total_judges = len(active_judges)

    categories_data = []
    for category in categories:
        actual_scores, expected_scores, complete = get_category_score_completion(category, total_judges)
        percent = round((actual_scores / expected_scores) * 100, 1) if expected_scores else 0
        categories_data.append({
            'category': category,
            'actual_scores': actual_scores,
            'expected_scores': expected_scores,
            'percent': percent,
            'complete': complete
        })

    now = datetime.utcnow()
    portal_active_window = timedelta(minutes=5)
    judges_data = []
    for judge in active_judges:
        in_portal = False
        if judge.is_logged_in and judge.last_portal_at:
            in_portal = (now - judge.last_portal_at) <= portal_active_window
        judges_data.append({
            'judge': judge,
            'logged_in': bool(judge.is_logged_in),
            'in_portal': in_portal,
            'last_login_at': judge.last_login_at,
            'last_portal_at': judge.last_portal_at
        })

    return render_template(
        'live_monitoring.html',
        categories_data=categories_data,
        judges_data=judges_data,
        total_judges=total_judges,
        portal_window_minutes=int(portal_active_window.total_seconds() // 60)
    )

@app.route('/admin/scores')
@admin_required
def judge_scores():
    categories = Category.query.order_by(Category.order).all()
    criteria_by_category = {
        category.id: Criteria.query.filter_by(category_id=category.id).order_by(Criteria.order).all()
        for category in categories
    }
    judge_entries = build_judge_scores_overview(categories, criteria_by_category)

    return render_template(
        'judge_scores.html',
        judge_entries=judge_entries,
        categories=categories,
        criteria_by_category=criteria_by_category
    )

@socketio.on('portal_ping')
def handle_portal_ping(data=None):
    judge_id = session.get('judge_id')
    if not judge_id:
        return
    judge = Judge.query.get(judge_id)
    if not judge:
        return
    judge.is_logged_in = True
    judge.last_portal_at = datetime.utcnow()
    db.session.commit()
    emit_realtime_update('portal_update', {'judge_id': judge.id, 'active': True})

@app.route('/admin/users')
@admin_required
def admin_users():
    ensure_default_admin()
    users = User.query.order_by(User.username.asc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_users_create():
    ensure_default_admin()
    current_user = get_current_user()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'admin').strip().lower()

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('admin_users'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('admin_users'))

    if role not in {'admin', 'tabulator'}:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('admin_users'))

    user = User(username=username, role=role)
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

@app.route('/admin/password', methods=['GET', 'POST'])
@staff_required
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
    return render_template('index.html')

@app.route('/admin/settings')
@admin_required
def admin_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    return render_template('admin_settings.html', show_category_winners=settings.show_category_winners)
@app.route('/competition-settings', methods=['GET', 'POST'])
@admin_required
def competition_settings():
    """Manage competition settings like title"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        competition_title = request.form.get('competition_title', '').strip()
        
        if not competition_title:
            flash('Competition title cannot be empty!', 'error')
        else:
            settings.competition_title = competition_title
            settings.updated_at = datetime.utcnow()
            db.session.commit()
            flash('Competition settings updated successfully!', 'success')
            return redirect(url_for('competition_settings'))
    
    return render_template('competition_settings.html', settings=settings)

@app.route('/admin/competition/close', methods=['POST'])
@admin_required
def close_competition():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}

    round1_categories = get_round_categories('round1')
    round2_categories = get_round_categories('round2')
    round3_categories = get_round_categories('round3')

    round1_results = build_results_payload(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(
        compute_results_by_division(round1_categories, contestants_by_division),
        5
    )
    round2_results = build_results_payload(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(
        compute_results_by_division(round2_categories, top5_by_division),
        3
    )
    round3_results = build_results_payload(round3_categories, top3_by_division)

    results_payload = {
        'round1': {
            'categories': build_category_payload(round1_categories),
            'results_by_division': round1_results
        },
        'round2': {
            'categories': build_category_payload(round2_categories),
            'results_by_division': round2_results
        },
        'round3': {
            'categories': build_category_payload(round3_categories),
            'results_by_division': round3_results
        }
    }

    breakdown_payload = build_judge_breakdown(round1_categories + round2_categories + round3_categories)

    history_entry = CompetitionHistory(
        competition_title=settings.competition_title,
        closed_at=datetime.utcnow(),
        results_json=json.dumps(results_payload),
        breakdown_json=json.dumps(breakdown_payload)
    )
    db.session.add(history_entry)

    Score.query.delete()
    JudgeSubmission.query.delete()
    Criteria.query.delete()
    Category.query.delete()
    Contestant.query.delete()
    Judge.query.delete()
    settings.active_category_id = None
    settings.active_set_at = None
    db.session.commit()

    log_event('competition_closed', f'competition_title={settings.competition_title}')
    flash('Competition closed. Results saved to history and scoring data reset.', 'success')
    return redirect(url_for('history'))

@app.route('/admin/history')
@admin_required
def history():
    entries = CompetitionHistory.query.order_by(CompetitionHistory.closed_at.desc()).all()
    return render_template('history.html', entries=entries)

@app.route('/admin/history/<int:history_id>')
@admin_required
def history_view(history_id):
    entry = CompetitionHistory.query.get_or_404(history_id)
    results_payload = json.loads(entry.results_json)
    breakdown_payload = json.loads(entry.breakdown_json)
    return render_template(
        'history_results.html',
        entry=entry,
        results_payload=results_payload,
        breakdown_payload=breakdown_payload
    )

@app.route('/admin/history/<int:history_id>/pdf')
@admin_required
def history_pdf(history_id):
    entry = CompetitionHistory.query.get_or_404(history_id)
    results_payload = json.loads(entry.results_json)

    round_candidates = ['round3', 'round2', 'round1']
    selected_round = None
    for round_key in round_candidates:
        round_data = results_payload.get(round_key, {})
        if round_data.get('categories') and round_data.get('results_by_division'):
            selected_round = round_data
            break
    if not selected_round:
        flash('No results available for this competition.', 'warning')
        return redirect(url_for('history_view', history_id=history_id))

    categories = selected_round.get('categories', [])
    all_results = selected_round.get('results_by_division', {})

    results_data = []
    for division_results in all_results.values():
        for result in division_results:
            contestant = SimpleNamespace(**result['contestant'])
            results_data.append({
                'rank': result['rank'],
                'contestant': contestant,
                'category_scores': result['category_scores'],
                'total_score': result['total_score']
            })

    category_objs = [SimpleNamespace(**category) for category in categories]
    settings = Settings.query.first() or Settings(competition_title=entry.competition_title)
    settings.competition_title = entry.competition_title

    return build_results_pdf_response(
        categories=category_objs,
        results_data=results_data,
        settings=settings,
        header_label='FINAL RESULTS',
        include_winners=False,
        include_division_column=True,
        filename_suffix=f"history_{entry.id}"
    )

@app.route('/admin/scoring-control')
@admin_required
def scoring_control():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    categories = Category.query.order_by(Category.order).all()
    judges_count = Judge.query.count()
    entries = []
    for category in categories:
        criteria_count = Criteria.query.filter_by(category_id=category.id).count()
        actual, expected, complete = get_category_score_completion(category, judges_count)
        is_active = settings.active_category_id == category.id
        submitted_judges = JudgeSubmission.query.filter_by(category_id=category.id).count()
        all_transmitted = judges_count > 0 and submitted_judges >= judges_count
        entries.append({
            'category': category,
            'criteria_count': criteria_count,
            'expected': expected,
            'actual': actual,
            'complete': complete,
            'is_active': is_active,
            'activate_disabled': settings.active_category_id is not None and not is_active,
            'can_lock': is_active and not category.is_locked and all_transmitted
        })

    active_category = None
    if settings.active_category_id:
        active_category = Category.query.get(settings.active_category_id)

    return render_template(
        'scoring_control.html',
        entries=entries,
        active_category=active_category
    )

@app.route('/admin/scoring-control/activate/<int:category_id>', methods=['POST'])
@admin_required
def scoring_control_activate(category_id):
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    category = Category.query.get_or_404(category_id)
    if category.is_locked:
        flash('Cannot activate a locked category.', 'error')
        return redirect(url_for('scoring_control'))

    if settings.active_category_id and settings.active_category_id != category.id:
        flash('Another category is already active. Deactivate it first.', 'warning')
        return redirect(url_for('scoring_control'))

    settings.active_category_id = category.id
    settings.active_set_at = datetime.utcnow()
    db.session.commit()
    emit_realtime_update('category_update', {
        'active_category_id': settings.active_category_id,
        'locked_category_id': None
    })
    flash(f'Category "{category.name}" is now active for scoring.', 'success')
    return redirect(url_for('scoring_control'))

@app.route('/admin/scoring-control/deactivate', methods=['POST'])
@admin_required
def scoring_control_deactivate():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    settings.active_category_id = None
    settings.active_set_at = None
    db.session.commit()
    emit_realtime_update('category_update', {
        'active_category_id': None,
        'locked_category_id': None
    })
    flash('Scoring has been deactivated.', 'success')
    return redirect(url_for('scoring_control'))

@app.route('/toggle-category-winners', methods=['POST'])
@admin_required
def toggle_category_winners():
    """Toggle the display of category winners in results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
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
    all_categories = Category.query.order_by(Category.order).all()
    round1_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
    return render_template('categories.html', categories=all_categories, round1_total=round1_total)

@app.route('/category/add', methods=['GET', 'POST'])
@admin_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        round_name = request.form.get('round', 'round1')

        if round_name in ['round2', 'round3']:
            existing_round = Category.query.filter_by(round=round_name).first()
            if existing_round:
                flash(f'Only one category is allowed for {round_name.title()}.', 'error')
                return render_template('add_category.html')
            if percentage != 100:
                flash('Round 2 and Round 3 categories must be 100%.', 'error')
                return render_template('add_category.html')
        
        # Check total percentage for Round 1 only
        if round_name == 'round1':
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
            new_total = current_total + percentage

            if new_total > 100:
                flash(f'Cannot add category. Round 1 total would be {new_total}%. Categories must total 100%.', 'error')
                return render_template('add_category.html')
        
        # Get the next order number
        max_order = db.session.query(db.func.max(Category.order)).scalar() or 0
        
        category = Category(name=name, percentage=percentage, order=max_order + 1, round=round_name)
        db.session.add(category)
        db.session.commit()

        if round_name == 'round1':
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
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
    
    # Safety check: don't allow editing if category is locked
    if category.is_locked:
        flash('Cannot edit a locked category. Unlock it first.', 'error')
        return redirect(url_for('categories'))
    
    if request.method == 'POST':
        new_percentage = float(request.form.get('percentage'))
        new_round = request.form.get('round', category.round)

        if new_round in ['round2', 'round3']:
            existing_round = Category.query.filter_by(round=new_round).filter(Category.id != category_id).first()
            if existing_round:
                flash(f'Only one category is allowed for {new_round.title()}.', 'error')
                return render_template('edit_category.html', category=category)
            if new_percentage != 100:
                flash('Round 2 and Round 3 categories must be 100%.', 'error')
                return render_template('edit_category.html', category=category)
        
        # Check total percentage for Round 1 only
        if new_round == 'round1':
            other_categories_total = db.session.query(db.func.sum(Category.percentage)).filter(
                Category.round == 'round1', Category.id != category_id
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
            current_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
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
    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}
    for division_contestants in contestants_by_division.values():
        for contestant in division_contestants:
            contestant.photo_data_url = build_photo_data_url(contestant)
    total_contestants = sum(len(items) for items in contestants_by_division.values())
    return render_template(
        'contestants.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        contestants_by_division=contestants_by_division,
        total_contestants=total_contestants
    )


@app.route('/contestant/<int:contestant_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_contestant(contestant_id):
    contestant = Contestant.query.get_or_404(contestant_id)
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        new_division = normalize_division(request.form.get('division'))
        photo_file = request.files.get('photo')
        
        # Safety check: if number or division changed, make sure it's not already taken
        if new_number != contestant.number or new_division != contestant.division:
            existing = Contestant.query.filter_by(number=new_number, division=new_division).first()
            if existing and existing.id != contestant.id:
                flash(f'Contestant number {new_number} already exists in {DIVISION_LABELS.get(new_division, new_division)} division!', 'error')
                return render_template('edit_contestant.html', contestant=contestant, division_labels=DIVISION_LABELS)
        
        contestant.number = new_number
        contestant.name = new_name
        contestant.division = new_division

        if photo_file and photo_file.filename:
            if not allowed_image_file(photo_file.filename):
                flash('Invalid image type. Use png, jpg, jpeg, or gif.', 'error')
                return render_template('edit_contestant.html', contestant=contestant, division_labels=DIVISION_LABELS)
            photo_data, photo_mime = read_contestant_photo(photo_file)
            if photo_data:
                contestant.photo_data = photo_data
                contestant.photo_mime = photo_mime
                contestant.photo_filename = None
        db.session.commit()
        
        flash(f'Contestant #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('edit_contestant.html', contestant=contestant, division_labels=DIVISION_LABELS)

@app.route('/judges')
@admin_required
def judges():
    all_judges = Judge.query.order_by(Judge.number).all()
    return render_template('judges.html', judges=all_judges)

@app.route('/judge/add', methods=['GET', 'POST'])
@admin_required
def add_judge():
    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Check if number already exists
        existing = Judge.query.filter_by(number=number).first()
        if existing:
            flash(f'Judge number {number} already exists!', 'error')
            return render_template('add_judge.html')
        
        if not username or not password:
            flash('Username and password are required for judge login.', 'error')
            return render_template('add_judge.html')

        if Judge.query.filter_by(username=username).first():
            flash('Judge username already exists!', 'error')
            return render_template('add_judge.html')

        judge = Judge(number=number, name=name, username=username)
        judge.set_password(password)
        db.session.add(judge)
        db.session.commit()
        
        flash(f'Judge #{number} - {name} added successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('add_judge.html')

@app.route('/judge/<int:judge_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '')
        
        # Safety check: if number changed, make sure it's not already taken
        if new_number != judge.number:
            existing = Judge.query.filter_by(number=new_number).first()
            if existing:
                flash(f'Judge number {new_number} is already taken!', 'error')
                return render_template('edit_judge.html', judge=judge)

        if not new_username:
            flash('Username is required.', 'error')
            return render_template('edit_judge.html', judge=judge)

        if new_username != judge.username:
            existing_username = Judge.query.filter_by(username=new_username).first()
            if existing_username:
                flash('Judge username is already taken!', 'error')
                return render_template('edit_judge.html', judge=judge)
        
        judge.number = new_number
        judge.name = new_name
        judge.username = new_username
        if new_password:
            judge.set_password(new_password)
        db.session.commit()
        
        flash(f'Judge #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('edit_judge.html', judge=judge)

@app.route('/judge/<int:judge_id>/delete', methods=['POST'])
@admin_required
def delete_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    
    # Safety check: warn if judge has scores
    score_count = Score.query.filter_by(judge_id=judge_id).count()
    if score_count > 0:
        flash(f'Warning: Deleted judge #{judge.number} - {judge.name} who had {score_count} scores.', 'warning')
    
    judge_info = f"#{judge.number} - {judge.name}"
    JudgeSubmission.query.filter_by(judge_id=judge_id).delete()
    db.session.delete(judge)
    db.session.commit()
    
    flash(f'Judge {judge_info} deleted successfully!', 'success')
    return redirect(url_for('judges'))

@app.route('/contestant/add', methods=['GET', 'POST'])
@admin_required
def add_contestant():
    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        division_raw = request.form.get('division')
        photo_file = request.files.get('photo')
        if not division_raw:
            flash('Division is required.', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)
        division = normalize_division(division_raw)
        
        # Check if number already exists
        existing = Contestant.query.filter_by(number=number, division=division).first()
        if existing:
            flash(f'Contestant number {number} already exists in {DIVISION_LABELS.get(division, division)} division!', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)

        if photo_file and photo_file.filename:
            if not allowed_image_file(photo_file.filename):
                flash('Invalid image type. Use png, jpg, jpeg, or gif.', 'error')
                return render_template('add_contestant.html', division_labels=DIVISION_LABELS)
            photo_data, photo_mime = read_contestant_photo(photo_file)
        else:
            photo_data, photo_mime = None, None
        
        contestant = Contestant(
            number=number,
            name=name,
            division=division,
            photo_filename=None,
            photo_data=photo_data,
            photo_mime=photo_mime
        )
        db.session.add(contestant)
        db.session.commit()
        
        flash(f'Contestant #{number} - {name} added successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('add_contestant.html', division_labels=DIVISION_LABELS)

@app.route('/scoring')
@staff_required
def scoring_menu():
    categories = Category.query.order_by(Category.order).all()
    contestants_count = Contestant.query.count()
    judges = Judge.query.all()
    judges_count = len(judges)

    round1_categories = get_round_categories('round1')
    round2_categories = get_round_categories('round2')
    divisions = get_divisions()

    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}
    round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
    top5_contestants = flatten_contestants(top5_by_division)

    round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)
    top3_contestants = flatten_contestants(top3_by_division)

    criteria_status_by_category = {}
    for category in categories:
        criteria_list = Criteria.query.filter_by(category_id=category.id).order_by(Criteria.order).all()
        if category.round == 'round1':
            eligible_by_division = contestants_by_division
        elif category.round == 'round2':
            eligible_by_division = top5_by_division
        else:
            eligible_by_division = top3_by_division

        contestants = flatten_contestants(eligible_by_division)
        contestant_ids = [contestant.id for contestant in contestants]
        expected_per_criteria = len(contestant_ids) * judges_count
        status_rows = []

        for criterion in criteria_list:
            actual_count = 0
            if contestant_ids:
                actual_count = Score.query.filter_by(category_id=category.id, criteria_id=criterion.id) \
                    .filter(Score.contestant_id.in_(contestant_ids)).count()
            complete = expected_per_criteria > 0 and actual_count >= expected_per_criteria
            status_rows.append({
                'id': criterion.id,
                'name': criterion.name,
                'actual': actual_count,
                'expected': expected_per_criteria,
                'complete': complete
            })
        criteria_status_by_category[category.id] = status_rows
    
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
        judges_count=judges_count,
        criteria_status_by_category=criteria_status_by_category
    )

@app.route('/scoring/<int:category_id>')
@staff_required
def scoring(category_id):
    category = Category.query.get_or_404(category_id)
    if category.is_locked and session.get('role') != 'tabulator':
        flash('This category is already locked!', 'warning')
        return redirect(url_for('scoring_menu'))
    
    round1_categories = get_round_categories('round1')
    round2_categories = get_round_categories('round2')

    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}
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
    judges = Judge.query.order_by(Judge.number).all()
    
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
@staff_required
def save_scores(category_id):
    category = Category.query.get_or_404(category_id)
    if category.is_locked and session.get('role') != 'tabulator':
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    data = request.get_json()
    scores_data = data.get('scores', [])
    judge_id = data.get('judge_id')
    
    if not judge_id:
        return jsonify({'success': False, 'message': 'Judge ID is required'}), 400
    
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
    emit_realtime_update('scores_update', {'category_id': category_id})
    
    return jsonify({'success': True, 'message': 'Scores saved successfully'})

@app.route('/category/<int:category_id>/lock', methods=['POST'])
@admin_required
def lock_category(category_id):
    category = Category.query.get_or_404(category_id)

    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()

    if not settings.active_category_id:
        return jsonify({'success': False, 'message': 'No active category selected for scoring.'}), 400

    if settings.active_category_id != category.id:
        return jsonify({'success': False, 'message': 'Only the active category can be locked.'}), 400
    
    if category.is_locked:
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    # Check if criteria percentages total 100%
    criteria_total = db.session.query(db.func.sum(Criteria.percentage)).filter_by(category_id=category_id).scalar() or 0
    if criteria_total != 100:
        return jsonify({'success': False, 'message': f'Cannot lock category. Criteria percentages total {criteria_total}%. Must equal 100%.'}), 400
    
    # Check if all Round 1 category percentages total 100%
    if category.round == 'round1':
        all_categories_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
        if all_categories_total != 100:
            return jsonify({'success': False, 'message': f'Cannot lock category. Round 1 categories total {all_categories_total}%. Must equal 100%.'}), 400
    
    # Check if all required contestants have scores for all criteria from all judges
    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}
    contestants = flatten_contestants(contestants_by_division)
    if category.round == 'round2':
        round1_categories = get_round_categories('round1')
        if not round1_categories:
            return jsonify({'success': False, 'message': 'Round 1 categories are required before locking Round 2.'}), 400
        round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
        top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
        contestants = flatten_contestants(top5_by_division)
    elif category.round == 'round3':
        round1_categories = get_round_categories('round1')
        round2_categories = get_round_categories('round2')
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
    judges = Judge.query.all()

    contestant_ids = [c.id for c in contestants]
    expected_scores = len(contestants) * len(criteria) * len(judges)
    actual_scores = Score.query.filter_by(category_id=category_id).filter(Score.contestant_id.in_(contestant_ids)).count()
    
    if actual_scores < expected_scores:
        return jsonify({'success': False, 'message': f'Please ensure all {len(judges)} judges have scored all contestants before locking'}), 400
    
    category.is_locked = True
    settings.active_category_id = None
    settings.active_set_at = None
    db.session.commit()

    emit_realtime_update('category_update', {
        'active_category_id': None,
        'locked_category_id': category_id
    })
    emit_realtime_update('scores_update', {'category_id': category_id})

    log_event('category_locked', f'category_id={category_id} category_name={category.name}')
    
    return jsonify({'success': True, 'message': f'Category "{category.name}" has been locked'})


@app.route('/results')
@staff_required
def results():
    categories = Category.query.order_by(Category.order).all()
    judges = Judge.query.all()
    read_only_mode = session.get('role') == 'admin'
    judges_count = len(judges)
    
    # Get settings
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    
    def category_ready_by_submission(category):
        if judges_count == 0:
            return False
        submitted_judges = JudgeSubmission.query.filter_by(category_id=category.id).all()
        judge_ids = {submission.judge_id for submission in submitted_judges}
        return len(judge_ids) >= judges_count

    def category_ready_by_scores(category):
        _, _, complete = get_category_score_completion(category, judges_count)
        return complete

    # Check if all categories are locked (per round)
    all_locked = all(cat.is_locked for cat in categories)
    
    round1_categories = get_round_categories('round1')
    round2_categories = get_round_categories('round2')
    round3_categories = get_round_categories('round3')

    if read_only_mode:
        round1_complete = [c for c in round1_categories if category_ready_by_scores(c)]
        round2_complete = [c for c in round2_categories if category_ready_by_scores(c)]
        round3_complete = [c for c in round3_categories if category_ready_by_scores(c)]
    else:
        round1_complete = [c for c in round1_categories if category_ready_by_submission(c)]
        round2_complete = [c for c in round2_categories if category_ready_by_submission(c)]
        round3_complete = [c for c in round3_categories if category_ready_by_submission(c)]

    round1_locked = bool(round1_categories) and all(cat.is_locked for cat in round1_categories)
    round2_locked = bool(round2_categories) and all(cat.is_locked for cat in round2_categories)
    round3_locked = bool(round3_categories) and all(cat.is_locked for cat in round3_categories)

    if read_only_mode:
        round1_locked = round1_locked or bool(round1_complete)
        round2_locked = round2_locked or bool(round2_complete)
        round3_locked = round3_locked or bool(round3_complete)
        all_locked = all_locked or all_judges_transmitted_for_categories(categories, judges_count)

    round1_display_categories = round1_categories if round1_locked and not read_only_mode else round1_complete
    round2_display_categories = round2_categories if round2_locked and not read_only_mode else round2_complete
    round3_display_categories = round3_categories if round3_locked and not read_only_mode else round3_complete

    round1_partial = read_only_mode and not all(cat.is_locked for cat in round1_categories) and bool(round1_display_categories)
    round2_partial = read_only_mode and not all(cat.is_locked for cat in round2_categories) and bool(round2_display_categories)
    round3_partial = read_only_mode and not all(cat.is_locked for cat in round3_categories) and bool(round3_display_categories)

    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}

    round1_results_by_division = compute_results_by_division(round1_display_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)

    round2_results_by_division = compute_results_by_division(round2_display_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)

    round3_results_by_division = compute_results_by_division(round3_display_categories, top3_by_division)
    
    # Calculate category winners if the setting is enabled
    category_winners_by_division = {}
    if settings.show_category_winners:
        for division in divisions:
            division_results = round1_results_by_division.get(division, [])
            if not division_results:
                continue
            division_winners = {}
            for category in round1_display_categories:
                best_score = None
                winners = []

                for result in division_results:
                    if category.name not in result['category_scores']:
                        continue
                    score = result['category_scores'][category.name]['raw']
                    if best_score is None or score > best_score:
                        best_score = score
                        winners = [{'contestant': result['contestant'], 'score': score}]
                    elif score == best_score:
                        winners.append({'contestant': result['contestant'], 'score': score})

                if winners:
                    division_winners[category.name] = {
                        'winners': winners,
                        'score': best_score
                    }
            if division_winners:
                category_winners_by_division[division] = division_winners

    return render_template(
        'results.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        round1_results_by_division=round1_results_by_division,
        round2_results_by_division=round2_results_by_division,
        round3_results_by_division=round3_results_by_division,
        round1_categories=round1_display_categories,
        round2_categories=round2_display_categories,
        round3_categories=round3_display_categories,
        all_locked=all_locked,
        round1_locked=round1_locked,
        round2_locked=round2_locked,
        round3_locked=round3_locked,
        judges_count=judges_count,
        category_winners_by_division=category_winners_by_division,
        show_category_winners=settings.show_category_winners,
        read_only_mode=read_only_mode,
        round1_partial=round1_partial,
        round2_partial=round2_partial,
        round3_partial=round3_partial
    )

@app.route('/results/download-pdf')
@staff_required
def download_results_pdf():
    """Generate and download PDF of competition results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    categories = Category.query.order_by(Category.order).all()
    contestants = Contestant.query.order_by(Contestant.division, Contestant.number).all()
    judges_count = Judge.query.count()

    if session.get('role') == 'admin':
        if not all(cat.is_locked for cat in categories) and not all_judges_transmitted_for_categories(categories, judges_count):
            flash('Final results are not available yet. Wait for all judge submissions or locks.', 'warning')
            return redirect(url_for('results'))
    results_data = compute_results_for_categories(categories, contestants)

    return build_results_pdf_response(
        categories=categories,
        results_data=results_data,
        settings=settings,
        header_label='FINAL RESULTS',
        include_winners=settings.show_category_winners,
        include_division_column=True
    )




@app.route('/results/download-pdf/<round_name>')
@staff_required
def download_results_pdf_round(round_name):
    """Generate and download PDF of results for a specific round"""
    if round_name not in ('round1', 'round2', 'round3'):
        flash('Invalid round selected for download.', 'error')
        return redirect(url_for('results'))

    raw_division = request.args.get('division')
    division = normalize_division(raw_division) if raw_division else None
    if raw_division and raw_division.lower() not in DIVISION_VALUES:
        flash('Invalid division selected for download.', 'error')
        return redirect(url_for('results'))

    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    round_categories = get_round_categories(round_name)
    if not round_categories:
        flash('No categories found for that round.', 'warning')
        return redirect(url_for('results'))

    judges_count = Judge.query.count()
    if not all(cat.is_locked for cat in round_categories):
        if session.get('role') == 'admin':
            completed_categories = get_completed_categories_by_submission(round_categories, judges_count)
            if not completed_categories:
                flash('That round is not ready yet. Wait for judge submissions.', 'warning')
                return redirect(url_for('results'))
            round_categories = completed_categories
        else:
            flash('That round is not locked yet.', 'warning')
            return redirect(url_for('results'))

    contestants = Contestant.query.order_by(Contestant.division, Contestant.number).all()
    if division:
        contestants = get_contestants_by_division(division)
        if not contestants:
            flash('No contestants found for the selected division.', 'warning')
            return redirect(url_for('results'))
    if round_name == 'round2':
        round1_categories = get_round_categories('round1')
        if division:
            round1_results = compute_results_for_categories(round1_categories, contestants) if round1_categories else []
            contestants = [r['contestant'] for r in round1_results[:5]]
        else:
            divisions = get_divisions()
            contestants_by_division = {value: get_contestants_by_division(value) for value in divisions}
            round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
            top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)
            contestants = flatten_contestants(top5_by_division)
    elif round_name == 'round3':
        round1_categories = get_round_categories('round1')
        round2_categories = get_round_categories('round2')
        if division:
            round1_results = compute_results_for_categories(round1_categories, contestants) if round1_categories else []
            top5_contestants = [r['contestant'] for r in round1_results[:5]]
            round2_results = compute_results_for_categories(round2_categories, top5_contestants) if round2_categories else []
            contestants = [r['contestant'] for r in round2_results[:3]]
        else:
            divisions = get_divisions()
            contestants_by_division = {value: get_contestants_by_division(value) for value in divisions}
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

    return build_results_pdf_response(
        categories=round_categories,
        results_data=results_data,
        settings=settings,
        header_label=header_label,
        include_winners=settings.show_category_winners and round_name == 'round1',
        filename_suffix=f"{round_name}_{division}" if division else round_name
    )


def build_results_pdf_response(categories, results_data, settings, header_label, include_winners=False, filename_suffix=None, include_division_column=False):
    """Build a PDF response for provided results data."""
    num_categories = len(categories)
    base_columns = 4 + (1 if include_division_column else 0)
    total_columns = base_columns + num_categories
    row_count = len(results_data)
    use_landscape = total_columns > 9
    dense_layout = total_columns > 9 or row_count > 10

    # Create PDF
    buffer = BytesIO()
    page_size = landscape(letter) if use_landscape else letter
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
        textColor=colors.HexColor('#880015'),
        spaceAfter=3 if dense_layout else 5,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    title_text = f"<b>{settings.competition_title.upper()} RESULTS</b>"
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
        for category in categories:
            best_score = None
            winners = []
            
            for result in results_data:
                if category.name in result['category_scores']:
                    score = result['category_scores'][category.name]['raw']
                    if best_score is None or score > best_score:
                        best_score = score
                        winners = [result['contestant']]
                    elif score == best_score:
                        winners.append(result['contestant'])
            
            if winners:
                category_winners[category.name] = {
                    'winners': winners,
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
                    winner_names = ", ".join([w.name for w in winner_info['winners']])
                    winner_numbers = ", ".join([str(w.number) for w in winner_info['winners']])
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
    safe_filename = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in settings.competition_title)
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
        CompetitionHistory.query.delete()
        Score.query.delete()
        JudgeSubmission.query.delete()
        Criteria.query.delete()
        Category.query.delete()
        Contestant.query.delete()
        Judge.query.delete()
        db.session.commit()
        log_event('data_reset', 'contestants, categories, criteria, judges, scores, history cleared')
        flash('Database reset successfully! Contestants, categories, judges, criteria, scores, and history were cleared.', 'success')
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'error')
    
    return redirect(url_for('admin_settings'))

if __name__ == '__main__':
    with app.app_context():
        ensure_schema_updates()
        db.create_all()
        # Initialize settings if not exists
        if not Settings.query.first():
            default_settings = Settings(competition_title='Pageant Competition')
            db.session.add(default_settings)
            db.session.commit()
    socketio.run(app, debug=True)
