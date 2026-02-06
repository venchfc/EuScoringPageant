from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import os
import csv
from io import BytesIO, StringIO
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_, text
from sqlalchemy import or_
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

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='contestant', lazy=True, cascade='all, delete-orphan')

class Judge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='judge', lazy=True, cascade='all, delete-orphan')

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
    competition_title = db.Column(db.String(200), nullable=False, default='Pageant Competition')
    show_category_winners = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Ensure there is at least one admin user
def ensure_default_admin():
    if User.query.first() is None:
        admin_user = User(username=DEFAULT_ADMIN_USERNAME)
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
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()
    return dict(competition_title=settings.competition_title)

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
            flash('Login successful!', 'success')
            log_event('login_success', f'username={username}', user=user)
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
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
@login_required
def admin_logs():
    params = request.args.to_dict()
    logs = build_log_query(params).order_by(AuditLog.created_at.desc()).limit(200).all()
    usernames = [row[0] for row in db.session.query(AuditLog.username).distinct().order_by(AuditLog.username.asc()).all() if row[0]]
    actions = [row[0] for row in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action.asc()).all() if row[0]]
    return render_template('admin_logs.html', logs=logs, usernames=usernames, actions=actions, filters=params)

@app.route('/admin/logs.csv')
@login_required
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
@login_required
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
@login_required
def admin_users():
    ensure_default_admin()
    users = User.query.order_by(User.username.asc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@login_required
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

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    log_event('admin_user_created', f'created_username={username}', user=current_user)
    flash('User created successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/reset', methods=['POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
def admin_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    return render_template('admin_settings.html', show_category_winners=settings.show_category_winners)
@app.route('/competition-settings', methods=['GET', 'POST'])
@login_required
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

@app.route('/toggle-category-winners', methods=['POST'])
@login_required
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
@login_required
def categories():
    all_categories = Category.query.order_by(Category.order).all()
    round1_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.round == 'round1').scalar() or 0
    return render_template('categories.html', categories=all_categories, round1_total=round1_total)

@app.route('/category/add', methods=['GET', 'POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
def contestants():
    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}
    total_contestants = sum(len(items) for items in contestants_by_division.values())
    return render_template(
        'contestants.html',
        divisions=divisions,
        division_labels=DIVISION_LABELS,
        contestants_by_division=contestants_by_division,
        total_contestants=total_contestants
    )


@app.route('/contestant/<int:contestant_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_contestant(contestant_id):
    contestant = Contestant.query.get_or_404(contestant_id)
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        new_division = normalize_division(request.form.get('division'))
        
        # Safety check: if number or division changed, make sure it's not already taken
        if new_number != contestant.number or new_division != contestant.division:
            existing = Contestant.query.filter_by(number=new_number, division=new_division).first()
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
@login_required
def judges():
    all_judges = Judge.query.order_by(Judge.number).all()
    return render_template('judges.html', judges=all_judges)

@app.route('/judge/add', methods=['GET', 'POST'])
@login_required
def add_judge():
    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        
        # Check if number already exists
        existing = Judge.query.filter_by(number=number).first()
        if existing:
            flash(f'Judge number {number} already exists!', 'error')
            return render_template('add_judge.html')
        
        judge = Judge(number=number, name=name)
        db.session.add(judge)
        db.session.commit()
        
        flash(f'Judge #{number} - {name} added successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('add_judge.html')

@app.route('/judge/<int:judge_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        
        # Safety check: if number changed, make sure it's not already taken
        if new_number != judge.number:
            existing = Judge.query.filter_by(number=new_number).first()
            if existing:
                flash(f'Judge number {new_number} is already taken!', 'error')
                return render_template('edit_judge.html', judge=judge)
        
        judge.number = new_number
        judge.name = new_name
        db.session.commit()
        
        flash(f'Judge #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('judges'))
    
    return render_template('edit_judge.html', judge=judge)

@app.route('/judge/<int:judge_id>/delete', methods=['POST'])
@login_required
def delete_judge(judge_id):
    judge = Judge.query.get_or_404(judge_id)
    
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
@login_required
def add_contestant():
    if request.method == 'POST':
        number = int(request.form.get('number'))
        name = request.form.get('name')
        division_raw = request.form.get('division')
        if not division_raw:
            flash('Division is required.', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)
        division = normalize_division(division_raw)
        
        # Check if number already exists
        existing = Contestant.query.filter_by(number=number, division=division).first()
        if existing:
            flash(f'Contestant number {number} already exists in {DIVISION_LABELS.get(division, division)} division!', 'error')
            return render_template('add_contestant.html', division_labels=DIVISION_LABELS)
        
        contestant = Contestant(number=number, name=name, division=division)
        db.session.add(contestant)
        db.session.commit()
        
        flash(f'Contestant #{number} - {name} added successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('add_contestant.html', division_labels=DIVISION_LABELS)

@app.route('/scoring')
@login_required
def scoring_menu():
    categories = Category.query.order_by(Category.order).all()
    contestants_count = Contestant.query.count()
    judges_count = Judge.query.count()

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
@login_required
def scoring(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
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
@login_required
def save_scores(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
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
    
    return jsonify({'success': True, 'message': 'Scores saved successfully'})

@app.route('/category/<int:category_id>/lock', methods=['POST'])
@login_required
def lock_category(category_id):
    category = Category.query.get_or_404(category_id)
    
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
    db.session.commit()

    log_event('category_locked', f'category_id={category_id} category_name={category.name}')
    
    return jsonify({'success': True, 'message': f'Category "{category.name}" has been locked'})


@app.route('/results')
@login_required
def results():
    categories = Category.query.order_by(Category.order).all()
    judges = Judge.query.all()
    
    # Get settings
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    
    # Check if all categories are locked (per round)
    all_locked = all(cat.is_locked for cat in categories)
    
    round1_categories = get_round_categories('round1')
    round2_categories = get_round_categories('round2')
    round3_categories = get_round_categories('round3')

    round1_locked = bool(round1_categories) and all(cat.is_locked for cat in round1_categories)
    round2_locked = bool(round2_categories) and all(cat.is_locked for cat in round2_categories)
    round3_locked = bool(round3_categories) and all(cat.is_locked for cat in round3_categories)

    divisions = get_divisions()
    contestants_by_division = {division: get_contestants_by_division(division) for division in divisions}

    round1_results_by_division = compute_results_by_division(round1_categories, contestants_by_division)
    top5_by_division = get_top_contestants_by_division(round1_results_by_division, 5)

    round2_results_by_division = compute_results_by_division(round2_categories, top5_by_division)
    top3_by_division = get_top_contestants_by_division(round2_results_by_division, 3)

    round3_results_by_division = compute_results_by_division(round3_categories, top3_by_division)
    
    # Calculate category winners if the setting is enabled
    category_winners_by_division = {}
    if settings.show_category_winners:
        for division in divisions:
            division_results = round1_results_by_division.get(division, [])
            if not division_results:
                continue
            division_winners = {}
            for category in round1_categories:
                best_contestant = None
                best_score = -1

                for result in division_results:
                    if category.name in result['category_scores']:
                        score = result['category_scores'][category.name]['raw']
                        if score > best_score:
                            best_score = score
                            best_contestant = result['contestant']

                if best_contestant:
                    division_winners[category.name] = {
                        'contestant': best_contestant,
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
        round1_categories=round1_categories,
        round2_categories=round2_categories,
        round3_categories=round3_categories,
        all_locked=all_locked,
        round1_locked=round1_locked,
        round2_locked=round2_locked,
        round3_locked=round3_locked,
        judges_count=len(judges),
        category_winners_by_division=category_winners_by_division,
        show_category_winners=settings.show_category_winners
    )

@app.route('/results/download-pdf')
def download_results_pdf():
    """Generate and download PDF of competition results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()

    categories = Category.query.order_by(Category.order).all()
    contestants = Contestant.query.order_by(Contestant.division, Contestant.number).all()
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

    if not all(cat.is_locked for cat in round_categories):
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
        textColor=colors.maroon,
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
            best_contestant = None
            best_score = -1
            
            for result in results_data:
                if category.name in result['category_scores']:
                    score = result['category_scores'][category.name]['raw']
                    if score > best_score:
                        best_score = score
                        best_contestant = result['contestant']
            
            if best_contestant:
                category_winners[category.name] = {
                    'contestant': best_contestant,
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
                    winner_data.append([
                        category.name,
                        winner_info['contestant'].name,
                        str(winner_info['contestant'].number),
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
@login_required
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
@login_required
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
@login_required
def reset_database():
    """Reset scoring data while keeping admin accounts"""
    try:
        Score.query.delete()
        Criteria.query.delete()
        Category.query.delete()
        Contestant.query.delete()
        Judge.query.delete()
        db.session.commit()
        log_event('data_reset', 'contestants, categories, criteria, judges, scores cleared')
        flash('Database reset successfully! Contestants, categories, judges, criteria, and scores were cleared.', 'success')
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'error')
    
    return redirect(url_for('admin_settings'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Initialize settings if not exists
        if not Settings.query.first():
            default_settings = Settings(competition_title='Pageant Competition')
            db.session.add(default_settings)
            db.session.commit()
    app.run(debug=True)
