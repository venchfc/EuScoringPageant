from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import os
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pageant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Admin credentials (change these for production)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'adminITD2026'

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
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
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
    number = db.Column(db.Integer, unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
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

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    competition_title = db.Column(db.String(200), nullable=False, default='Pageant Competition')
    show_category_winners = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

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
    return render_template('categories.html', categories=all_categories)

@app.route('/category/add', methods=['GET', 'POST'])
@login_required
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        
        # Check total percentage
        current_total = db.session.query(db.func.sum(Category.percentage)).scalar() or 0
        new_total = current_total + percentage
        
        if new_total > 100:
            flash(f'Cannot add category. Total percentage would be {new_total}%. Categories must total 100%.', 'error')
            return render_template('add_category.html')
        
        # Get the next order number
        max_order = db.session.query(db.func.max(Category.order)).scalar() or 0
        
        category = Category(name=name, percentage=percentage, order=max_order + 1)
        db.session.add(category)
        db.session.commit()
        
        flash(f'Category "{name}" added successfully! Total: {new_total}%', 'success')
        if new_total < 100:
            flash(f'Note: Categories total {new_total}%. Add {100 - new_total}% more to reach 100%.', 'warning')
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
        
        # Check total percentage (excluding current category)
        other_categories_total = db.session.query(db.func.sum(Category.percentage)).filter(Category.id != category_id).scalar() or 0
        new_total = other_categories_total + new_percentage
        
        if new_total > 100:
            flash(f'Cannot update category. Total percentage would be {new_total}%. Categories must total 100%.', 'error')
            return render_template('edit_category.html', category=category)
        
        category.name = request.form.get('name')
        category.percentage = new_percentage
        
        db.session.commit()
        
        flash(f'Category "{category.name}" updated successfully! Total: {new_total}%', 'success')
        if new_total < 100:
            flash(f'Note: Categories total {new_total}%. Add {100 - new_total}% more to reach 100%.', 'warning')
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
    all_contestants = Contestant.query.order_by(Contestant.number).all()
    return render_template('contestants.html', contestants=all_contestants)


@app.route('/contestant/<int:contestant_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_contestant(contestant_id):
    contestant = Contestant.query.get_or_404(contestant_id)
    
    if request.method == 'POST':
        new_number = int(request.form.get('number'))
        new_name = request.form.get('name')
        
        # Safety check: if number changed, make sure it's not already taken
        if new_number != contestant.number:
            existing = Contestant.query.filter_by(number=new_number).first()
            if existing:
                flash(f'Contestant number {new_number} is already taken!', 'error')
                return render_template('edit_contestant.html', contestant=contestant)
        
        contestant.number = new_number
        contestant.name = new_name
        db.session.commit()
        
        flash(f'Contestant #{new_number} - {new_name} updated successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('edit_contestant.html', contestant=contestant)

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
        
        # Check if number already exists
        existing = Contestant.query.filter_by(number=number).first()
        if existing:
            flash(f'Contestant number {number} already exists!', 'error')
            return render_template('add_contestant.html')
        
        contestant = Contestant(number=number, name=name)
        db.session.add(contestant)
        db.session.commit()
        
        flash(f'Contestant #{number} - {name} added successfully!', 'success')
        return redirect(url_for('contestants'))
    
    return render_template('add_contestant.html')

@app.route('/scoring')
def scoring_menu():
    categories = Category.query.order_by(Category.order).all()
    contestants_count = Contestant.query.count()
    judges_count = Judge.query.count()
    
    # Check which categories are ready for scoring
    for category in categories:
        category.criteria_count = Criteria.query.filter_by(category_id=category.id).count()
        category.ready = category.criteria_count > 0 and contestants_count > 0 and judges_count > 0
    
    return render_template('scoring_menu.html', categories=categories, contestants_count=contestants_count, judges_count=judges_count)

@app.route('/scoring/<int:category_id>')
def scoring(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
        flash('This category is already locked!', 'warning')
        return redirect(url_for('scoring_menu'))
    
    contestants = Contestant.query.order_by(Contestant.number).all()
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
    
    return jsonify({'success': True, 'message': 'Scores saved successfully'})

@app.route('/category/<int:category_id>/lock', methods=['POST'])
def lock_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    # Check if criteria percentages total 100%
    criteria_total = db.session.query(db.func.sum(Criteria.percentage)).filter_by(category_id=category_id).scalar() or 0
    if criteria_total != 100:
        return jsonify({'success': False, 'message': f'Cannot lock category. Criteria percentages total {criteria_total}%. Must equal 100%.'}), 400
    
    # Check if all category percentages total 100%
    all_categories_total = db.session.query(db.func.sum(Category.percentage)).scalar() or 0
    if all_categories_total != 100:
        return jsonify({'success': False, 'message': f'Cannot lock category. All categories total {all_categories_total}%. Must equal 100%.'}), 400
    
    # Check if all contestants have scores for all criteria from all judges
    contestants = Contestant.query.all()
    criteria = Criteria.query.filter_by(category_id=category_id).all()
    judges = Judge.query.all()
    
    expected_scores = len(contestants) * len(criteria) * len(judges)
    actual_scores = Score.query.filter_by(category_id=category_id).count()
    
    if actual_scores < expected_scores:
        return jsonify({'success': False, 'message': f'Please ensure all {len(judges)} judges have scored all contestants before locking'}), 400
    
    category.is_locked = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Category "{category.name}" has been locked'})

@app.route('/results')
def results():
    categories = Category.query.order_by(Category.order).all()
    contestants = Contestant.query.order_by(Contestant.number).all()
    judges = Judge.query.all()
    
    # Get settings
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition', show_category_winners=False)
        db.session.add(settings)
        db.session.commit()
    
    # Check if all categories are locked
    all_locked = all(cat.is_locked for cat in categories)
    
    results_data = []
    
    for contestant in contestants:
        total_score = 0
        category_scores = {}
        
        for category in categories:
            criteria = Criteria.query.filter_by(category_id=category.id).all()
            category_total = 0
            
            for criterion in criteria:
                # Get scores from all judges and average them
                scores = Score.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    criteria_id=criterion.id
                ).all()
                
                if scores:
                    # Average the scores from all judges
                    avg_score = sum(s.score for s in scores) / len(scores) if scores else 0
                    # Multiply by 10 to normalize from 0-10 scale to 0-100
                    # Apply criteria percentage
                    weighted_score = (avg_score * 10) * (criterion.percentage / 100)
                    category_total += weighted_score
            
            # Apply category percentage
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
    
    # Sort by total score (descending)
    results_data.sort(key=lambda x: x['total_score'], reverse=True)
    
    # Add rankings
    for idx, result in enumerate(results_data, 1):
        result['rank'] = idx
    
    # Calculate category winners if the setting is enabled
    category_winners = {}
    if settings.show_category_winners:
        for category in categories:
            # Find contestant with highest raw score in this category
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
    
    return render_template('results.html', results=results_data, categories=categories, 
                         all_locked=all_locked, judges_count=len(judges), 
                         category_winners=category_winners, 
                         show_category_winners=settings.show_category_winners)

@app.route('/results/download-pdf')
def download_results_pdf():
    """Generate and download PDF of competition results"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings(competition_title='Pageant Competition')
        db.session.add(settings)
        db.session.commit()
    
    categories = Category.query.order_by(Category.order).all()
    contestants = Contestant.query.order_by(Contestant.number).all()
    judges = Judge.query.all()
    
    # Check if all categories are locked
    all_locked = all(cat.is_locked for cat in categories)
    
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
    
    # Sort by total score (descending)
    results_data.sort(key=lambda x: x['total_score'], reverse=True)
    
    # Add rankings
    for idx, result in enumerate(results_data, 1):
        result['rank'] = idx
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#800000'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    title_text = f"<b>{settings.competition_title.upper()} RESULTS</b>"
    title = Paragraph(title_text, title_style)
    elements.append(title)
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        alignment=TA_CENTER,
        spaceAfter=5
    )
    
    subtitle = Paragraph("Manuel S. Enverga University Foundation - Catanauan Inc", subtitle_style)
    elements.append(subtitle)
    
    status_text = "<b>FINAL RESULTS - All Categories Locked</b>" if all_locked else "Preliminary Results - Not All Categories Locked"
    status = Paragraph(status_text, subtitle_style)
    elements.append(status)
    
    elements.append(Spacer(1, 20))
    
    # Create table data
    table_data = []
    header_row = ['Rank', 'No.', 'Name']
    
    # Add category headers
    for category in categories:
        header_row.append(f"{category.name}\\n({category.percentage}%)")
    header_row.append('Total Score')
    
    table_data.append(header_row)
    
    # Add contestant rows
    for result in results_data:
        row = [
            str(result['rank']),
            str(result['contestant'].number),
            result['contestant'].name
        ]
        
        for category in categories:
            if result['category_scores'][category.name]:
                weighted = result['category_scores'][category.name]['weighted']
                raw = result['category_scores'][category.name]['raw']
                row.append(f"{weighted:.2f}\\n({raw:.2f})")
            else:
                row.append('-')
        
        row.append(f"{result['total_score']:.2f}")
        table_data.append(row)
    
    # Create table
    table = Table(table_data)
    
    # Style the table
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#800000')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ])
    
    # Highlight top 3
    if len(results_data) >= 1:
        table_style.add('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FFD700'))  # Gold
    if len(results_data) >= 2:
        table_style.add('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#C0C0C0'))  # Silver
    if len(results_data) >= 3:
        table_style.add('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#CD7F32'))  # Bronze
    
    table.setStyle(table_style)
    elements.append(table)
    
    elements.append(Spacer(1, 20))
    
    # Add category winners if enabled
    if settings.show_category_winners:
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
                fontSize=14,
                textColor=colors.HexColor('#800000'),
                spaceAfter=15,
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
                        f"{winner_info['score']:.2f}"
                    ])
            
            winner_table = Table(winner_data, colWidths=[2*inch, 2.5*inch, 1*inch, 1*inch])
            
            winner_table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#800000')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFF8DC'), colors.HexColor('#FFFACD')]),
            ])
            
            winner_table.setStyle(winner_table_style)
            elements.append(winner_table)
            
            elements.append(Spacer(1, 15))
    
    # Legend
    legend_style = ParagraphStyle(
        'Legend',
        parent=styles['Normal'],
        fontSize=8,
        spaceAfter=3
    )
    
    legend = Paragraph("<b>Score Breakdown:</b> Weighted Score (Raw Score) - Raw scores shown in parentheses", legend_style)
    elements.append(legend)
    
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
    """Reset all data - works in all environments"""
    try:
        db.drop_all()
        db.create_all()
        # Initialize default settings
        default_settings = Settings(competition_title='Pageant Competition')
        db.session.add(default_settings)
        db.session.commit()
        flash('Database reset successfully! All data has been cleared.', 'success')
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
