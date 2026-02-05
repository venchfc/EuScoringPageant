from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pageant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contestant_id = db.Column(db.Integer, db.ForeignKey('contestant.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    criteria_ref = db.relationship('Criteria')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/categories')
def categories():
    all_categories = Category.query.order_by(Category.order).all()
    return render_template('categories.html', categories=all_categories)

@app.route('/category/add', methods=['GET', 'POST'])
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        
        # Get the next order number
        max_order = db.session.query(db.func.max(Category.order)).scalar() or 0
        
        category = Category(name=name, percentage=percentage, order=max_order + 1)
        db.session.add(category)
        db.session.commit()
        
        flash(f'Category "{name}" added successfully!', 'success')
        return redirect(url_for('categories'))
    
    return render_template('add_category.html')

@app.route('/category/<int:category_id>/criteria', methods=['GET', 'POST'])
def manage_criteria(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
        flash('This category is locked and cannot be modified.', 'error')
        return redirect(url_for('categories'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        percentage = float(request.form.get('percentage'))
        
        # Get the next order number for this category
        max_order = db.session.query(db.func.max(Criteria.order)).filter_by(category_id=category_id).scalar() or 0
        
        criteria = Criteria(category_id=category_id, name=name, percentage=percentage, order=max_order + 1)
        db.session.add(criteria)
        db.session.commit()
        
        flash(f'Criteria "{name}" added successfully!', 'success')
        return redirect(url_for('manage_criteria', category_id=category_id))
    
    criteria_list = Criteria.query.filter_by(category_id=category_id).order_by(Criteria.order).all()
    return render_template('manage_criteria.html', category=category, criteria=criteria_list)

@app.route('/contestants')
def contestants():
    all_contestants = Contestant.query.order_by(Contestant.number).all()
    return render_template('contestants.html', contestants=all_contestants)

@app.route('/contestant/add', methods=['GET', 'POST'])
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

@app.route('/scoring/<int:category_id>')
def scoring(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
        flash('This category is already locked!', 'warning')
        return redirect(url_for('categories'))
    
    contestants = Contestant.query.order_by(Contestant.number).all()
    criteria = Criteria.query.filter_by(category_id=category_id).order_by(Criteria.order).all()
    
    # Get existing scores
    existing_scores = {}
    for score in Score.query.filter_by(category_id=category_id).all():
        key = f"{score.contestant_id}_{score.criteria_id}"
        existing_scores[key] = score.score
    
    return render_template('scoring.html', category=category, contestants=contestants, 
                         criteria=criteria, existing_scores=existing_scores)

@app.route('/scoring/<int:category_id>/save', methods=['POST'])
def save_scores(category_id):
    category = Category.query.get_or_404(category_id)
    
    if category.is_locked:
        return jsonify({'success': False, 'message': 'Category is already locked'}), 400
    
    data = request.get_json()
    scores_data = data.get('scores', [])
    
    # Delete existing scores for this category
    Score.query.filter_by(category_id=category_id).delete()
    
    # Add new scores
    for score_entry in scores_data:
        score = Score(
            contestant_id=score_entry['contestant_id'],
            category_id=category_id,
            criteria_id=score_entry['criteria_id'],
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
    
    # Check if all contestants have scores for all criteria
    contestants = Contestant.query.all()
    criteria = Criteria.query.filter_by(category_id=category_id).all()
    
    expected_scores = len(contestants) * len(criteria)
    actual_scores = Score.query.filter_by(category_id=category_id).count()
    
    if actual_scores < expected_scores:
        return jsonify({'success': False, 'message': 'Please score all contestants before locking'}), 400
    
    category.is_locked = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Category "{category.name}" has been locked'})

@app.route('/results')
def results():
    categories = Category.query.order_by(Category.order).all()
    contestants = Contestant.query.order_by(Contestant.number).all()
    
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
                score = Score.query.filter_by(
                    contestant_id=contestant.id,
                    category_id=category.id,
                    criteria_id=criterion.id
                ).first()
                
                if score:
                    # Apply criteria percentage
                    weighted_score = score.score * (criterion.percentage / 100)
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
    
    return render_template('results.html', results=results_data, categories=categories, all_locked=all_locked)

@app.route('/reset', methods=['POST'])
def reset_database():
    """For development - reset all data"""
    try:
        db.drop_all()
        db.create_all()
        flash('Database reset successfully!', 'success')
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
