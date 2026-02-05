# Pageant Scoring System

A professional web-based scoring system for pageant competitions built with Flask.

## Features

✨ **Dynamic Categories & Criteria**
- Add unlimited competition categories (Evening Gown, Swimsuit, Q&A, etc.)
- Define custom criteria for each category with percentage weights
- Flexible percentage allocation

🔒 **Score Locking**
- Lock categories once scoring is complete
- Irreversible locking prevents score tampering
- Visual indicators for locked/unlocked status

📊 **Automatic Rankings**
- Real-time score calculation
- Weighted scoring based on category and criteria percentages
- Beautiful podium display for top 3 contestants
- Detailed score breakdown tables

👥 **Contestant Management**
- Easy contestant registration with numbers and names
- Visual contestant cards

🎨 **Modern UI**
- Responsive Bootstrap 5 design
- Beautiful gradient themes
- Mobile-friendly interface

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Setup Steps

1. **Navigate to the project directory:**
   ```bash
   cd "c:\Users\user\Documents\ScoringEUplus"
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Mac/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Open your browser and visit:**
   ```
   http://127.0.0.1:5000
   ```

## Usage Guide

### Step 1: Create Categories
1. Go to **Categories** page
2. Click **Add Category**
3. Enter category name (e.g., "Evening Gown")
4. Set percentage weight (e.g., 30%)
5. Make sure total percentages across all categories = 100%

### Step 2: Define Criteria
1. From Categories page, click **Manage Criteria** for a category
2. Add criteria (e.g., "Poise", "Presentation")
3. Set percentage weights for each criterion
4. Criteria percentages should total 100% within each category

### Step 3: Add Contestants
1. Go to **Contestants** page
2. Click **Add Contestant**
3. Enter contestant number and name
4. Repeat for all contestants

### Step 4: Score Each Category
1. Go to **Categories** page
2. Click **Score** button for a category
3. Enter scores (0-100) for each contestant and criterion
4. Click **Save Scores** to save progress
5. Click **Save & Lock Category** when complete (irreversible!)

### Step 5: View Results
1. Go to **Results** page
2. See rankings, podium display, and detailed scores
3. Results are final when all categories are locked

## Project Structure

```
ScoringEUplus/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── pageant.db            # SQLite database (auto-created)
│
└── templates/            # HTML templates
    ├── base.html         # Base template with navbar
    ├── index.html        # Home page
    ├── categories.html   # Category listing
    ├── add_category.html # Add category form
    ├── manage_criteria.html # Criteria management
    ├── contestants.html  # Contestant listing
    ├── add_contestant.html # Add contestant form
    ├── scoring.html      # Scoring interface
    └── results.html      # Results and rankings
```

## Database Schema

- **Category**: Competition categories with percentage weights
- **Criteria**: Scoring criteria within categories
- **Contestant**: Pageant contestants
- **Score**: Individual scores for contestant-criterion pairs

## Security Notes

- Change the `SECRET_KEY` in app.py before production use
- The database reset feature should be removed in production
- Consider adding user authentication for production deployments

## Technologies Used

- **Flask 3.0** - Web framework
- **SQLAlchemy** - Database ORM
- **Bootstrap 5** - Frontend framework
- **SQLite** - Database (can be upgraded to PostgreSQL)

## License

This project is provided as-is for pageant scoring purposes.

## Support

For issues or questions, please check the code comments or modify as needed for your specific pageant requirements.
