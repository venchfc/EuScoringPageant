"""
Migration script to add show_category_winners column to Settings table.
Run this if you encounter an error about missing column.
"""

from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        try:
            # Check if column exists
            with db.engine.connect() as conn:
                result = conn.execute(text("PRAGMA table_info(settings)"))
                columns = [row[1] for row in result]
                
                if 'show_category_winners' not in columns:
                    print("Adding show_category_winners column to settings table...")
                    conn.execute(text("ALTER TABLE settings ADD COLUMN show_category_winners BOOLEAN DEFAULT 0"))
                    conn.commit()
                    print("✓ Column added successfully!")
                else:
                    print("✓ Column already exists. No migration needed.")
        except Exception as e:
            print(f"Error during migration: {e}")
            print("\nIf this persists, you may need to reset the database.")

if __name__ == '__main__':
    migrate()
