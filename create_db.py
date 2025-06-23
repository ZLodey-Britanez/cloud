from app import app, init_db

DATABASE = 'database.db'

with app.app_context():
    init_db()