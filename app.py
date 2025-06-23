import os
from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'cairocoders-ednalan'

DATABASE = 'database.db'  # Имя файла базы данных
UPLOAD_FOLDER = '/cloud/uploads'  # Папка для хранения загруженных файлов
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'} # Разрешенные типы файлов

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Создаем папку uploads, если ее нет

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Для доступа к столбцам по имени
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Проверяем, существует ли таблица users, и создаем её, если нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    # Добавим таблицу для хранения информации о файлах
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            uploader_id INTEGER NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploader_id) REFERENCES users (id)
        )
    ''')

    # Таблица прав доступа к файлам (для совместной работы)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            permission_type TEXT NOT NULL DEFAULT 'view',  -- 'view', 'edit', 'owner'
            FOREIGN KEY (file_id) REFERENCES files (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE (file_id, user_id)  -- Чтобы у одного пользователя не было нескольких записей для одного и того же файла
        )
    ''')

    conn.commit()
    conn.close()

# Инициализируем базу данных при запуске приложения
with app.app_context():
    init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('shared_access.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if account exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        account = cursor.fetchone()

        if account:
            password_rs = account['password']

            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                # Redirect to home page
                conn.close()
                return redirect(url_for('uploaded_files')) #uploaded_files
            else:
                # Account doesnt exist or username/password incorrect
                flash('Не правильно введены логин/пароль')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Не правильно введены логин/пароль')

        conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        _hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if account exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        account = cursor.fetchone()

        # If account exists show error and validation checks
        if account:
            flash('Аккаунт уже существует!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Не корректно введена почта!')
        elif not re.match(r'[А-яа-яA-Za-z0-9]+', username):
            flash('Логин должен состоять только из букв и цифр!')
        elif not username or not password or not email:
            flash('Пожалуйста заполните данные!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (?, ?, ?, ?)",
                           (fullname, username, _hashed_password, email))
            conn.commit()
            flash('Регистрация успешно выполнена!')

        conn.close()
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Пожалуйста заполните данные!')

    # Show registration form with message (if any)
    return render_template('register.html')

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['id'],))
        account = cursor.fetchone()
        conn.close()

        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('Не является файлом')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('Файл не выбран')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)  # Сохраняем файл на сервере

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO files (filename, original_filename, uploader_id) VALUES (?, ?, ?)",
                           (filename, file.filename, session['id'])) # Сохраняем информацию о файле в БД
            file_id = cursor.lastrowid # Получаем ID только что добавленного файла
            conn.commit()
            # Даём пользователю права владельца на этот файл
            cursor.execute("INSERT INTO file_permissions (file_id, user_id, permission_type) VALUES (?, ?, ?)",
                           (file_id, session['id'], 'owner'))
            conn.commit()
            conn.close()

            flash('Файл успешно загружен')
            return redirect(url_for('uploaded_files'))  # Перенаправляем на страницу со списком файлов

    return render_template('upload.html')

@app.route('/uploads_list')
def uploaded_files():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE uploader_id = ?", (session['id'],))
    files = cursor.fetchall()
    conn.close()

    return render_template('uploads_list.html', files=files)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    file = cursor.fetchone()
    conn.close()

    if not file:
        flash('Файл не найден')
        return redirect(url_for('uploaded_files'))

    if file['uploader_id'] != session['id']:
        flash('У вас не достаточно прав для скачивания данного файла')
        return redirect(url_for('uploaded_files'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    try:
        return send_file(
            filepath,
            as_attachment=True,
            download_name=file['original_filename'],
            mimetype='application/octet-stream'  # Универсальный MIME-тип
        )
    except FileNotFoundError:
        flash('Файл на сервере не обнаружен')
        return redirect(url_for('uploaded_files'))
    
@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Проверяем, является ли текущий пользователь владельцем файла
    cursor.execute('''
        SELECT * 
        FROM file_permissions
        WHERE file_id = ? AND user_id = ? AND permission_type = 'owner'
    ''', (file_id, session['id']))

    owner_check = cursor.fetchone()

    if not owner_check:
        flash('Вы должны быть владельцем данного файла, чтобы поделиться им с другими')
        return redirect(url_for('uploaded_files'))

    if request.method == 'POST':
        username_to_share = request.form['username']
        permission_type = request.form['permission']  # 'view' or 'edit'

        # Получаем ID пользователя, которому даём доступ
        cursor.execute('SELECT id FROM users WHERE username = ?', (username_to_share,))
        user_to_share = cursor.fetchone()

        if not user_to_share:
            flash('Пользователь не найден')
        else:
            try:
                # Предоставляем доступ к файлу
                cursor.execute("INSERT INTO file_permissions (file_id, user_id, permission_type) VALUES (?, ?, ?)",
                               (file_id, user_to_share['id'], permission_type))
                conn.commit()
                flash(f'Вы поделились файлом с {username_to_share}')
            except sqlite3.IntegrityError:
                flash(f'Пользователь {username_to_share} уже имеет доступ к этому файлу')


    # Получаем информацию о файле для отображения в шаблоне
    cursor.execute("SELECT original_filename FROM files WHERE id = ?", (file_id,))
    file = cursor.fetchone()
    conn.close()

    return render_template('share_file.html', file=file, file_id=file_id)

@app.route('/shared_access')
def share_file_list():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    # Получаем файлы, к которым у пользователя есть хоть какой-то доступ (владение, редактирование, просмотр)
    cursor.execute('''
        SELECT f.* 
        FROM files f
        JOIN file_permissions fp ON f.id = fp.file_id
        WHERE fp.user_id = ? AND fp.permission_type = "view" or fp.permission_type = "edit"
    ''', (session['id'],))
    files = cursor.fetchall()
    conn.close()

    return render_template('shared_access.html', files=files)

@app.route('/download_share/<int:file_id>')
def download_share_file(file_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Проверяем, существует ли файл
    cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    file = cursor.fetchone()

    if not file:
        conn.close()
        flash('Файл не найден')
        return redirect(url_for('share_file_list'))

    # 2. Проверяем права доступа пользователя к файлу
    cursor.execute("""
        SELECT permission_type FROM file_permissions
        WHERE file_id = ? AND user_id = ?
    """, (file_id, user_id))
    permission = cursor.fetchone()

    # 3. Проверяем, имеет ли пользователь право на скачивание (permission_type != 'view') или является владельцем
    if permission is None and file['uploader_id'] != user_id:
        conn.close()
        flash('У вас не достаточно прав для скачивания данного файла')
        return redirect(url_for('share_file_list'))

    if permission and permission[0] == 'view' and file['uploader_id'] != user_id:
         conn.close()
         flash('У вас нет прав на скачивание данного файла (только просмотр).')
         return redirect(url_for('share_file_list'))


    conn.close()

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
    try:
        return send_file(
            filepath,
            as_attachment=True,
            download_name=file['original_filename'],
            mimetype='application/octet-stream'  # Универсальный MIME-тип
        )
    except FileNotFoundError:
        flash('Файл на сервере не обнаружен')
        return redirect(url_for('share_file_list'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
