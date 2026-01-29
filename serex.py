from flask import Flask, render_template, request, session, jsonify, g, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_change_in_production_12345')
app.config['DATABASE'] = 'database/users.db'
socketio = SocketIO(app, cors_allowed_origins="*")


# ========== БАЗА ДАНИХ ==========
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ========== МАРШРУТИ HTML ==========
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))


@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')


@app.route('/register')
def register():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('register.html')


@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session.get('username', 'Гість'))


# ========== API ЕНДПОІНТИ ==========
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({'success': False, 'error': 'Логін і пароль обов\'язкові'})

        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Логін має бути від 3 символів'})

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Пароль має бути від 6 символів'})

        db = get_db()
        cursor = db.cursor()

        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'Користувач вже існує'})

        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        db.commit()

        # Автоматичний вхід після реєстрації
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        session['user_id'] = user['id']
        session['username'] = user['username']

        return jsonify({
            'success': True, 
            'message': 'Реєстрація успішна',
            'user': {
                'id': user['id'],
                'username': user['username']
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username']
                }
            })
        else:
            return jsonify({'success': False, 'error': 'Невірний логін або пароль'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/check_auth')
def check_auth():
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': session['user_id'],
                'username': session['username']
            }
        })
    return jsonify({'authenticated': False})


# ========== WEBSOCKET ЛОГІКА ==========
online_users = {}


@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_data = {
            'id': session['user_id'],
            'username': session['username']
        }
        online_users[request.sid] = user_data
        broadcast_online_users()
        emit('auth_success', user_data)
        print(f'Користувач {session["username"]} підключився')


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in online_users:
        username = online_users[request.sid]['username']
        del online_users[request.sid]
        broadcast_online_users()
        print(f'Користувач {username} відключився')


def broadcast_online_users():
    users_list = [{'id': u['id'], 'username': u['username']} for u in online_users.values()]
    emit('online_users_update', {'users': users_list}, broadcast=True)


@socketio.on('private_message')
def handle_private_message(data):
    recipient_id = data.get('recipient_id')
    message = data.get('message')
    sender_sid = request.sid

    if sender_sid in online_users:
        sender = online_users[sender_sid]

        for sock_id, user_data in online_users.items():
            if user_data['id'] == recipient_id:
                emit('private_message', {
                    'from': sender['username'],
                    'from_id': sender['id'],
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }, room=sock_id)
                emit('message_delivered', {
                    'to_id': recipient_id,
                    'message': message
                }, room=sender_sid)
                return

        emit('user_offline', {'user_id': recipient_id}, room=sender_sid)


@socketio.on('search_users')
def handle_search_users(data):
    query = data.get('query', '').lower()
    if not query:
        return

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'SELECT id, username FROM users WHERE username LIKE ? LIMIT 10',
        (f'%{query}%',)
    )
    results = cursor.fetchall()

    emit('search_results', {
        'results': [{'id': r[0], 'username': r[1]} for r in results]
    })


# ========== ЗАПУСК ==========
if __name__ == '__main__':
    os.makedirs('database', exist_ok=True)
    init_db()
    
    port = int(os.environ.get('PORT', 8000))
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=False,
        allow_unsafe_werkzeug=True
    )
