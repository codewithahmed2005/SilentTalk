import os
import json
import uuid
import hashlib
import random
import threading
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# ─── Config ─────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
])
CORS(app, supports_credentials=True)
app.config['SECRET_KEY'] = 'change-this-to-a-random-secret-key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

DB_FILE = os.path.join(os.path.dirname(__file__), '..', 'userchat.json')
db_lock = threading.Lock()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mp3', 'wav', 'ogg'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ─── DB Helpers ─────────────────────────────────────────────────
def init_db():
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        write_db({"users": {}, "chats": {}})

def read_db():
    with db_lock:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)

def write_db(data):
    with db_lock:
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_user_id():
    db = read_db()
    while True:
        uid = ''.join([str(random.randint(0, 9)) for _ in range(10)])
        if uid not in db['users']:
            return uid

def get_chat_id(u1, u2):
    return '_'.join(sorted([u1, u2]))

# ─── Auth Decorator ─────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.split(" ")[1] if " " in auth else auth
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.current_user = data['user_id']
        except Exception:
            return jsonify({'error': 'Token invalid or expired'}), 401
        return f(*args, **kwargs)
    return decorated

# ─── Auth Routes ────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'password', 'name')):
        return jsonify({'error': 'Missing fields'}), 400

    db = read_db()
    for u in db['users'].values():
        if u['username'] == data['username']:
            return jsonify({'error': 'Username already taken'}), 409

    uid = generate_user_id()
    db['users'][uid] = {
        'id': uid,
        'name': data['name'],
        'username': data['username'],
        'about': data.get('about', ''),
        'password': hashlib.sha256(data['password'].encode()).hexdigest(),
        'profile_image': None,
        'contacts': [],
        'theme': 'light',
        'created_at': datetime.now().isoformat()
    }
    write_db(db)
    return jsonify({'message': 'Account created', 'user_id': uid}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    db = read_db()
    for uid, user in db['users'].items():
        if user['username'] == data.get('username'):
            if user['password'] == hashlib.sha256(data['password'].encode()).hexdigest():
                token = jwt.encode({
                    'user_id': uid,
                    'exp': datetime.utcnow() + timedelta(days=30)
                }, app.config['SECRET_KEY'], algorithm='HS256')
                return jsonify({
                    'token': token,
                    'user': {
                        'id': uid,
                        'name': user['name'],
                        'username': user['username'],
                        'about': user['about'],
                        'profile_image': user['profile_image'],
                        'theme': user['theme']
                    }
                })
    return jsonify({'error': 'Invalid credentials'}), 401

# ─── Profile Routes ─────────────────────────────────────────────
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    db = read_db()
    user = db['users'].get(request.current_user)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user['id'],
        'name': user['name'],
        'username': user['username'],
        'about': user['about'],
        'profile_image': user['profile_image'],
        'theme': user['theme']
    })

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile():
    data = request.get_json()
    db = read_db()
    user = db['users'][request.current_user]

    if 'name' in data:
        user['name'] = data['name']
    if 'username' in data:
        for uid, u in db['users'].items():
            if uid != request.current_user and u['username'] == data['username']:
                return jsonify({'error': 'Username taken'}), 409
        user['username'] = data['username']
    if 'about' in data:
        user['about'] = data['about']
    if 'profile_image' in data:
        user['profile_image'] = data['profile_image']
    if 'theme' in data:
        user['theme'] = data['theme']

    write_db(db)
    return jsonify({'message': 'Profile updated'})

# ─── Account Deletion ───────────────────────────────────────────
@app.route('/api/account', methods=['DELETE'])
@token_required
def delete_account():
    db = read_db()
    uid = request.current_user

    # Remove from all contact lists
    for u in db['users'].values():
        if uid in u['contacts']:
            u['contacts'].remove(uid)

    # Delete all chats involving this user
    to_delete = [cid for cid, c in db['chats'].items() if uid in c['participants']]
    for cid in to_delete:
        del db['chats'][cid]

    del db['users'][uid]
    write_db(db)
    return jsonify({'message': 'Account deleted permanently'})

# ─── Contact Routes ─────────────────────────────────────────────
@app.route('/api/contacts', methods=['POST'])
@token_required
def add_contact():
    data = request.get_json()
    contact_id = data.get('user_id')
    db = read_db()

    if contact_id not in db['users']:
        return jsonify({'error': 'User not found'}), 404
    if contact_id == request.current_user:
        return jsonify({'error': 'Cannot add yourself'}), 400

    user = db['users'][request.current_user]
    if contact_id not in user['contacts']:
        user['contacts'].append(contact_id)
        write_db(db)
    return jsonify({'message': 'Contact added'})

@app.route('/api/contacts', methods=['GET'])
@token_required
def get_contacts():
    db = read_db()
    contacts = []
    for cid in db['users'][request.current_user]['contacts']:
        u = db['users'].get(cid)
        if u:
            contacts.append({
                'id': u['id'], 'name': u['name'],
                'username': u['username'], 'profile_image': u['profile_image'],
                'about': u['about']
            })
    return jsonify(contacts)

@app.route('/api/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    db = read_db()
    u = db['users'].get(user_id)
    if not u:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'id': u['id'], 'name': u['name'],
        'username': u['username'], 'about': u['about'],
        'profile_image': u['profile_image']
    })

# ─── Chat & Message Routes ──────────────────────────────────────
@app.route('/api/chats', methods=['GET'])
@token_required
def get_chats():
    db = read_db()
    result = []
    for cid, chat in db['chats'].items():
        if request.current_user not in chat['participants']:
            continue
        other = [p for p in chat['participants'] if p != request.current_user][0]
        ou = db['users'].get(other, {})
        last = None
        if chat['messages']:
            lk = list(chat['messages'].keys())[-1]
            lm = chat['messages'][lk]
            if not lm['deleted']:
                last = {'content': lm['content'][:50], 'timestamp': lm['timestamp'], 'type': lm['type']}
            else:
                last = {'content': 'This message was deleted', 'timestamp': lm['timestamp'], 'type': 'text'}
        result.append({
            'chat_id': cid,
            'user': {'id': ou.get('id'), 'name': ou.get('name'), 'profile_image': ou.get('profile_image')},
            'last_message': last
        })
    result.sort(key=lambda x: x['last_message']['timestamp'] if x['last_message'] else '', reverse=True)
    return jsonify(result)

@app.route('/api/chats/<chat_id>/messages', methods=['GET'])
@token_required
def get_messages(chat_id):
    db = read_db()
    chat = db['chats'].get(chat_id)
    if not chat or request.current_user not in chat['participants']:
        return jsonify({'error': 'Chat not found'}), 404

    msgs = []
    for mid, m in chat['messages'].items():
        sender = db['users'].get(m['sender'], {})
        reply = None
        if m.get('reply_to') and m['reply_to'] in chat['messages']:
            rm = chat['messages'][m['reply_to']]
            reply = {
                'id': rm['id'],
                'content': rm['content'] if not rm['deleted'] else 'This message was deleted',
                'sender_name': db['users'].get(rm['sender'], {}).get('name', 'Unknown'),
                'type': rm['type']
            }
        msgs.append({
            'id': m['id'], 'sender': m['sender'],
            'sender_name': sender.get('name', 'Unknown'),
            'type': m['type'], 'content': m['content'],
            'timestamp': m['timestamp'], 'edited': m.get('edited', False),
            'deleted': m.get('deleted', False), 'reply_to': reply
        })
    msgs.sort(key=lambda x: x['timestamp'])
    return jsonify(msgs)

@app.route('/api/chats/<chat_id>/messages', methods=['POST'])
@token_required
def send_message(chat_id):
    data = request.get_json()
    db = read_db()

    chat = db['chats'].get(chat_id)
    if not chat:
        parts = chat_id.split('_')
        if request.current_user not in parts:
            return jsonify({'error': 'Invalid chat'}), 400
        chat = {'participants': parts, 'messages': {}}
        db['chats'][chat_id] = chat

    if request.current_user not in chat['participants']:
        return jsonify({'error': 'Unauthorized'}), 403

    msg_id = str(uuid.uuid4())
    chat['messages'][msg_id] = {
        'id': msg_id,
        'sender': request.current_user,
        'type': data.get('type', 'text'),
        'content': data.get('content', ''),
        'timestamp': datetime.now().isoformat(),
        'reply_to': data.get('reply_to'),
        'edited': False,
        'deleted': False
    }
    write_db(db)
    return jsonify({'message': 'Sent', 'id': msg_id}), 201

@app.route('/api/messages/<message_id>', methods=['PUT'])
@token_required
def edit_message(message_id):
    data = request.get_json()
    db = read_db()
    for chat in db['chats'].values():
        if message_id in chat['messages']:
            msg = chat['messages'][message_id]
            if msg['sender'] != request.current_user:
                return jsonify({'error': 'Unauthorized'}), 403
            if msg['deleted']:
                return jsonify({'error': 'Cannot edit deleted message'}), 400
            msg['content'] = data['content']
            msg['edited'] = True
            write_db(db)
            return jsonify({'message': 'Edited'})
    return jsonify({'error': 'Message not found'}), 404

@app.route('/api/messages/<message_id>', methods=['DELETE'])
@token_required
def delete_message(message_id):
    db = read_db()
    for chat in db['chats'].values():
        if message_id in chat['messages']:
            msg = chat['messages'][message_id]
            if msg['sender'] != request.current_user:
                return jsonify({'error': 'Unauthorized'}), 403
            msg['deleted'] = True
            msg['content'] = 'This message was deleted'
            write_db(db)
            return jsonify({'message': 'Deleted'})
    return jsonify({'error': 'Message not found'}), 404

# ─── File Upload ────────────────────────────────────────────────
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
    filename = f"{request.current_user}_{uuid.uuid4().hex}.{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    return jsonify({'filename': filename})

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ─── Run ────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)