import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as pyjwt
from flask_migrate import Migrate

app = Flask(__name__)

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Секретный ключ для JWT
SECRET_KEY = os.getenv("SECRET_KEY", "1q2w3e4r5t6y7u8i9o0p")

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    progress = db.Column(db.JSON, default={})

# Регистрация пользователя
@app.route('/api/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({"error": "Необходимо указать логин, пароль и почту"}), 400

    if len(password) < 8:
        return jsonify({"error": "Пароль слишком короткий. Он должен содержать не менее 8 символов."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Пользователь с таким логином уже существует"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Пользователь с такой почтой уже существует"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Регистрация пройдена успешна!"}), 200

# Авторизация пользователя
@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Введите логин и пароль"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Аккаунта с таким именем не существует"}), 404

    if not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Неверный пароль"}), 401

    token = pyjwt.encode({"username": user.username}, SECRET_KEY, algorithm="HS256")
    return jsonify({"message": "Авторизация успешна!", "token": token}), 200

# Автоматическая авторизация через токен
@app.route('/api/auto_login', methods=['POST'])
def auto_login():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"error": "Токен не предоставлен"}), 400

    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("username")

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "Пользователь не найден"}), 404

        return jsonify({"message": "Авторизация успешна!", "username": user.username}), 200
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "Срок действия токена истек"}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "Неверный токен"}), 401

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
