from flask import Flask, request, jsonify
import mysql.connector
import random
import string
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
CORS(app)
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY')
jwt = JWTManager(app)

db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

def get_db():
    return mysql.connector.connect(**db_config)

#login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    usuario = cursor.fetchone()
    cursor.close()
    db.close()

    if not usuario:
        return jsonify({'mensaje': 'Credenciales incorrectas'}), 401

    # Veri el hashsito
    if not bcrypt.checkpw(password.encode('utf-8'), usuario['password'].encode('utf-8')):
        return jsonify({'mensaje': 'Credenciales incorrectas'}), 401

    if usuario['rol'] == 'administrador':
        codigo = ''.join(random.choices(string.digits, k=6))
        expira_en = datetime.now() + timedelta(minutes=5)

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO otp_codes (usuario_id, codigo, expira_en) VALUES (%s, %s, %s)",
                       (usuario['id'], codigo, expira_en))
        db.commit()
        cursor.close()
        db.close()

        return jsonify({
            'mensaje': 'OTP generado',
            'rol': 'administrador',
            'usuario_id': usuario['id'],
            'otp': codigo
        }), 200

    else:
        token = create_access_token(identity=str(usuario['id']))
        return jsonify({
            'mensaje': 'Login exitoso',
            'rol': 'empleado',
            'token': token
        }), 200

# vali el OTP
@app.route('/verificar-otp', methods=['POST'])
def verificar_otp():
    data = request.get_json()
    usuario_id = data.get('usuario_id')
    codigo = data.get('codigo')

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM otp_codes 
        WHERE usuario_id = %s AND codigo = %s AND usado = FALSE AND expira_en > NOW()
        ORDER BY created_at DESC LIMIT 1
    """, (usuario_id, codigo))
    otp = cursor.fetchone()

    if not otp:
        cursor.close()
        db.close()
        return jsonify({'mensaje': 'Código inválido o expirado'}), 401

    cursor.execute("UPDATE otp_codes SET usado = TRUE WHERE id = %s", (otp['id'],))
    db.commit()
    cursor.close()
    db.close()

    token = create_access_token(identity=str(usuario_id))
    return jsonify({'mensaje': 'Acceso concedido', 'rol': 'administrador', 'token': token}), 200
   

@app.route('/obtener-otp/<int:usuario_id>', methods=['GET'])
@jwt_required()
def obtener_otp(usuario_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT codigo, expira_en FROM otp_codes 
        WHERE usuario_id = %s AND usado = FALSE AND expira_en > NOW()
        ORDER BY created_at DESC LIMIT 1
    """, (usuario_id,))
    otp = cursor.fetchone()
    cursor.close()
    db.close()

    if not otp:
        return jsonify({'mensaje': 'No hay código pendiente'}), 404

    return jsonify({
        'codigo': otp['codigo'],
        'expira_en': str(otp['expira_en'])
    }), 200

@app.route('/registro', methods=['POST'])
def registro():
    data = request.get_json()
    nombre = data.get('nombre')
    email = data.get('email')
    password = data.get('password')
    rol = data.get('rol')

    if rol not in ['administrador', 'empleado']:
        return jsonify({'mensaje': 'Rol inválido'}), 400

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO usuarios (nombre, email, password, rol) VALUES (%s, %s, %s, %s)",
                       (nombre, email, hashed, rol))
        db.commit()
        cursor.close()
        db.close()
        return jsonify({'mensaje': 'Usuario registrado correctamente'}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'mensaje': 'El email ya está registrado'}), 409
    
if __name__ == '__main__':
    app.run(debug=True)