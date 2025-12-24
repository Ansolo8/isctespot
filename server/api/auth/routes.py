from flask import Blueprint, request, jsonify
from db.db_connector import DBConnector
from api.auth.jwt_utils import issue_token, validate_token
from api.utils.crypto_utils import encrypt_value
import bcrypt

auth = Blueprint('auth', __name__)

# =========================================================
# Password Utilities (bcrypt - non reversible)
# =========================================================

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


# =========================================================
# Authentication
# =========================================================

@auth.route('/login', methods=['POST'])
def login():
    dbc = DBConnector()
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    user_id = dbc.execute_query(query='get_user_by_name', args=username)
    if not isinstance(user_id, int):
        return jsonify({'status': 'Bad credentials'}), 403

    stored_hash = dbc.execute_query(query='get_user_password', args=user_id)
    if not verify_password(password, stored_hash):
        return jsonify({'status': 'Bad credentials'}), 403

    dbc.execute_query(query='update_user_activity', args={
        'user_id': user_id,
        'active': True
    })

    is_admin = bool(dbc.execute_query(query='get_user_admin', args=user_id))
    is_agent = bool(dbc.execute_query(query='get_user_agent', args=user_id))

    comp_id = dbc.execute_query(query='get_user_comp_id', args=user_id)
    if not isinstance(comp_id, int):
        return jsonify({'status': 'Bad request'}), 400

    token = issue_token(
        user_id=user_id,
        comp_id=comp_id,
        is_admin=is_admin,
        is_agent=is_agent
    )

    return jsonify({
        'status': 'Ok',
        'user_id': user_id,
        'token': token,
        'is_admin': is_admin,
        'comp_id': comp_id
    }), 200


@auth.route('/logout', methods=['POST'])
def logout():
    dbc = DBConnector()
    data = request.get_json()

    dbc.execute_query(query='update_user_activity', args={
        'user_id': data.get('user_id'),
        'active': False
    })

    return jsonify({'status': 'Ok'}), 200


# =========================================================
# Signup & User Management
# =========================================================

@auth.route('/signup', methods=['POST'])
def signup():
    dbc = DBConnector()
    data = request.get_json()

    hashed_password = hash_password(data['password'])

    user_id = dbc.execute_query('create_user_admin', args={
        "username": data['username'],
        "password": hashed_password,
        "email": data['email'],
        "comp_name": data['comp_name'],
        "num_employees": data['num_employees'],
        "is_admin": True
    })

    if not isinstance(user_id, int):
        return jsonify({'status': 'Bad request'}), 400

    comp_id = dbc.execute_query('create_company', args={
        "user_id": user_id,
        "comp_name": data['comp_name'],
        "num_employees": data['num_employees']
    })

    dbc.execute_query('update_user_comp_id', args={
        'user_id': user_id,
        'comp_id': comp_id
    })

    token = issue_token(
        user_id=user_id,
        comp_id=comp_id,
        is_admin=True,
        is_agent=False
    )

    return jsonify({
        'status': 'Ok',
        'user_id': user_id,
        'comp_id': comp_id,
        'is_admin': True,
        'token': token
    }), 200


@auth.route('/user/reset-password', methods=['POST'])
def reset_password():
    dbc = DBConnector()
    data = request.get_json()

    is_valid, payload = validate_token(data.get('token'))
    if not is_valid:
        return jsonify({'status': 'Unauthorized'}), 403

    user_id = data.get('user_id')
    if payload.get('is_admin'):
        user_id = payload.get('user_id')

    new_hash = hash_password(data.get('new_password'))

    dbc.execute_query(query='update_user_password', args={
        "user_id": user_id,
        "new_password": new_hash
    })

    return jsonify({'status': 'Ok'}), 200


# =========================================================
# Employees
# =========================================================

@auth.route('/employee/new', methods=['POST'])
def new_employee():
    dbc = DBConnector()
    data = request.get_json()

    is_valid, payload = validate_token(data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    employee_id = dbc.execute_query('create_user_employee', args={
        'username': data['username'],
        'email': data['email'],
        'comp_id': payload['comp_id']
    })

    if isinstance(employee_id, int):
        return jsonify({'status': 'Ok', 'employee_id': employee_id}), 200

    return jsonify({'status': 'Bad request'}), 400


@auth.route('/employee/delete', methods=['POST'])
def delete_employee():
    dbc = DBConnector()
    data = request.get_json()

    is_valid, payload = validate_token(data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    result = dbc.execute_query('delete_user_by_id', data['employee_id'])
    if result is True:
        return jsonify({'status': 'Ok'}), 200

    return jsonify({'status': 'Bad request'}), 400


# =========================================================
# Payment Information (Asymmetric Encryption)
# =========================================================

@auth.route('/user/payment-info', methods=['POST'])
def save_payment_info():
    dbc = DBConnector()
    data = request.get_json()

    is_valid, payload = validate_token(data.get('token'))
    if not is_valid:
        return jsonify({'status': 'Unauthorized'}), 403

    encrypted_iban = encrypt_value(data['nib'])

    dbc.execute_query(
        query='store_user_iban',
        args={
            'user_id': payload['user_id'],
            'iban': encrypted_iban
        }
    )

    return jsonify({'status': 'Ok'}), 200


# =========================================================
# Company Retirement
# =========================================================

@auth.route('/retire', methods=['POST'])
def retire():
    dbc = DBConnector()
    data = request.get_json()

    is_valid, payload = validate_token(data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    comp_id = payload['comp_id']
    user_id = payload['user_id']

    dbc.execute_query('delete_sales_by_comp_id', comp_id)
    dbc.execute_query('delete_products_by_comp_id', comp_id)
    dbc.execute_query('delete_users_by_comp_id', comp_id)
    dbc.execute_query('delete_company_by_id', comp_id)
    dbc.execute_query('delete_user_by_id', user_id)

    return jsonify({'status': 'Ok'}), 200

