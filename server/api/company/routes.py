import os
from flask import Blueprint, request, jsonify, abort, send_file
from db.db_connector import DBConnector
from services.process_file import ProcessFile
from services.process_cash_flow import ProcessCashFlow
from services.process_sales import ProcessSales
from services.process_payments import PaymentProcessor
from api.auth.jwt_utils import validate_token

company = Blueprint('company', __name__)

@company.route('/analytics', methods=['GET', 'POST'])
def list_clients():
    ''' List Sales function'''
    dbc = DBConnector()
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorised'}), 403

    results = dbc.execute_query(query='get_company_sales', args=payload['comp_id'])

    pcf = ProcessCashFlow(payload['comp_id'], 'PT', month=7)
    revenue = pcf.revenue

    ps = ProcessSales(results, payload['user_id'])
    ps.get_3_most_recent_sales()

    if isinstance(results, list):
        return jsonify({
            'status': 'Ok',
            'last_3_sales': ps.last_3_sales,
            'revenue': revenue,
            'sales': results
        }), 200

    return jsonify({'status': 'Bad request'}), 403


@company.route('/employees', methods=['GET', 'POST'])
def list_employees():
    ''' List employees function'''
    dbc = DBConnector()
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorised'}), 403

    results = dbc.execute_query(query='get_employees_list', args=payload['comp_id'])
    if isinstance(results, list):
        return jsonify({'status': 'Ok', 'employees': results}), 200

    return jsonify({'status': 'Bad request'}), 403


@company.route('/products', methods=['GET', 'POST'])
def list_products():
    ''' List products for given company '''
    dbc = DBConnector()
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403

    results = dbc.execute_query(query='get_products_list', args=payload['comp_id'])
    if isinstance(results, list):
        return jsonify({'status': 'Ok', 'products': results}), 200

    return jsonify({'status': 'Bad request'}), 403


@company.route('/payments/auto', methods=['POST'])
def automatic_payment():
    ''' Automatic company payment '''
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorised'}), 403

    amount = dict_data.get('amount')
    description = dict_data.get('description', 'Automatic company payment')

    payment = PaymentProcessor()
    success = payment.process_company_payment(
        company_id=payload['comp_id'],
        amount=amount
    )

    if success:
        return jsonify({'status': 'Ok', 'message': 'Payment processed successfully'}), 200

    return jsonify({'status': 'Error', 'message': 'Payment failed'}), 500


@company.route('/payment-card', methods=['POST'])
def add_payment_card():
    data = request.get_json()
    is_valid, payload = validate_token(data.get('token'))

    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    encrypted_card = encrypt_value(data['card_number'])

    dbc = DBConnector()
    dbc.execute_query(
        query='store_company_card',
        args={
            'company_id': payload['comp_id'],
            'card': encrypted_card,
            'exp_month': data['exp_month'],
            'exp_year': data['exp_year']
        }
    )

    return jsonify({'status': 'Ok'}), 200


@company.route('/pay', methods=['POST'])
def pay_now():
    data = request.get_json()
    is_valid, payload = validate_token(data.get('token'))

    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    service = PaymentService()
    result = service.pay_now(
        encrypted_iban=data['destination_iban'],
        amount_cents=data['amount_cents']
    )

    return jsonify({'status': result['status']}), 200


@company.route('/schedule-pay', methods=['POST'])
def schedule_pay():
    data = request.get_json()
    is_valid, payload = validate_token(data.get('token'))

    if not is_valid or not payload.get('is_admin'):
        return jsonify({'status': 'Unauthorized'}), 403

    service = PaymentService()
    result = service.schedule(
        encrypted_iban=data['destination_iban'],
        amount_cents=data['amount_cents'],
        execute_at=datetime.fromisoformat(data['schedule_at'])
    )

    return jsonify({'status': result['status']}), 200
