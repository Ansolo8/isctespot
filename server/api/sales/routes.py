from flask import Blueprint, request, jsonify
from db.db_connector import DBConnector
from services.process_sales import ProcessSales
from services.process_payments import PaymentProcessor
from api.auth.jwt_utils import validate_token

sales = Blueprint('sales', __name__)

@sales.route('/user/overview', methods=['GET', 'POST'])
def list_user_sales():
    ''' List user sales function'''
    dbc = DBConnector()
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403

    results = dbc.execute_query(query='get_user_sales', args=payload['user_id'])
    ps = ProcessSales(results, payload['user_id'])
    ps.get_3_most_recent_sales()

    if isinstance(results, list):
        return jsonify({
            'status': 'Ok',
            'sales': results,
            'last_3_sales': ps.last_3_sales,
            'revenue': ps.revenue
        }), 200

    return jsonify({'status': 'Bad request'}), 400


@sales.route('/sales/new', methods=['POST'])
def add_new_sale():
    ''' Add new sale function '''
    dbc = DBConnector()
    dict_data = request.get_json()

    is_valid, payload = validate_token(dict_data.get('token'))
    if not is_valid:
        return jsonify({'status': 'Unauthorised'}), 403

    result = dbc.execute_query(
        query='create_sale',
        args={
            'client_id': dict_data['client_id'],
            'user_id': payload['user_id'],
            'product_id': dict_data['product_id'],
            'quantity': dict_data['quantity']
        }
    )

    if isinstance(result, int):
        # Pagamento automático da venda (simulado)
        payment = PaymentProcessor()

        # Valor fictício (simulação)
        amount = dict_data['quantity'] * 10

        payment.process_company_payment(
            company_id=payload['comp_id'],
            amount=amount
        )

        return jsonify({'status': 'Ok', 'sale_id': result}), 200

    return jsonify({'status': 'Bad request'}), 400

