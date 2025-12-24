from server.services.fastpay_service import FastPayService
from server.db.db_connector import DBConnector

class PaymentProcessor:

    def __init__(self):
        self.db = DBConnector()
        self.fastpay = FastPayService()

    def process_company_payment(self, company_id: int, amount: float):
        """
        Processa pagamento automático de uma empresa
        """

        description = f"Automatic payment for company {company_id}"

        payment_result = self.fastpay.create_payment(
            company_id=company_id,
            amount=amount,
            description=description
        )

        if payment_result["status"] == "SUCCESS":
            self.db.execute_query(
                "create_payment_record",
                {
                    "company_id": company_id,
                    "amount": amount,
                    "transaction_id": payment_result["transaction_id"],
                    "status": "SUCCESS"
                }
            )
            return True

        self.db.execute_query(
            "create_payment_record",
            {
                "company_id": company_id,
                "amount": amount,
                "transaction_id": None,
                "status": "FAILED"
            }
        )
        return False
