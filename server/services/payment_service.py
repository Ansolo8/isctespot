from db.db_connector import DBConnector
from services.fastpay_gateway import FastPayGateway
from api.utils.crypto_helper import decrypt_value

class PaymentService:

    def __init__(self):
        self.db = DBConnector()
        self.fastpay = FastPayGateway()

    def _safe_iban(self, iban: str) -> str:
        return iban[:4] + "****" + iban[-2:]

    def pay_now(self, encrypted_iban: str, amount_cents: int):
        iban = decrypt_value(encrypted_iban)

        print(f"[Payment] Processing payment to {self._safe_iban(iban)}")

        return self.fastpay.execute_payment(
            iban=iban,
            amount_cents=amount_cents
        )

    def schedule(self, encrypted_iban: str, amount_cents: int, execute_at):
        iban = decrypt_value(encrypted_iban)

        print(f"[Payment] Scheduling payment to {self._safe_iban(iban)}")

        return self.fastpay.schedule_payment(
            iban=iban,
            amount_cents=amount_cents,
            execute_at=execute_at
        )
