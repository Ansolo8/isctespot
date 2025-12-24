# services/fastpay_gateway.py
import os
import uuid
import requests
from datetime import datetime

class FastPayGateway:

    def __init__(self):
        self.base_url = os.getenv(
            "FASTPAY_API_URL",
            "https://sandbox.fastpay.local"
        )
        self.api_token = os.getenv("FASTPAY_API_TOKEN", "demo-token")

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Idempotency-Key": str(uuid.uuid4()),
            "Content-Type": "application/json"
        }

    def execute_payment(self, iban: str, amount_cents: int):
        payload = {
            "iban": iban,
            "amount": amount_cents,
            "currency": "EUR"
        }

        # Simulação de chamada externa
        print("[FastPay] Executing payment:", payload)
        return {"status": "success", "reference": str(uuid.uuid4())}

    def schedule_payment(self, iban: str, amount_cents: int, execute_at: datetime):
        payload = {
            "iban": iban,
            "amount": amount_cents,
            "currency": "EUR",
            "execute_at": execute_at.isoformat()
        }

        print("[FastPay] Scheduling payment:", payload)
        return {"status": "scheduled", "reference": str(uuid.uuid4())}
