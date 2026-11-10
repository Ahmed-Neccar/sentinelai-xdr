import base64
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.api.v1.ingest import _verify_registered_sensor_request, _verify_sensor_proof
from app.core.errors import AppError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SignedRequest:
    def __init__(self, *, sensor_id: str, private_key: Ed25519PrivateKey, counter: int = 1):
        self.method = "POST"
        self.url = SimpleNamespace(path="/api/v1/ingest/live/events")
        self.body_bytes = b'{"events":[{"event_type":"net.conn"}]}'
        self.timestamp = str(int(time.time()))
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key = base64.b64encode(public_bytes).decode("ascii")
        message = (
            f"{sensor_id}\n{counter}\n{self.timestamp}\n{self.method}\n{self.url.path}\n".encode()
            + self.body_bytes
        )
        self.headers = {
            "x-sentinel-sensor-id": sensor_id,
            "x-sentinel-timestamp": self.timestamp,
            "x-sentinel-counter": str(counter),
            "x-sentinel-signature": base64.b64encode(private_key.sign(message)).decode("ascii"),
        }

    async def body(self) -> bytes:
        return self.body_bytes


def run_immediate(coroutine):
    """Run proof-validation coroutines that do not perform asynchronous I/O."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Proof validation unexpectedly suspended")


def test_sensor_signature_accepts_exact_request_and_returns_counter() -> None:
    sensor_id = str(uuid4())
    request = SignedRequest(
        sensor_id=sensor_id, private_key=Ed25519PrivateKey.generate(), counter=7
    )

    counter = run_immediate(_verify_sensor_proof(request, sensor_id, request.public_key))

    assert counter == 7


@pytest.mark.parametrize("tamper", ["body", "sensor_id", "path"])
def test_sensor_signature_rejects_tampered_request(tamper: str) -> None:
    sensor_id = str(uuid4())
    request = SignedRequest(sensor_id=sensor_id, private_key=Ed25519PrivateKey.generate())
    if tamper == "body":
        request.body_bytes += b" "
    elif tamper == "sensor_id":
        request.headers["x-sentinel-sensor-id"] = str(uuid4())
    else:
        request.url.path = "/api/v1/ingest/live/finish"

    with pytest.raises(AppError) as error:
        run_immediate(_verify_sensor_proof(request, sensor_id, request.public_key))

    assert error.value.code in {"sensor_proof_invalid", "sensor_proof_expired"}


def test_sensor_signature_rejects_expired_timestamp() -> None:
    sensor_id = str(uuid4())
    request = SignedRequest(sensor_id=sensor_id, private_key=Ed25519PrivateKey.generate())
    request.headers["x-sentinel-timestamp"] = str(int(time.time()) - 120)

    with pytest.raises(AppError) as error:
        run_immediate(_verify_sensor_proof(request, sensor_id, request.public_key))

    assert error.value.code == "sensor_proof_expired"


def test_sensor_request_counter_advances_and_replay_is_rejected() -> None:
    sensor_id = uuid4()
    key = Ed25519PrivateKey.generate()
    request = SignedRequest(sensor_id=str(sensor_id), private_key=key, counter=9)
    registration = SimpleNamespace(
        sensor_id=sensor_id,
        public_key=request.public_key,
        last_request_counter=8,
    )

    run_immediate(_verify_registered_sensor_request(request, registration))

    assert registration.last_request_counter == 9
    with pytest.raises(AppError) as error:
        run_immediate(_verify_registered_sensor_request(request, registration))
    assert error.value.code == "sensor_request_replayed"
