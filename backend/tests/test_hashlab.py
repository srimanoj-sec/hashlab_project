from fastapi.testclient import TestClient
from app.main import app, digest_bytes, hamming_distance, ALGORITHMS

client = TestClient(app)

def test_health_and_algorithms():
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(client.get("/api/algorithms").json()) == 6

def test_frontend_origin_allowed_by_cors():
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://127.0.0.1:5174",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5174"

def test_digest_lengths():
    expected = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-512": 128, "SHA3-256": 64, "SHA3-512": 128}
    for algorithm, chars in expected.items():
        assert len(digest_bytes(b"abc", algorithm)) == chars

def test_deterministic_hashing():
    assert digest_bytes(b"abc", "SHA-256") == digest_bytes(b"abc", "SHA-256")

def test_input_change_changes_digest_for_sample():
    for algorithm in ALGORITHMS:
        assert digest_bytes(b"Hello", algorithm) != digest_bytes(b"hello", algorithm)

def test_hamming_distance():
    assert hamming_distance("00", "01") == 1
    assert hamming_distance("00", "ff") == 8

def test_hash_endpoint():
    response = client.post("/api/hash", json={"text": "Hello", "algorithms": ["SHA-256", "SHA3-256"]})
    assert response.status_code == 200
    assert len(response.json()["results"]) == 2

def test_mutation_endpoint():
    response = client.post("/api/mutate", json={"text": "Hello", "mutation": "flip_bit", "position": 0})
    assert response.status_code == 200
    assert len(response.json()["results"]) == 6
    assert all(0 <= row["avalanche_percent"] <= 100 for row in response.json()["results"])

def test_invalid_algorithm_rejected():
    response = client.post("/api/hash", json={"text": "x", "algorithms": ["NOT-A-HASH"]})
    assert response.status_code == 400

def test_empty_mutation_rejected():
    response = client.post("/api/mutate", json={"text": "", "mutation": "flip_bit"})
    assert response.status_code == 400
