from threat_api.main import app


def test_health():
    c = app.test_client()
    r = c.get("/health")
    assert r.status_code == 200
