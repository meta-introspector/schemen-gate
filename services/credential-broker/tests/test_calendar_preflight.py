from pathlib import Path

import httpx
import pytest

from credential_broker.calendar_preflight import PARAMS, URL, check


@pytest.mark.parametrize("status", [200, 401, 403, 302])
def test_exact_read_and_redacted_result(tmp_path: Path, status: int) -> None:
    secret = "secret-canary"
    path = tmp_path / "token"
    path.write_text(secret)
    path.chmod(0o600)
    calls = []

    def provider(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.method == "GET"
        assert str(request.url.copy_with(query=None)) == URL
        assert dict(request.url.params) == PARAMS
        assert request.headers["authorization"] == "Bearer " + secret
        return httpx.Response(
            status,
            json={"kind": "calendar#events"} if status == 200 else {"error": secret},
            headers={"location": "https://outside.example"},
        )

    result = check(path, transport=httpx.MockTransport(provider))
    assert result["status"] == ("PASS" if status == 200 else "FAIL")
    assert result["delegated_flow_verified"] is False
    assert secret not in str(result)
    assert len(calls) == 1


def test_refuses_public_secret_before_network(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("canary")
    path.chmod(0o644)
    with pytest.raises(ValueError):
        check(path)


@pytest.mark.parametrize("body", [b"not JSON", b'{"kind":"wrong"}', b"x" * 4097])
def test_invalid_success_is_not_pass(tmp_path: Path, body: bytes) -> None:
    path = tmp_path / "token"
    path.write_text("canary")
    path.chmod(0o600)
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=body))
    if len(body) > 4096:
        with pytest.raises(ValueError):
            check(path, transport=transport)
    else:
        assert check(path, transport=transport)["status"] == "FAIL"
