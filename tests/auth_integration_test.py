import pytest
from fastapi import HTTPException
from fastapi.params import Security
from fastapi.testclient import TestClient
from typing_extensions import Annotated

from fastapi_auth0 import Auth0TokenVerifier, JWTPayload

from fastapi import FastAPI

app = FastAPI()

verifier = Auth0TokenVerifier(domain="", audience="", scopes={})


@app.get("/test/token")
def good_token_endpoint(token: Annotated[JWTPayload, Security(verifier.verify)]):
    if token:
        return token.claims

    raise HTTPException(status_code=400, detail="Token not populated from verifier")


@app.get("/test/scoped")
def good_scoped_endpoint(
    token: Annotated[
        JWTPayload,
        Security(verifier.verify, scopes=["user:read:me", "user:read", "company:read"]),
    ],
):
    if token:
        return token.claims

    raise HTTPException(status_code=400, detail="Token not populated from verifier")


@app.get("/test/scopebad")
def bad_token_scoped_endpoint(
    token: Annotated[
        JWTPayload, Security(verifier.verify, scopes=["garbage:scope", "user:read"])
    ],
):
    if token:
        return token.claims

    raise HTTPException(status_code=400, detail="Token not populated from verifier")


@pytest.mark.integration
def test_auth_token_verifier_works(headers):
    client = TestClient(app)
    response = client.get("/test/token", headers=headers)
    assert response.status_code == 200, response.text

    response = client.get("test/scoped", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()
    # client-credential flow won't populate email claim
    assert all(
        key in data
        for key in ["sub", "scope", "permissions", "iat", "exp", "iss", "aud"]
    ), data


@pytest.mark.integration
def test_bad_headers_returns_401_status_code():
    client = TestClient(app)
    response = client.get("/test/token")
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Missing Bearer Token"}

    response = client.get("test/token", headers={})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Missing Bearer Token"}

    response = client.get("test/token", headers={"Authorization": ""})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Missing Bearer Token"}

    response = client.get("test/token", headers={"Authorization": "Bearer"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Missing Bearer Token"}

    response = client.get(
        "/test/token",
        headers={
            "Authorization": "Bearer AZiex12317876naASg123tminm3f98l9ynastmnyiu2342"
        },
    )
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not enough segments"}

    response = client.get(
        "/test/token",
        headers={"Authorization": "AZiex12317876naASg123tminm3f98l9ynastmnyiu2342"},
    )
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Missing Bearer Token"}


@pytest.mark.integration
def test_bad_scope_returns_403(headers):
    client = TestClient(app)
    response = client.get("/test/scopebad", headers=headers)
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Missing 'garbage:scope' scope"}
