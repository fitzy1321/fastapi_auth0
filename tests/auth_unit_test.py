import contextlib
from typing import Any
from unittest import mock

import pytest
from fastapi.security import HTTPAuthorizationCredentials, SecurityScopes

from fastapi_auth0 import Auth0TokenVerifier, ForbiddenHTTPException


@pytest.fixture
def mock_jwk_client():
    """Mock the PyJWKClient. We don't want network requests in unit tests."""
    with mock.patch("jwt.PyJWKClient") as jwk_client_mock:
        jwk_client_mock.return_value.get_signing_key_from_jwt.return_value = (
            mock.MagicMock()
        )
        yield jwk_client_mock


@contextlib.contextmanager
def get_mock_jwt_decode(payload: dict[str, Any]):
    """Get a mocked jwt payload.

    Remember, keys are called 'claims' in jwt terminology.
    """
    with mock.patch("jwt.decode") as decode_mock:
        decode_mock.return_value = payload
        yield decode_mock


def test_jwt_jwk_mocks_work(mock_jwk_client):
    verifier = Auth0TokenVerifier()

    with get_mock_jwt_decode({"sub": "test_user"}) as mock_jwt_decode:
        token = verifier.verify(
            mock.MagicMock(),
            HTTPAuthorizationCredentials(scheme="bearer", credentials="token"),
        )

    assert mock_jwk_client.called
    assert mock_jwt_decode.called
    assert token is not None
    assert token.id == "test_user"
    assert token.sub == "test_user"
    assert token.claims == {"sub": "test_user"}


def test_scopes(mock_jwk_client):
    payload = {"sub": "test_user_2", "scope": "read:post", "permissions": ["read:post"]}
    verifier = Auth0TokenVerifier()
    with get_mock_jwt_decode(payload) as mock_jwt_decode:
        token = verifier.verify(
            SecurityScopes(["read:post"]),
            HTTPAuthorizationCredentials(scheme="bearer", credentials="token"),
        )

    assert mock_jwk_client.called
    assert mock_jwt_decode.called
    assert token is not None
    assert token.id == "test_user_2"
    assert token.sub == "test_user_2"
    assert token.claims == {
        "sub": "test_user_2",
        "scope": "read:post",
        "permissions": ["read:post"],
    }


def test_missing_scopes_in_token_raises_403(mock_jwk_client):
    payload = {"sub": "test_user_2", "scope": "read:post delete:post create:post"}
    verifier = Auth0TokenVerifier()
    with get_mock_jwt_decode(payload), pytest.raises(ForbiddenHTTPException):
        verifier.verify(
            SecurityScopes(
                ["create:post", "delete:post", "read:post", "missing-scope:nope"]
            ),
            HTTPAuthorizationCredentials(scheme="bearer", credentials="token"),
        )

    assert mock_jwk_client.called
