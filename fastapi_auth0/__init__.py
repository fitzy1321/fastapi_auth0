import urllib.parse


from enum import StrEnum
from typing import Any, Sequence

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlowImplicit, OAuthFlows
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2,
    # OAuth2AuthorizationCodeBearer,
    # OAuth2PasswordBearer,
    # OpenIdConnect,
    SecurityScopes,
)


# * ###### JWT and JWKS Terminology ######
# * JWT: JSON Web Token, a string with three sections separated by dots.
# *   Headers: first section of jwt. Should be a dict containing
# *       algorithm info, token type, and kid.
# *     kid: key id, needed when validating signing keys from JWKS.
# *   Payload: second section of jwt, where the token "Claims" live, should be a dict.
# *     Claims: Key/Value pairs inside the payload, user and token data from auth0.
# *   Signature: third section of jwt, used to validate the token has not
# *       been tampered in flight.
# * JWKS: JSON Web Key Set, "keys" list containing public keys to validate JWTs.
# *
# * Note: 'scope' claim is a space-separated string of scopes, sent from auth0.
# *       'permissions' claim is a list of that string, sent from auth0.
# *       `jwt.decode()` does not populate or check for either claim.


class UnauthorizedHTTPException(HTTPException):
    """Returns HTTP 401"""

    def __init__(self, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail, headers=headers)


class ForbiddenHTTPException(HTTPException):
    """Returns HTTP 403"""

    def __init__(self, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status.HTTP_403_FORBIDDEN, detail, headers)


class OAuth2ImplicitBearer(OAuth2):
    """OAuth2 Implicit Bearer Flow repersentation.

    It's main function is to fetch Tokens from OpenAPI Authorize modal.

    Example usage:
    ```python
    auth = Auth0TokenVerifier(...)
    app = FastAPI(dependencies=[Depends(auth.implicit_scheme)])
    ```
    or
    ```python
    @app.get("/", dependencies=[Depends(auth.implicit_scheme)])
    def func(): ...
    ```
    """

    def __init__(
        self,
        authorizationUrl: str,  # noqa: N803
        scopes: dict[str, str] | None = None,
        scheme_name: str | None = None,
        auto_error: bool = True,
    ) -> None:
        flows = OAuthFlows(
            implicit=OAuthFlowImplicit(
                authorizationUrl=authorizationUrl,
                scopes=scopes or {},
            )
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        # Overload call method to prevent computational overhead.
        # The actual authentication is done in `Authenticator.verify`.
        # This is for OpenAPI Docs Authorize modal.
        return None


class Algorithms(StrEnum):
    """Colletion of Key Signing Algorithms."""

    RS256 = "RS256"
    HS256 = "HS256"


class _Claims(StrEnum):
    """Collection of important claims."""

    EMAIL = "email"
    PERMISSIONS = "permissions"
    SCOPE = "scope"
    SUBJECT = "sub"


class JWTPayload:
    """Token data returned from verify."""

    def __init__(
        self,
        *,
        email: str | None = None,
        permissions: list[str] | None = None,
        sub: str,
        **kwargs,
    ) -> None:
        # The func arg names need to match the claims from payload dict keys.
        self.id = self.sub = sub
        self.claims: dict[str, Any] = {"sub": sub}

        self.email = email
        if email:
            self.claims["email"] = email

        self.permissions = permissions
        if permissions:
            self.claims["permissions"] = permissions

        if kwargs:
            self.claims.update(kwargs)


class Auth0TokenVerifier:
    """Does all the token verification using PyJWT.

    Example Usage:
    ```python
    auth = Auth0TokenVerifier(...)
    app = FastAPI()

    @app.get("/")
    def index(token: Annotated[Token, Security(auth.verify)]):
        pass

    @app.get("/no_data", dependencies=[Security(auth.verify)])
    def token_no_data():
        pass

    @app.get("/scoped")
    def scoped(token: Annotated[Token, Security(auth.verify, scopes=["read"])]):
        pass

    @app.get(
        "/scoped_no_data",
        dependencies=[Security(auth.verify, scopes=["read"])],
        )
    def scoped_no_data():
        pass
    ```
    """

    def __init__(
        self,
        *,
        algorithm: Algorithms = Algorithms.RS256,
        audience: str = "",
        domain: str = "",
        scopes: dict[str, str] | None = None,
    ) -> None:
        self._algorithms = [str(algorithm)]
        self._audience = audience
        self._issuer = f"https://{domain}/"

        self._jwks_client = jwt.PyJWKClient(
            f"https://{domain}/.well-known/jwks.json", cache_keys=True
        )

        # Various OAuth2 Flows for OpenAPI interface
        params = urllib.parse.urlencode({"audience": self._audience})
        self._auth_url = f"https://{domain}/authorize?{params}"

        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=self._auth_url,
            scopes=scopes,
        )

        # TODO: uncomment and test later
        # self.authcode_scheme = OAuth2AuthorizationCodeBearer(
        #     authorizationUrl=auth_url,
        #     tokenUrl=f"https://{self._domain}/oauth/token",
        #     scopes=scopes,
        # )
        # self.password_scheme = OAuth2PasswordBearer(
        #     tokenUrl=f"https://{self._domain}/oauth/token", scopes=scopes
        # )
        # self.oidc_scheme = OpenIdConnect(
        #     openIdConnectUrl=f"https://{self._domain}/.well-known/openid-configuration"
        # )

    def verify(
        self,
        security_scopes: SecurityScopes,
        token: HTTPAuthorizationCredentials | None = Depends(
            HTTPBearer(auto_error=False)  # noqa: B008
        ),
    ) -> JWTPayload:
        # FastAPI HTTPBearer does not raise the correct status codes IMO
        # `auto_error=False` will send a None token instead of raising errors
        # We want this behavior so we can set our error status codes "correctly"
        if token is None:
            raise UnauthorizedHTTPException(
                detail="Missing Bearer Token",
                headers={"WWW-Authenticate": 'Bearer realm="janus_api"'},
            )

        try:
            # TODO: find async version of this.
            # Network request happens here. NO MORE MOCKING EVERY TEST! YAY!
            signing = self._jwks_client.get_signing_key_from_jwt(token.credentials)
        except (jwt.exceptions.PyJWKClientError, jwt.exceptions.DecodeError) as e:
            raise UnauthorizedHTTPException(
                detail=str(e),
                headers={"WWW-Authenticate": 'Bearer realm="janus_api"'},
            ) from e

        try:
            # use `jwt.api_jwt.decode_complete()` to get jwt headers and payload
            payload: dict = jwt.decode(
                token.credentials,
                signing.key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
            )
        except Exception as e:
            raise ForbiddenHTTPException(str(e)) from e

        self._check_claims(payload, _Claims.SUBJECT)

        # ? not sure if these are needed? or might be occastional needed ?
        # self._check_claims(payload, ClaimNames.EMAIL)
        # self._check_claims(payload, _Claims.PERMISSIONS)

        if len(security_scopes.scopes) > 0:
            self._check_claims(payload, _Claims.SCOPE, security_scopes.scopes)

        try:
            return JWTPayload(**payload)
        except Exception as e:
            raise ForbiddenHTTPException(detail=f"Error parsing token: {str(e)}") from e

    def _check_claims(
        self,
        payload: dict,
        claim_name: _Claims,
        expected_value: Sequence[Any] | None = None,
    ) -> None:
        _claim_name = str(claim_name)

        err_msg = f"Missing required claim '{_claim_name}'"
        if _claim_name not in payload:
            raise ForbiddenHTTPException(detail=err_msg)

        if not expected_value:
            return

        payload_claim = (
            payload[_claim_name].split(" ")
            if claim_name == _Claims.SCOPE
            else payload[_claim_name]
        )

        for value in expected_value:
            if value not in payload_claim:
                if claim_name == _Claims.SCOPE:
                    err_msg = f"Missing '{value}' scope"
                else:
                    err_msg = f"Missing '{value}' {_claim_name}"
                raise ForbiddenHTTPException(detail=err_msg)
