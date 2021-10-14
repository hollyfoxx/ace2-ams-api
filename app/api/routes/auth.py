import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from api.models.auth import Auth
from api.routes import helpers
from core.auth import create_access_token, create_refresh_token, refresh_token, validate_access_token
from core.config import get_settings
from db import crud
from db.database import get_db


router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
)


def _set_access_token_cookie(response: Response, access_token: str):
    # The cookie will expire just prior to the actual JWT expiration to avoid a case where the frontend
    # still has the cookie but the JWT inside of it expired.
    #
    # The access_token will only be used on the /api/auth/refresh API endpoint
    access_expiration = get_settings().jwt_access_expire_seconds - 5
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=get_settings().cookies_secure,
        samesite=get_settings().cookies_samesite,
        max_age=access_expiration,
        expires=access_expiration,
    )


def _set_refresh_token_cookie(response: Response, refresh_token: str):
    # The cookie will expire just prior to the actual JWT expiration to avoid a case where the frontend
    # still has the cookie but the JWT inside of it expired.
    refresh_expiration = get_settings().jwt_refresh_expire_seconds - 5
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {refresh_token}",
        httponly=True,
        secure=get_settings().cookies_secure,
        samesite=get_settings().cookies_samesite,
        max_age=refresh_expiration,
        expires=refresh_expiration,
        path="/api/auth/refresh",
    )


#
# AUTH
#


def auth(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.auth(username=form_data.username, password=form_data.password, db=db)

    if user is None or not user.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    access_token = create_access_token(sub=user.username)
    _set_access_token_cookie(response, access_token)

    refresh_token = create_refresh_token(sub=user.username)
    _set_refresh_token_cookie(response, refresh_token)

    # Set a non-HttpOnly cookie that the frontend application can access to know that it is logged in.
    # The frontend can use the value in this cookie to know when to force the user to log in again
    # since using a refresh token will continually extend its lifetime.
    refresh_expiration = get_settings().jwt_refresh_expire_seconds - 5
    authenticated_until = datetime.datetime.utcnow() + datetime.timedelta(seconds=refresh_expiration)
    response.set_cookie(
        key="authenticated_until",
        value=str(authenticated_until.timestamp()),
        httponly=False,
        secure=get_settings().cookies_secure,
        samesite=get_settings().cookies_samesite,
        max_age=refresh_expiration,
        expires=refresh_expiration,
    )

    # Save the refresh token to the database
    user.refresh_token = refresh_token
    crud.commit(db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


helpers.api_route_auth(
    router=router,
    endpoint=auth,
    response_model=Auth,
    success_desc="Authentication was successful",
    failure_desc="Invalid username or password",
)


#
# AUTH LOGOUT
#


def auth_logout(response: Response, username: str = Depends(validate_access_token), db: Session = Depends(get_db)):
    """
    The logout endpoint only instructs the browser to delete the access and refresh token cookies. If the API is
    being consumed programatically outside of the browser, then the tokens will remain valid until their expiration.
    """
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    response.delete_cookie("authenticated_until")

    user = crud.read_user_by_username(username=username, db=db)
    user.refresh_token = None
    crud.commit(db)


helpers.api_route_auth(
    router=router,
    endpoint=auth_logout,
    path="/logout",
    success_desc="Logout was successful",
    failure_desc="Invalid access token",
)


#
# AUTH REFRESH
#


def auth_refresh(response: Response, new_tokens: dict = Depends(refresh_token)):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    access_token = new_tokens["access_token"]
    _set_access_token_cookie(response, access_token)

    refresh_token = new_tokens["refresh_token"]
    _set_refresh_token_cookie(response, refresh_token)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


helpers.api_route_auth(
    router=router,
    endpoint=auth_refresh,
    response_model=Auth,
    path="/refresh",
    success_desc="Token was successfully refreshed",
    failure_desc="Invalid refresh token",
)
