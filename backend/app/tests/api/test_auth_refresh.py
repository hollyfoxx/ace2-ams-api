import time

from fastapi import status

from core.config import Settings
from tests.helpers import create_test_user


#
# INVALID TESTS


def test_auth_refresh_invalid_token(client):
    post = client.post("/api/auth/refresh", headers={"Authorization": "Bearer asdf"})
    assert post.status_code == status.HTTP_401_UNAUTHORIZED
    assert post.json()["detail"] == "Invalid token"


def test_expired_token(client, db, monkeypatch):
    def mock_get_settings():
        settings = Settings()
        settings.jwt_refresh_expire_seconds = 1
        return settings

    # Patching __code__ works no matter how the function is imported
    monkeypatch.setattr("core.config.get_settings.__code__", mock_get_settings.__code__)

    create_test_user(db, "johndoe", "abcd1234")

    # Attempt to authenticate
    auth = client.post("/api/auth", data={"username": "johndoe", "password": "abcd1234"})
    refresh_token = auth.json()["refresh_token"]
    assert auth.status_code == status.HTTP_200_OK
    assert auth.json()["token_type"] == "bearer"
    assert refresh_token

    # Wait for the refresh token to expire
    time.sleep(2)

    # Attempt to use the refresh token to obtain a new access token
    refresh = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"})
    assert refresh.status_code == status.HTTP_401_UNAUTHORIZED
    assert refresh.json()["detail"] == "Refresh token expired"


def test_missing_token(client):
    # Attempt to get a new access token without supplying a refresh token
    refresh = client.post("/api/auth/refresh")
    assert refresh.status_code == status.HTTP_401_UNAUTHORIZED
    assert refresh.json()["detail"] == "Not authenticated"


def test_wrong_token_type(client, db):
    create_test_user(db, "johndoe", "abcd1234")

    # Attempt to authenticate
    auth = client.post("/api/auth", data={"username": "johndoe", "password": "abcd1234"})
    access_token = auth.json()["access_token"]
    assert auth.status_code == status.HTTP_200_OK
    assert auth.json()["token_type"] == "bearer"
    assert access_token

    # Attempt to use the access token to obtain a new access token
    refresh = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {access_token}"})
    assert refresh.status_code == status.HTTP_401_UNAUTHORIZED
    assert refresh.json()["detail"] == "Invalid token type"


#
# VALID TESTS
#


def test_auth_refresh_success(client, db, monkeypatch):
    def mock_get_settings():
        settings = Settings()
        settings.jwt_access_expire_seconds = 1
        return settings

    # Patching __code__ works no matter how the function is imported
    monkeypatch.setattr("core.config.get_settings.__code__", mock_get_settings.__code__)

    create_test_user(db, "johndoe", "abcd1234")

    # Attempt to authenticate
    auth = client.post("/api/auth", data={"username": "johndoe", "password": "abcd1234"})
    access_token = auth.json()["access_token"]
    refresh_token = auth.json()["refresh_token"]
    assert auth.status_code == status.HTTP_200_OK
    assert auth.json()["token_type"] == "bearer"
    assert access_token
    assert refresh_token

    # Attempt to use the token to access a protected API endpoint
    get = client.get("/api/user/", headers={"Authorization": f"Bearer {access_token}"})
    assert get.status_code == status.HTTP_200_OK
    assert len(get.json()) == 1

    # Wait for the access token to expire
    time.sleep(2)

    # Attempt to use the access token to access a protected API endpoint now that the token is expired
    get = client.get("/api/user/", headers={"Authorization": f"Bearer {access_token}"})
    assert get.status_code == status.HTTP_401_UNAUTHORIZED
    assert get.json()["detail"] == "Access token expired"

    # Attempt to refresh the access token
    refresh = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"})
    new_access_token = refresh.json()["access_token"]
    assert refresh.status_code == status.HTTP_200_OK
    assert new_access_token
    assert new_access_token != access_token
    assert refresh.json()["refresh_token"] is None

    # Attempt to use the new access token to access a protected API endpoint
    get = client.get("/api/user/", headers={"Authorization": f"Bearer {new_access_token}"})
    assert get.status_code == status.HTTP_200_OK
    assert len(get.json()) == 1