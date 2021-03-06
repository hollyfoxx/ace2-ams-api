import pytest
import uuid

from fastapi import status


#
# INVALID TESTS
#


@pytest.mark.parametrize(
    "key,value",
    [
        ("default_alert_queue", 123),
        ("default_alert_queue", None),
        ("default_alert_queue", ""),
        ("display_name", 123),
        ("display_name", None),
        ("display_name", ""),
        ("email", 123),
        ("email", None),
        ("email", ""),
        ("email", "johndoe"),
        ("email", "johndoe@test"),
        ("enabled", 123),
        ("enabled", None),
        ("enabled", "True"),
        ("password", 123),
        ("password", None),
        ("password", ""),
        ("password", "abc"),
        ("roles", 123),
        ("roles", None),
        ("roles", "test_role"),
        ("roles", [123]),
        ("roles", [None]),
        ("roles", [""]),
        ("roles", ["abc", 123]),
        ("timezone", 123),
        ("timezone", None),
        ("timezone", ""),
        ("timezone", "Mars/Jezero"),
        ("username", 123),
        ("username", None),
        ("username", ""),
        ("uuid", None),
        ("uuid", 1),
        ("uuid", "abc"),
        ("uuid", ""),
    ],
)
def test_create_invalid_fields(client_valid_access_token, key, value):
    create_json = {
        "default_alert_queue": "test_queue",
        "display_name": "John Doe",
        "email": "johndoe@test.com",
        "password": "abcd1234",
        "roles": ["test_role"],
        "username": "johndoe",
    }
    create_json[key] = value
    create = client_valid_access_token.post("/api/user/", json=create_json)
    assert create.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.parametrize(
    "key",
    [
        ("email"),
        ("username"),
        ("uuid"),
    ],
)
def test_create_duplicate_unique_fields(client_valid_access_token, key):
    # Create an alert queue
    client_valid_access_token.post("/api/alert/queue/", json={"value": "test_queue"})

    # Create a user role
    client_valid_access_token.post("/api/user/role/", json={"value": "test_role"})

    # Create an object
    create1_json = {
        "default_alert_queue": "test_queue",
        "display_name": "John Doe",
        "email": "john@test.com",
        "password": "abcd1234",
        "roles": ["test_role"],
        "username": "johndoe",
        "uuid": str(uuid.uuid4()),
    }
    client_valid_access_token.post("/api/user/", json=create1_json)

    # Ensure you cannot create another object with the same unique field value
    create2_json = {
        "default_alert_queue": "test_queue",
        "display_name": "Jane Doe",
        "email": "jane@test.com",
        "password": "wxyz6789",
        "roles": ["test_role"],
        "username": "janedoe",
        "uuid": str(uuid.uuid4()),
    }
    create2_json[key] = create1_json[key]
    create2 = client_valid_access_token.post("/api/user/", json=create2_json)
    assert create2.status_code == status.HTTP_409_CONFLICT


@pytest.mark.parametrize(
    "key",
    [
        ("default_alert_queue"),
        ("display_name"),
        ("email"),
        ("password"),
        ("roles"),
        ("username"),
    ],
)
def test_create_missing_required_fields(client_valid_access_token, key):
    create_json = {
        "default_alert_queue": "test_queue",
        "display_name": "John Doe",
        "email": "john@test.com",
        "password": "abcd1234",
        "roles": ["test_role"],
        "username": "johndoe",
    }
    del create_json[key]
    create = client_valid_access_token.post("/api/user/", json=create_json)
    assert create.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


#
# VALID TESTS
#


@pytest.mark.parametrize(
    "key,value",
    [("enabled", False), ("timezone", "America/New_York"), ("uuid", str(uuid.uuid4()))],
)
def test_create_valid_optional_fields(client_valid_access_token, key, value):
    # Create an alert queue
    client_valid_access_token.post("/api/alert/queue/", json={"value": "test_queue"})

    # Create a user role
    client_valid_access_token.post("/api/user/role/", json={"value": "test_role"})

    # Create the object
    create_json = {
        "default_alert_queue": "test_queue",
        "display_name": "John Doe",
        "email": "john@test.com",
        "password": "abcd1234",
        "roles": ["test_role"],
        "username": "johndoe",
    }
    create_json[key] = value
    create = client_valid_access_token.post("/api/user/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client_valid_access_token.get(create.headers["Content-Location"])
    assert get.json()[key] == value


def test_create_valid_required_fields(client_valid_access_token):
    # Create an alert queue
    client_valid_access_token.post("/api/alert/queue/", json={"value": "test_queue"})

    # Create a user role
    client_valid_access_token.post("/api/user/role/", json={"value": "test_role"})

    # Create the object
    create_json = {
        "default_alert_queue": "test_queue",
        "display_name": "John Doe",
        "email": "john@test.com",
        "password": "abcd1234",
        "roles": ["test_role"],
        "username": "johndoe",
    }
    create = client_valid_access_token.post("/api/user/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client_valid_access_token.get(create.headers["Content-Location"])
    assert get.json()["default_alert_queue"]["value"] == "test_queue"
    assert get.json()["display_name"] == "John Doe"
    assert get.json()["email"] == "john@test.com"
    assert get.json()["enabled"] is True
    assert "password" not in get.json()
    assert len(get.json()["roles"]) == 1
    assert get.json()["roles"][0]["value"] == "test_role"
    assert get.json()["timezone"] == "UTC"
    assert get.json()["username"] == "johndoe"
