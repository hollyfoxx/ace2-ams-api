import pytest
import uuid

from fastapi import status
from fastapi.testclient import TestClient
from typing import Tuple

from tests.api.node import (
    INVALID_CREATE_FIELDS,
    NONEXISTENT_FIELDS,
    VALID_DIRECTIVES,
    VALID_TAGS,
    VALID_THREAT_ACTOR,
    VALID_THREATS,
)


def create_alert(client: TestClient) -> Tuple[str, str]:
    """
    Helper function to create an alert. Returns a tuple of (alert_uuid, analysis_uuid)
    """

    # Create an alert queue and type
    client.post("/api/alert/queue/", json={"value": "test_queue"})
    client.post("/api/alert/type/", json={"value": "test_type"})

    # Create the alert
    create_json = {"queue": "test_queue", "type": "test_type"}
    create = client.post("/api/alert/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])

    return get.json()["uuid"], get.json()["analysis"]["uuid"]


#
# INVALID TESTS
#


@pytest.mark.parametrize(
    "key,value",
    [
        ("alert_uuid", 123),
        ("alert_uuid", None),
        ("alert_uuid", ""),
        ("alert_uuid", "abc"),
        ("context", 123),
        ("context", ""),
        ("parent_analysis_uuid", 123),
        ("parent_analysis_uuid", None),
        ("parent_analysis_uuid", ""),
        ("parent_analysis_uuid", "abc"),
        ("performed_analysis_uuids", 123),
        ("performed_analysis_uuids", "abc"),
        ("performed_analysis_uuids", [123]),
        ("performed_analysis_uuids", [None]),
        ("performed_analysis_uuids", [""]),
        ("performed_analysis_uuids", ["abc"]),
        ("redirection_uuid", 123),
        ("redirection_uuid", ""),
        ("redirection_uuid", "abc"),
        ("time", None),
        ("time", ""),
        ("time", "Monday"),
        ("time", "2022-01-01"),
        ("type", 123),
        ("type", None),
        ("type", ""),
        ("uuid", 123),
        ("uuid", None),
        ("uuid", ""),
        ("uuid", "abc"),
        ("value", 123),
        ("value", None),
        ("value", ""),
    ],
)
def test_create_invalid_fields(client, key, value):
    create_json = {
        key: value,
        "alert_uuid": str(uuid.uuid4()),
        "parent_analysis_uuid": str(uuid.uuid4()),
        "type": "test_type",
        "value": "test",
    }
    create_json[key] = value
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert key in create.text


@pytest.mark.parametrize(
    "key,value",
    INVALID_CREATE_FIELDS,
)
def test_create_invalid_node_fields(client, key, value):
    create_json = {
        key: value,
        "alert_uuid": str(uuid.uuid4()),
        "parent_analysis_uuid": str(uuid.uuid4()),
        "type": "test_type",
        "value": "test",
    }
    create_json[key] = value
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_duplicate_uuid(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an object
    create_json = {
        "uuid": str(uuid.uuid4()),
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    client.post("/api/observable/instance/", json=create_json)

    # Ensure you cannot create another object with the same UUID
    create2 = client.post("/api/observable/instance/", json=create_json)
    assert create2.status_code == status.HTTP_409_CONFLICT


def test_create_nonexistent_alert(client):
    # Create an alert
    _, analysis_uuid = create_alert(client=client)
    alert_uuid = str(uuid.uuid4())

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent alert
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND
    assert alert_uuid in create.text


def test_create_nonexistent_analysis(client):
    # Create an alert
    alert_uuid, _ = create_alert(client=client)
    analysis_uuid = str(uuid.uuid4())

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent analysis
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND
    assert analysis_uuid in create.text


def test_create_nonexistent_performed_analysis(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent performed analysis
    performed_analysis_uuid = str(uuid.uuid4())
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "performed_analysis_uuids": [performed_analysis_uuid],
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND
    assert performed_analysis_uuid in create.text


def test_create_nonexistent_redirection(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent redirection target
    redirection_uuid = str(uuid.uuid4())
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "redirection_uuid": redirection_uuid,
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND
    assert redirection_uuid in create.text


def test_create_nonexistent_type(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent type
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "abc",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND
    assert "abc" in create.text


@pytest.mark.parametrize(
    "key,value",
    NONEXISTENT_FIELDS,
)
def test_create_nonexistent_node_fields(client, key, value):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Ensure you cannot create an observable instance with a nonexistent type
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    create_json[key] = value
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_404_NOT_FOUND


#
# VALID TESTS
#


@pytest.mark.parametrize(
    "key,value",
    [
        ("context", None),
        ("context", "test"),
        ("time", 1640995200),
        ("time", "2022-01-01T00:00:00Z"),
        ("time", "2022-01-01 00:00:00"),
        ("time", "2022-01-01 00:00:00.000000"),
        ("time", "2021-12-31 19:00:00-05:00"),
        ("uuid", str(uuid.uuid4())),
    ],
)
def test_create_valid_optional_fields(client, key, value):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create the observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    create_json[key] = value
    create = client.post("/api/observable/instance/", json=create_json)

    # Read it back
    get = client.get(create.headers["Content-Location"])

    # If the test is for time, make sure that the retrieved value matches the proper UTC timestamp
    if key == "time" and value:
        assert get.json()[key] == "2022-01-01T00:00:00+00:00"
    else:
        assert get.json()[key] == value


def test_create_valid_performed_analysis_uuids(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create some child analyses for the observable instance
    child_analysis_uuid1 = str(uuid.uuid4())
    child_analysis_uuid2 = str(uuid.uuid4())
    client.post("/api/analysis/", json={"uuid": child_analysis_uuid1})
    client.post("/api/analysis/", json={"uuid": child_analysis_uuid2})

    # Create the observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "performed_analysis_uuids": [child_analysis_uuid1, child_analysis_uuid2],
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert sorted(get.json()["performed_analysis_uuids"]) == sorted([child_analysis_uuid1, child_analysis_uuid2])


def test_create_valid_redirection(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    observable_instance_uuid = str(uuid.uuid4())
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "uuid": observable_instance_uuid,
        "value": "test",
    }
    client.post("/api/observable/instance/", json=create_json)

    # Create another observable instance that redirects to the previously created one
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "redirection_uuid": observable_instance_uuid,
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert get.json()["redirection_uuid"] == observable_instance_uuid


def test_create_valid_required_fields(client):
    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert get.status_code == 200
    assert get.json()["alert_uuid"] == alert_uuid
    assert get.json()["parent_analysis_uuid"] == analysis_uuid
    assert get.json()["observable"]["type"]["value"] == "test_type"
    assert get.json()["observable"]["value"] == "test"


@pytest.mark.parametrize(
    "values",
    VALID_DIRECTIVES,
)
def test_create_valid_node_directives(client, values):
    # Create the directives. Need to only create unique values, otherwise the database will return a 409
    # conflict exception and will roll back the test's database session (causing the test to fail).
    for value in list(set(values)):
        client.post("/api/node/directive/", json={"value": value})

    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
        "directives": values,
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert len(get.json()["directives"]) == len(list(set(values)))


@pytest.mark.parametrize(
    "values",
    VALID_TAGS,
)
def test_create_valid_node_tags(client, values):
    # Create the tags. Need to only create unique values, otherwise the database will return a 409
    # conflict exception and will roll back the test's database session (causing the test to fail).
    for value in list(set(values)):
        client.post("/api/node/tag/", json={"value": value})

    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
        "tags": values,
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert len(get.json()["tags"]) == len(list(set(values)))


@pytest.mark.parametrize(
    "value",
    VALID_THREAT_ACTOR,
)
def test_create_valid_node_threat_actor(client, value):
    # Create the threat actor. Need to only create unique values, otherwise the database will return a 409
    # conflict exception and will roll back the test's database session (causing the test to fail).
    if value:
        client.post("/api/node/threat_actor/", json={"value": value})

    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
        "threat_actor": value,
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])
    if value:
        assert get.json()["threat_actor"]["value"] == value
    else:
        assert get.json()["threat_actor"] is None


@pytest.mark.parametrize(
    "values",
    VALID_THREATS,
)
def test_create_valid_node_threats(client, values):
    # Create a threat type
    client.post("/api/node/threat/type/", json={"value": "test_type"})

    # Create the threats. Need to only create unique values, otherwise the database will return a 409
    # conflict exception and will roll back the test's database session (causing the test to fail).
    for value in list(set(values)):
        client.post("/api/node/threat/", json={"types": ["test_type"], "value": value})

    # Create an alert
    alert_uuid, analysis_uuid = create_alert(client=client)

    # Create an observable type
    client.post("/api/observable/type/", json={"value": "test_type"})

    # Create an observable instance
    create_json = {
        "alert_uuid": alert_uuid,
        "parent_analysis_uuid": analysis_uuid,
        "type": "test_type",
        "value": "test",
        "threats": values,
    }
    create = client.post("/api/observable/instance/", json=create_json)
    assert create.status_code == status.HTTP_201_CREATED

    # Read it back
    get = client.get(create.headers["Content-Location"])
    assert len(get.json()["threats"]) == len(list(set(values)))
