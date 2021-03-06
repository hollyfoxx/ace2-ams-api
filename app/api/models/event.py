from datetime import datetime
from pydantic import Field, UUID4
from typing import List, Optional
from uuid import uuid4

from api.models import type_str, validators
from api.models.node import NodeBase, NodeCreate, NodeRead, NodeUpdate
from api.models.event_prevention_tool import EventPreventionToolRead
from api.models.event_remediation import EventRemediationRead
from api.models.event_risk_level import EventRiskLevelRead
from api.models.event_source import EventSourceRead
from api.models.event_status import EventStatusRead
from api.models.event_type import EventTypeRead
from api.models.event_vector import EventVectorRead
from api.models.user import UserRead


class EventBase(NodeBase):
    """Represents a collection of alerts that combine to form an attack."""

    alert_time: Optional[datetime] = Field(description="The time of the earliest alert in the event")

    contain_time: Optional[datetime] = Field(description="The time the attack represented by the event was contained")

    # TODO: Make this a calculated value based on the alerts as they get added to the event
    disposition_time: Optional[datetime] = Field(
        description="The earliest time one of the alerts in the event was dispositioned"
    )

    event_time: Optional[datetime] = Field(description="The time at which the attack represented by the event occurred")

    name: type_str = Field(description="The name of the event")

    owner: Optional[type_str] = Field(description="The username of the user who has taken ownership of this event")

    # TODO: Make this a calculated value based on the alerts as they are added to the event
    ownership_time: Optional[datetime] = Field(
        description="The earliest time an analyst took ownership over an alert in the event"
    )

    prevention_tools: List[type_str] = Field(
        default_factory=list, description="A list of prevention tools involved in the event"
    )

    remediation_time: Optional[datetime] = Field(
        description="The earliest time that any remediation was performed on the attack represented by the event"
    )

    remediations: List[type_str] = Field(
        default_factory=list,
        description="A list of remediations performed to clean up the attack represented by the event",
    )

    risk_level: Optional[type_str] = Field(description="The risk level assigned to the event")

    source: Optional[type_str] = Field(description="The source of the event")

    status: type_str = Field(description="The status assigned to the event")

    type: Optional[type_str] = Field(description="The type assigned to the event")

    vectors: List[type_str] = Field(default_factory=list, description="A list of vectors assigned to the event")


class EventCreate(NodeCreate, EventBase):
    uuid: UUID4 = Field(default_factory=uuid4, description="The UUID of the event")


class EventRead(NodeRead, EventBase):
    alert_uuids: List[UUID4] = Field(default_factory=list, description="A list of alert UUIDs contained in the event")

    creation_time: datetime = Field(description="The time the event was created")

    owner: Optional[UserRead] = Field(description="The user who has taken ownership of this event")

    prevention_tools: List[EventPreventionToolRead] = Field(
        description="A list of prevention tools involved in the event"
    )

    remediations: List[EventRemediationRead] = Field(
        description="A list of remediations performed to clean up the attack represented by the event"
    )

    risk_level: Optional[EventRiskLevelRead] = Field(description="The risk level assigned to the event")

    source: Optional[EventSourceRead] = Field(description="The source of the event")

    status: EventStatusRead = Field(description="The status assigned to the event")

    type: Optional[EventTypeRead] = Field(description="The type assigned to the event")

    uuid: UUID4 = Field(description="The UUID of the event")

    vectors: List[EventVectorRead] = Field(description="A list of vectors assigned to the event")

    _convert_association_list: classmethod = validators.convert_association_list("alert_uuids")

    class Config:
        orm_mode = True


class EventUpdate(NodeUpdate, EventBase):
    name: Optional[type_str] = Field(description="The name of the event")

    status: Optional[type_str] = Field(description="The status assigned to the event")

    _prevent_none: classmethod = validators.prevent_none("name", "status")
