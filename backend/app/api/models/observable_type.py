from pydantic import BaseModel, Field, StrictStr, validator
from typing import Optional
from uuid import UUID


class ObservableTypeBase(BaseModel):
    """Represents a type of observable that the application knows about."""

    description: Optional[StrictStr] = Field(
        description="An optional human-readable description of the observable type"
    )

    uuid: Optional[UUID] = Field(description="The UUID of the observable type")

    value: StrictStr = Field(description="The value of the observable type")


class ObservableTypeCreate(ObservableTypeBase):
    pass


class ObservableTypeRead(ObservableTypeBase):
    uuid: UUID = Field(description="The UUID of the observable type")

    class Config:
        orm_mode = True


class ObservableTypeUpdate(ObservableTypeBase):
    value: Optional[StrictStr] = Field(description="The value of the observable type")

    @validator("value")
    def prevent_none(cls, v):
        assert v is not None, "value may not be None"
        return v
