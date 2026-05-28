"""Input query validation model."""

# Standard Library
import typing as t
import hashlib
import secrets
from datetime import UTC, datetime

# Third Party
from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator, StringConstraints
from typing_extensions import Annotated

# Project
from hyperglass.log import log
from hyperglass.util import snake_to_camel, repr_from_attrs
from hyperglass.state import use_state
from hyperglass.plugins import InputPluginManager
from hyperglass.exceptions.public import InputInvalid, QueryTypeNotFound, QueryLocationNotFound
from hyperglass.exceptions.private import InputValidationError

# Local
from ..config.devices import Device


QueryLocation = Annotated[str, StringConstraints(strict=True, min_length=1, strip_whitespace=True)]
QueryTarget = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]
QueryType = Annotated[str, StringConstraints(strict=True, min_length=1, strip_whitespace=True)]


class SimpleQuery(BaseModel):
    """A simple representation of a post-validated query."""

    query_location: str
    query_target: t.Union[t.List[str], str]
    query_type: str

    def __repr_name__(self) -> str:
        """Alias SimpleQuery to Query for clarity in logging."""
        return "Query"


class Query(BaseModel):
    """Validation model for input query parameters."""

    model_config = ConfigDict(extra="allow", alias_generator=snake_to_camel, populate_by_name=True)

    # Device `id` (or `name`, normalized to `id` by the validator)
    query_location: QueryLocation

    query_target: t.Union[t.List[QueryTarget], QueryTarget]

    # Directive `id` field
    query_type: QueryType
    _kwargs: t.Dict[str, t.Any]

    def __init__(self, **data) -> None:
        """Initialize the query with a UTC timestamp at initialization time."""
        super().__init__(**data)
        self._kwargs = data
        self.timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

        state = use_state()
        self._state = state

        try:
            self.directive = self.device.directives[self.query_type]
        except IndexError as err:
            raise QueryTypeNotFound(query_type=self.query_type) from err

        self._input_plugin_manager = InputPluginManager()

        try:
            self.validate_query_target()
        except InputValidationError as err:
            raise InputInvalid(**err.kwargs) from err

        self.query_target = self.transform_query_target()

    def summary(self) -> SimpleQuery:
        """Summarized and post-validated model of a Query."""
        return SimpleQuery(
            query_location=self.query_location,
            query_target=self.query_target,
            query_type=self.query_type,
        )

    def __repr__(self) -> str:
        """Represent only the query fields."""
        return repr_from_attrs(self, ("query_location", "query_type", "query_target"))

    def __str__(self) -> str:
        """Alias __str__ to __repr__."""
        return repr(self)

    def digest(self) -> str:
        """Create SHA256 hash digest of model representation."""
        return hashlib.sha256(repr(self).encode()).hexdigest()

    def random(self) -> str:
        """Create a random string to prevent client or proxy caching."""
        return hashlib.sha256(
            secrets.token_bytes(8) + repr(self).encode() + secrets.token_bytes(8)
        ).hexdigest()

    def validate_query_target(self) -> None:
        """Validate a query target after all fields/relationships have been initialized."""
        # Run config/rule-based validations.
        self.directive.validate_target(self.query_target)
        # Run plugin-based validations.
        self._input_plugin_manager.validate(query=self)
        log.bind(query=self.summary()).debug("Validation passed")

    def transform_query_target(self) -> t.Union[t.List[str], str]:
        """Transform a query target based on defined plugins."""
        return self._input_plugin_manager.transform(query=self)

    def dict(self) -> t.Dict[str, t.Union[t.List[str], str]]:
        """Include only public fields."""
        return super().model_dump(include={"query_location", "query_target", "query_type"})

    @property
    def device(self) -> Device:
        """Get this query's device object by query_location."""
        return self._state.devices[self.query_location]

    @field_validator("query_location")
    def validate_query_location(cls, value):
        """Ensure query_location resolves to a known device, normalizing to its id."""

        devices = use_state("devices")

        for device in devices:
            if value == device.id:
                return value
            if value == device.name:
                return device.id

        raise QueryLocationNotFound(location=value)

    @field_validator("query_type")
    def validate_query_type(cls, value: t.Any, info: ValidationInfo):
        """Ensure the requested query type exists on the targeted device."""
        location = info.data.get("query_location")
        if location is None:
            # query_location failed to validate; surface that error instead.
            return value

        devices = use_state("devices")
        device = devices[location]

        if device.has_directives(value):
            return value

        raise QueryTypeNotFound(query_type=value)
