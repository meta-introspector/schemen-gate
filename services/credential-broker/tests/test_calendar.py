from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from credential_broker.calendar import GOOGLE_ORIGIN, calendar_request
from credential_broker.models import BrokerError


def proposal() -> dict[str, Any]:
    return {
        "calendar_id": "primary",
        "send_updates": "none",
        "event": {
            "id": "ec8a63348cd24a2ba3eb25a7484179f1",
            "summary": "One approved meeting",
            "start": {"dateTime": "2026-09-09T17:00:00Z"},
            "end": {"dateTime": "2026-09-09T10:30:00-07:00"},
        },
    }


def reject(value: Any, code: str | None = None) -> None:
    with pytest.raises(BrokerError) as error:
        calendar_request(value)
    assert error.value.status == 400
    if code is not None:
        assert error.value.code == code


def test_calendar_request_matches_documented_primary_event_shape() -> None:
    data = proposal()
    data["event"]["description"] = "Approved agenda\nSecond item."
    original = deepcopy(data)
    request = calendar_request(data)
    assert GOOGLE_ORIGIN == "https://www.googleapis.com"
    assert request == {
        "method": "POST",
        "path": "/calendar/v3/calendars/primary/events",
        "query": {"sendUpdates": "none"},
        "json": original["event"],
    }
    assert data == original
    data["event"]["start"]["dateTime"] = "2026-09-10T00:00:00Z"
    data["event"]["summary"] = "Changed after approval"
    data["event"]["description"] = "Changed agenda"
    assert request["json"] == original["event"]
    request["json"]["end"]["dateTime"] = "2026-09-11T00:00:00Z"
    assert data["event"]["end"] == original["event"]["end"]


@pytest.mark.parametrize("field", ["calendar_id", "send_updates", "event"])
def test_calendar_requires_every_top_level_field(field: str) -> None:
    data = proposal()
    del data[field]
    reject(data, "calendar_invalid_request")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("calendar_id", "someone@example.test"),
        ("calendar_id", "Primary"),
        ("calendar_id", "primary/../secondary"),
        ("calendar_id", None),
        ("send_updates", "all"),
        ("send_updates", "externalOnly"),
        ("send_updates", False),
    ],
)
def test_calendar_cannot_change_calendar_or_notifications(field: str, value: Any) -> None:
    data = proposal()
    data[field] = value
    reject(data, "calendar_profile_denied")


@pytest.mark.parametrize("field", ["origin", "method", "path", "query", "headers", "tenant"])
def test_calendar_cannot_add_a_different_request_lane(field: str) -> None:
    data = proposal()
    data[field] = "unapproved"
    reject(data, "calendar_invalid_request")


@pytest.mark.parametrize("field", ["id", "summary", "start", "end"])
def test_calendar_requires_each_event_field(field: str) -> None:
    data = proposal()
    del data["event"][field]
    reject(data, "calendar_invalid_event")


@pytest.mark.parametrize(
    "field",
    [
        "attendees",
        "recurrence",
        "attachments",
        "conferenceData",
        "reminders",
        "extendedProperties",
        "guestsCanModify",
        "location",
        "iCalUID",
        "eventType",
    ],
)
def test_calendar_rejects_unapproved_event_capabilities(field: str) -> None:
    data = proposal()
    data["event"][field] = {}
    reject(data, "calendar_invalid_event")


@pytest.mark.parametrize("value", [None, {}, [], "abcd", "w2345", "ABCDE", "ab-cd", "a" * 129])
def test_calendar_event_id_is_explicit_and_constrained(value: Any) -> None:
    data = proposal()
    data["event"]["id"] = value
    reject(data, "calendar_invalid_event_id")


@pytest.mark.parametrize("value", ["", " \t\n", "a" * 201, None, [], "bad\ud800"])
def test_calendar_summary_is_bounded_unicode_text(value: Any) -> None:
    data = proposal()
    data["event"]["summary"] = value
    reject(data, "calendar_invalid_summary")


@pytest.mark.parametrize("value", ["a" * 2001, None, {}, "bad\udfff"])
def test_calendar_description_is_bounded_unicode_text(value: Any) -> None:
    data = proposal()
    data["event"]["description"] = value
    reject(data, "calendar_invalid_description")


def test_calendar_preserves_unicode_names_and_boundary_lengths() -> None:
    data = proposal()
    data["event"]["id"] = "v" * 128
    data["event"]["summary"] = "会" * 200
    data["event"]["description"] = "é" * 2000
    assert calendar_request(data)["json"] == data["event"]
    data["event"]["id"] = "012av"
    data["event"]["description"] = ""
    assert calendar_request(data)["json"] == data["event"]


@pytest.mark.parametrize("field", ["start", "end"])
@pytest.mark.parametrize(
    "value",
    [
        None,
        "2026-09-09T17:00:00Z",
        {"date": "2026-09-09"},
        {"dateTime": "2026-09-09T17:00:00Z", "timeZone": "America/Los_Angeles"},
        {"dateTime": "2026-09-09T17:00:00Z", "attendees": []},
        {"dateTime": None},
        {"dateTime": "2026-09-09T17:00:00"},
        {"dateTime": "2026-09-09 17:00:00Z"},
        {"dateTime": "2026-09-09T17:00:00-00:00"},
        {"dateTime": "2026-09-09T17:00:00+24:00"},
        {"dateTime": "2026-09-09T17:00:00+00:60"},
        {"dateTime": "2026-09-09T17:00:60Z"},
        {"dateTime": "2026-02-30T17:00:00Z"},
        {"dateTime": "2026-09-09T17:00:00.1234567Z"},
    ],
)
def test_calendar_requires_exact_known_offset_datetime(field: str, value: Any) -> None:
    data = proposal()
    data["event"][field] = value
    reject(data, "calendar_invalid_datetime")


@pytest.mark.parametrize(
    "end", ["2026-09-09T17:00:00Z", "2026-09-09T10:00:00-07:00", "2026-09-09T17:30:00+01:00"]
)
def test_calendar_end_must_follow_start_as_an_instant(end: str) -> None:
    data = proposal()
    data["event"]["end"]["dateTime"] = end
    reject(data, "calendar_invalid_time_range")


def test_calendar_subsecond_interval_preserves_approved_bytes() -> None:
    data = proposal()
    data["event"]["start"]["dateTime"] = "2026-09-09T17:00:00.000001+00:00"
    data["event"]["end"]["dateTime"] = "2026-09-09T17:00:00.000002Z"
    assert calendar_request(data)["json"] == data["event"]


@pytest.mark.parametrize("data", [None, [], "private-data"])
def test_calendar_nonobject_input_is_sanitized(data: Any) -> None:
    reject(data, "calendar_invalid_request")


def test_calendar_error_never_contains_supplied_data() -> None:
    data = proposal()
    sentinel = "sensitive-synthetic-value-must-not-enter-errors"
    data["event"]["id"] = sentinel
    with pytest.raises(BrokerError) as error:
        calendar_request(data)
    assert sentinel not in str(error.value)
    assert sentinel not in repr(error.value)
