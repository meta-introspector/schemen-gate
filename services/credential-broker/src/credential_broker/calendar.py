"""A deliberately small Google Calendar event profile for exact request approval.

This constructs a request; it does not grant authority or obtain an OAuth token.
The approving gate must bind the complete returned request to the connection.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .models import BrokerError

GOOGLE_ORIGIN = "https://www.googleapis.com"

_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _event_time(value: object) -> tuple[dict[str, str], datetime]:
    if not isinstance(value, dict) or set(value) != {"dateTime"}:
        raise BrokerError(400, "calendar_invalid_datetime")
    text = value["dateTime"]
    if not isinstance(text, str) or _DATETIME.fullmatch(text) is None or text.endswith("-00:00"):
        raise BrokerError(400, "calendar_invalid_datetime")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise BrokerError(400, "calendar_invalid_datetime") from None
    return {"dateTime": text}, parsed


def _text(value: object, maximum: int, code: str, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise BrokerError(400, code)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise BrokerError(400, code) from None
    return value


def calendar_request(data: dict[str, Any]) -> dict[str, Any]:
    """Validate one primary-calendar event and return its complete HTTP request.

    Times use uppercase RFC3339 date-times with a known UTC offset, no leap
    seconds, and at most six fractional digits. The original strings are kept
    for exact approval. Attendees, recurrence, and notification changes are
    outside this profile. The explicit event ID remains available to reconcile
    ambiguous provider outcomes; it is not an exactly-once execution guarantee.
    """
    if not isinstance(data, dict) or set(data) != {"calendar_id", "event", "send_updates"}:
        raise BrokerError(400, "calendar_invalid_request")
    if data["calendar_id"] != "primary" or data["send_updates"] != "none":
        raise BrokerError(400, "calendar_profile_denied")
    event = data["event"]
    required = {"id", "summary", "start", "end"}
    if (
        not isinstance(event, dict)
        or not required.issubset(event)
        or set(event) - required - {"description"}
    ):
        raise BrokerError(400, "calendar_invalid_event")
    event_id = event["id"]
    if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-v]{5,128}", event_id) is None:
        raise BrokerError(400, "calendar_invalid_event_id")
    summary = _text(event["summary"], 200, "calendar_invalid_summary", required=True)
    start, start_at = _event_time(event["start"])
    end, end_at = _event_time(event["end"])
    if end_at <= start_at:
        raise BrokerError(400, "calendar_invalid_time_range")
    approved: dict[str, Any] = {"id": event_id, "summary": summary, "start": start, "end": end}
    if "description" in event:
        approved["description"] = _text(event["description"], 2000, "calendar_invalid_description")
    return {
        "method": "POST",
        "path": "/calendar/v3/calendars/primary/events",
        "query": {"sendUpdates": "none"},
        "json": approved,
    }
