from __future__ import annotations

import datetime


def now():
    """A naive UTC timestamp (matches what the sqladal tables store)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
