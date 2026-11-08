"""A small 5-field cron parser for server backup schedules.

``minute hour day-of-month month day-of-week`` with ``*``, ``*/n``, ``a-b``,
``a-b/n``, ``a/n`` (from a, step n), lists (``1,15,30``) and names for months
(``jan``..``dec``) and weekdays (``sun``..``sat``; ``0`` and ``7`` are Sunday).
As in Vixie cron, when both day fields are restricted a day matches if *either*
matches. Times are evaluated in an IANA time zone (default ``Asia/Tehran``);
local times that do not exist (DST gap) are skipped, repeated ones run once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TIMEZONE = "Asia/Tehran"
MAX_EXPRESSION_LENGTH = 120
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
_TIMEZONE = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$")
_SEARCH_DAYS = 366 * 5


class CronError(ValueError):
    pass


def _value(token: str, low: int, high: int, names: tuple[str, ...] | None, offset: int) -> int:
    lowered = token.lower()
    if names is not None and lowered in names:
        return names.index(lowered) + offset
    if not token.isdigit() or len(token) > 2:
        raise CronError(f"invalid value {token!r}")
    number = int(token)
    if not low <= number <= high:
        raise CronError(f"value {number} out of range {low}-{high}")
    return number


def _field(
    text: str, low: int, high: int, names: tuple[str, ...] | None = None, offset: int = 0
) -> frozenset[int]:
    values: set[int] = set()
    for part in text.split(","):
        if not part:
            raise CronError("empty list item")
        base, slash, step_text = part.partition("/")
        step = 1
        if slash:
            if not step_text.isdigit() or not 1 <= int(step_text) <= high - low + 1:
                raise CronError(f"invalid step {step_text!r}")
            step = int(step_text)
        if base == "*":
            start, end = low, high
        elif "-" in base:
            first, _, last = base.partition("-")
            start = _value(first, low, high, names, offset)
            end = _value(last, low, high, names, offset)
            if end < start:
                raise CronError(f"invalid range {base!r}")
        else:
            start = _value(base, low, high, names, offset)
            end = high if slash else start
        values.update(range(start, end + 1, step))
    return frozenset(values)


@dataclass(frozen=True, slots=True)
class CronSchedule:
    expression: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday
    day_restricted: bool
    weekday_restricted: bool

    def _day_matches(self, moment: datetime) -> bool:
        if moment.month not in self.months:
            return False
        weekday = (moment.weekday() + 1) % 7
        day_ok = moment.day in self.days
        weekday_ok = weekday in self.weekdays
        if self.day_restricted and self.weekday_restricted:
            return day_ok or weekday_ok
        return day_ok and weekday_ok

    def next_after(self, after: float, timezone: str = DEFAULT_TIMEZONE) -> float:
        """First matching time strictly after ``after`` (unix seconds)."""
        zone = load_timezone(timezone)
        start = datetime.fromtimestamp(after, UTC).astimezone(zone)
        start = start.replace(second=0, microsecond=0, tzinfo=None) + timedelta(minutes=1)
        day = start.replace(hour=0, minute=0)
        hours = sorted(self.hours)
        minutes = sorted(self.minutes)
        for _ in range(_SEARCH_DAYS):
            if self._day_matches(day):
                for hour in hours:
                    for minute in minutes:
                        local = day.replace(hour=hour, minute=minute)
                        if local < start:
                            continue
                        aware = local.replace(tzinfo=zone, fold=0)
                        # Round-trip through UTC: a local time inside a DST gap moves.
                        back = aware.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
                        if back != local:
                            continue
                        timestamp = aware.timestamp()
                        if timestamp > after:
                            return timestamp
            day += timedelta(days=1)
        raise CronError("schedule never matches")


def load_timezone(name: str) -> ZoneInfo:
    if not isinstance(name, str) or not _TIMEZONE.fullmatch(name) or ".." in name:
        raise CronError("invalid time zone")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise CronError("unknown time zone") from exc


def parse_cron(expression: object) -> CronSchedule:
    if not isinstance(expression, str) or len(expression) > MAX_EXPRESSION_LENGTH:
        raise CronError("schedule must be a 5-field cron expression")
    fields = expression.split()
    if len(fields) != 5:
        raise CronError("schedule must have exactly 5 fields")
    minute, hour, day, month, weekday = fields
    weekdays = _field(weekday, 0, 7, _DAYS)
    if 7 in weekdays:
        weekdays = (weekdays - {7}) | {0}
    schedule = CronSchedule(
        expression=" ".join(fields),
        minutes=_field(minute, 0, 59),
        hours=_field(hour, 0, 23),
        days=_field(day, 1, 31),
        months=_field(month, 1, 12, _MONTHS, offset=1),
        weekdays=frozenset(weekdays),
        day_restricted=not day.startswith("*"),
        weekday_restricted=not weekday.startswith("*"),
    )
    # Rejects impossible dates such as "0 0 31 2 *".
    schedule.next_after(0.0, "UTC")
    return schedule
