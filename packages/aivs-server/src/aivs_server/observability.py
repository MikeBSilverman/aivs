"""Every background component reports whether it is running, the same way.

Nothing here may fail silently (plan, exit criterion 5). A loop that dies, or
that runs and fails every time, used to be visible only as an exception in a
log nobody was reading -- the embargo sweeper, the notification dispatcher and
now the detection rules all run unattended. Each registers here with how often
it should succeed; ``/readyz``, ``/metrics``, the admin status page and the
``component_degraded`` detection all read the same registry, so they cannot
disagree about whether something is healthy.

In-process by design: one application process runs these loops. A second
process would need its own registry and its own scrape target.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Literal

__all__ = ["HEARTBEATS", "ComponentReport", "Heartbeats", "render_metrics", "run_periodically"]

logger = logging.getLogger(__name__)

State = Literal["ok", "starting", "degraded"]

#: A component is degraded once this many of its intervals pass without a success.
_GRACE_INTERVALS: Final[int] = 2


@dataclass(slots=True)
class _Component:
    interval: dt.timedelta
    registered_at: dt.datetime
    last_success_at: dt.datetime | None = None
    last_failure_at: dt.datetime | None = None
    last_error: str | None = None
    successes: int = 0
    failures: int = 0


@dataclass(frozen=True, slots=True)
class ComponentReport:
    name: str
    state: State
    reason: str
    last_success_at: dt.datetime | None
    successes: int
    failures: int


class Heartbeats:
    """The registry. Holds no content: names, times, counts and error *types*."""

    def __init__(self) -> None:
        self._components: dict[str, _Component] = {}

    def register(self, name: str, interval: dt.timedelta, *, now: dt.datetime) -> None:
        self._components[name] = _Component(interval=interval, registered_at=now)

    def success(self, name: str, *, now: dt.datetime) -> None:
        component = self._components[name]
        component.last_success_at = now
        component.successes += 1

    def failure(self, name: str, error: BaseException, *, now: dt.datetime) -> None:
        component = self._components[name]
        component.last_failure_at = now
        # The type, never the message: messages can carry values.
        component.last_error = type(error).__name__
        component.failures += 1

    def report(self, *, now: dt.datetime) -> list[ComponentReport]:
        return [
            self._report(name, component, now)
            for name, component in sorted(self._components.items())
        ]

    def clear(self) -> None:
        """For tests: forget every component."""
        self._components.clear()

    @staticmethod
    def _report(name: str, component: _Component, now: dt.datetime) -> ComponentReport:
        grace = component.interval * _GRACE_INTERVALS
        if component.last_success_at is not None and now - component.last_success_at <= grace:
            state: State = "ok"
            reason = "ran recently"
        elif component.last_success_at is None and now - component.registered_at <= grace:
            state = "starting"
            reason = "has not run yet"
        else:
            state = "degraded"
            since = component.last_success_at or component.registered_at
            reason = f"no successful run for {int((now - since).total_seconds())}s"
            if component.last_error:
                reason += f"; last error {component.last_error}"
        return ComponentReport(
            name=name,
            state=state,
            reason=reason,
            last_success_at=component.last_success_at,
            successes=component.successes,
            failures=component.failures,
        )


#: The process's registry.
HEARTBEATS: Final[Heartbeats] = Heartbeats()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


async def run_periodically(
    name: str,
    interval: dt.timedelta,
    work: Callable[[], Awaitable[object]],
    *,
    heartbeats: Heartbeats = HEARTBEATS,
) -> None:  # pragma: no cover - the loop; its parts are tested
    """Run ``work`` every ``interval`` forever, reporting each outcome.

    A failure is logged and recorded and the loop continues: a background job
    that dies on a transient database error and never runs again is the silent
    failure this module exists to prevent.
    """
    heartbeats.register(name, interval, now=_now())
    while True:
        await asyncio.sleep(interval.total_seconds())
        try:
            await work()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            heartbeats.failure(name, exc, now=_now())
            logger.exception("%s failed; will retry on the next interval", name)
        else:
            heartbeats.success(name, now=_now())


def render_metrics(
    reports: list[ComponentReport], *, pending_deliveries: int, pending_embargoes: int
) -> str:
    """Prometheus text format, by hand: a dozen lines do not justify a dependency
    every member's third-party-risk review would ask about."""
    lines = [
        "# HELP aivs_component_up 1 when the component ran within its grace period.",
        "# TYPE aivs_component_up gauge",
    ]
    lines += [
        f'aivs_component_up{{component="{report.name}"}} {int(report.state == "ok")}'
        for report in reports
    ]
    lines += [
        "# HELP aivs_component_failures_total Failed runs since the process started.",
        "# TYPE aivs_component_failures_total counter",
    ]
    lines += [
        f'aivs_component_failures_total{{component="{report.name}"}} {report.failures}'
        for report in reports
    ]
    lines += [
        "# HELP aivs_component_last_success_timestamp_seconds Unix time of the last success.",
        "# TYPE aivs_component_last_success_timestamp_seconds gauge",
    ]
    lines += [
        f'aivs_component_last_success_timestamp_seconds{{component="{report.name}"}} '
        f"{report.last_success_at.timestamp() if report.last_success_at else 0}"
        for report in reports
    ]
    lines += [
        "# HELP aivs_webhook_deliveries_pending Notifications queued and not yet delivered.",
        "# TYPE aivs_webhook_deliveries_pending gauge",
        f"aivs_webhook_deliveries_pending {pending_deliveries}",
        "# HELP aivs_embargoes_pending Embargoes not yet released.",
        "# TYPE aivs_embargoes_pending gauge",
        f"aivs_embargoes_pending {pending_embargoes}",
    ]
    return "\n".join(lines) + "\n"
