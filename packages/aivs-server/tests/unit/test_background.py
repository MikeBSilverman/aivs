"""Every unattended job is started, registered, and survives its own failure.

The heartbeat tests registered names by hand, so deleting a job from the
lifespan, or the loop's exception branch, left the suite green (Phase A
review). These read the real list and run the real loop.
"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from aivs_server.main import background_components
from aivs_server.observability import Heartbeats, run_periodically


def test_the_process_runs_its_unattended_jobs_at_their_configured_intervals(settings):
    components = {c.name: c.interval for c in background_components(settings)}

    assert components == {
        "embargo_sweeper": dt.timedelta(seconds=settings.embargo_sweep_interval_seconds),
        "webhook_dispatcher": dt.timedelta(seconds=settings.webhook_dispatch_interval_seconds),
        "detections": dt.timedelta(seconds=settings.detection_interval_seconds),
        "published_counts": dt.timedelta(seconds=settings.count_publish_interval_seconds),
        "notification_digest": dt.timedelta(seconds=settings.digest_interval_seconds),
        "email_dispatcher": dt.timedelta(seconds=settings.email_dispatch_interval_seconds),
        "audit_read_summary": dt.timedelta(seconds=settings.audit_read_summary_interval_seconds),
    }


@pytest.mark.requirement("NFR-A3")
async def test_a_failing_run_is_recorded_and_the_loop_keeps_going():
    beats = Heartbeats()
    calls = 0

    async def flaky() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "transient"
            raise TimeoutError(msg)

    task = asyncio.create_task(
        run_periodically("flaky", dt.timedelta(milliseconds=10), flaky, heartbeats=beats)
    )
    try:
        for _ in range(100):
            await asyncio.sleep(0.01)
            [report] = beats.report(now=dt.datetime.now(dt.UTC))
            if report.successes:
                break
    finally:
        task.cancel()

    assert report.failures == 1
    assert report.successes >= 1, "a failure must not end the loop"
    assert report.state == "ok"
