"""Boundary audit (portmark-boundary-audit.md, main a8c8043) RC-02: timed-out thread-path tools are visible.

The thread path cannot stop a tool once it runs. After the deadline Portmark records a timeout, but the
thread keeps running and can still perform an effect. The gauge portmark_tool_threads_overdue counts those
threads until they finish, so an operator can see that one exists (owner decision 2A: the gauge now; the
default execution path is not changed).
"""

import queue
import threading
import time
import unittest
from unittest.mock import patch

from portmark.factory import make_host
from portmark.metrics import RuntimeMetrics
from portmark.models import Permit, ResourceBudget, ToolGrant
from portmark.tools import ToolExecutionError, ToolRegistry

HOST = "host:local-demo"


def _permit(name):
    return Permit(
        issuer="user:operator", subject="agent:demo", audience=HOST, expires_at=int(time.time()) + 3600,
        nonce=f"gauge-{time.monotonic_ns()}", grants=(ToolGrant(name, {}),),
        budget=ResourceBudget(max_steps=4, max_tool_calls=4, max_output_bytes=4096),
    )


def _wait_for(predicate, seconds=10.0):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


class OverdueThreadGaugeTests(unittest.TestCase):
    def setUp(self):
        self.release = threading.Event()
        self.addCleanup(self.release.set)  # never leave a test thread blocked
        self.registry = ToolRegistry()
        self.registry.register("slow.tool", lambda arguments: self.release.wait(30) and {"ok": True}, timeout=0.05)
        self.registry.register("fast.tool", lambda arguments: {"ok": True}, timeout=5)

    def test_a_timed_out_thread_is_counted_until_it_finishes(self):
        self.assertEqual(self.registry.overdue_threads(), 0)
        with self.assertRaisesRegex(ToolExecutionError, "exceeded its deadline"):
            self.registry.invoke(_permit("slow.tool"), "slow.tool", {})
        self.assertEqual(self.registry.overdue_threads(), 1)  # still running after the timeout
        self.release.set()
        self.assertTrue(_wait_for(lambda: self.registry.overdue_threads() == 0), "the finished thread stayed counted")

    def test_a_thread_that_finishes_as_the_deadline_fires_is_not_counted(self):
        # The race: the deadline fires, but the thread finishes before the timeout is recorded. It must
        # not be counted, or it would stay counted forever (its own finish already happened).
        original_get = queue.Queue.get

        def late_timeout(self_queue, *args, **kwargs):
            time.sleep(0.3)  # the fast tool finishes (and runs its finally) during this wait
            raise queue.Empty

        with patch.object(queue.Queue, "get", late_timeout):
            with self.assertRaisesRegex(ToolExecutionError, "exceeded its deadline"):
                self.registry.invoke(_permit("fast.tool"), "fast.tool", {})
        self.assertIs(queue.Queue.get, original_get)
        self.assertEqual(self.registry.overdue_threads(), 0)

    def test_a_tool_that_finishes_in_time_is_never_counted(self):
        self.assertEqual(self.registry.invoke(_permit("fast.tool"), "fast.tool", {}), {"ok": True})
        self.assertEqual(self.registry.overdue_threads(), 0)

    def test_the_scrape_reports_the_gauge(self):
        host = make_host(tools=self.registry)
        with self.assertRaises(ToolExecutionError):
            self.registry.invoke(_permit("slow.tool"), "slow.tool", {})
        host.refresh_capacity_metrics()
        self.assertIn("portmark_tool_threads_overdue 1", host.metrics.prometheus_text())
        self.release.set()
        self.assertTrue(_wait_for(lambda: self.registry.overdue_threads() == 0))
        host.refresh_capacity_metrics()
        self.assertIn("portmark_tool_threads_overdue 0", host.metrics.prometheus_text())


class GaugeNameTests(unittest.TestCase):
    def test_only_fixed_gauge_names_are_accepted(self):
        metrics = RuntimeMetrics()
        with self.assertRaisesRegex(ValueError, "unknown gauge"):
            metrics.set_gauge("anything_else", 1)
        metrics.set_gauge("tool_threads_overdue", 2)
        text = metrics.prometheus_text()
        self.assertIn("# TYPE portmark_tool_threads_overdue gauge", text)
        self.assertIn("portmark_tool_threads_overdue 2", text)


if __name__ == "__main__":
    unittest.main()
