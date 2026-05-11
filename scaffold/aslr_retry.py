#!/usr/bin/env python3
"""ASLR-retry wrapper for unstable heap exploits.

Many heap chains succeed only when a leaked address has a specific
nibble pattern (e.g. tcache poison requires the target's last 12 bits
to match an alignable chunk → ~1/16 success rate). Reconnecting and
retrying turns those into reliable exploits.

Usage:

    from scaffold.aslr_retry import aslr_retry
    from pwn import process, remote, context

    def exploit_one():
        # Open a fresh tube each attempt.
        p = remote(host, port) if remote_mode else process("./prob")
        try:
            # ... do exploit ...
            p.sendline(b"cat /flag*")
            data = p.recvrepeat(2.0)
            if b"FLAG{" in data or b"flag{" in data:
                return data.decode(errors="replace")
            return None
        finally:
            p.close()

    flag = aslr_retry(exploit_one, max_attempts=64)
    if flag:
        print(flag)
"""
from __future__ import annotations

import sys
import time
from typing import Callable, Any


def aslr_retry(
    exploit_one: Callable[[], Any],
    *,
    max_attempts: int = 64,
    sleep_s: float = 0.0,
    log: Callable[[str], None] | None = None,
    raise_on_giveup: bool = False,
) -> Any:
    """Call `exploit_one()` up to `max_attempts` times.

    `exploit_one()` MUST:
      - open and close its own tube each invocation (do NOT reuse a
        tube across attempts; the remote service almost certainly
        closed it after the crash)
      - return a truthy value on success (typically the flag string)
      - return a falsy value or raise on failure

    Returns the first truthy result, or None when all attempts fail
    (unless `raise_on_giveup=True`, in which case it raises
    `RuntimeError`).
    """
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    for attempt in range(1, max_attempts + 1):
        try:
            result = exploit_one()
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            log(f"[aslr-retry] attempt {attempt}/{max_attempts} raised: "
                f"{type(e).__name__}: {e}")
            result = None
        if result:
            log(f"[aslr-retry] success on attempt {attempt}/{max_attempts}")
            return result
        if sleep_s:
            time.sleep(sleep_s)
    msg = f"[aslr-retry] gave up after {max_attempts} attempts"
    log(msg)
    if raise_on_giveup:
        raise RuntimeError(msg)
    return None


def expected_attempts_for(success_rate: float) -> int:
    """How many attempts to allocate so the cumulative success
    probability is ≥ 0.99. Useful for nibble-race chains:

        expected_attempts_for(1 / 16)   # → ~72
        expected_attempts_for(1 / 256)  # → ~1175

    The orchestrator's runner sandbox times out at 300s by default, so
    cap your attempts at a number that fits in your per-attempt
    runtime budget.
    """
    import math
    if success_rate <= 0 or success_rate >= 1:
        return 1
    # P(no success in N) = (1 - p)^N. Solve for P ≤ 0.01.
    return max(1, int(math.ceil(math.log(0.01) / math.log(1 - success_rate))))
