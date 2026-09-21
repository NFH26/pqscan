"""Small networking helpers shared by every probe.

Kept in its own module rather than on the TLS collector so that tls_probe and domain_probe can
use it without importing the collector, which would be a cycle.
"""
from __future__ import annotations

import asyncio


async def close_quietly(writer: asyncio.StreamWriter | None, timeout: float = 2.0) -> None:
    """Close a stream without letting the close itself hang the scan.

    `wait_closed()` waits for the transport to finish, and against a peer that accepted the
    connection and then went silent mid-handshake it never finishes - so a tidy-up in a
    finally block becomes an unbounded hang, which is worse than the leak it was fixing. A
    hostile server test found exactly that.

    Teardown never changes what was measured, so every failure here is discarded, including
    cancellation: a close running during cancellation must not re-raise and mask the reason
    the task was cancelled in the first place.
    """
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(asyncio.shield(writer.wait_closed()), timeout)
    except (Exception, asyncio.CancelledError):
        pass
