from guard_agent import SyncGuardAgentHandler


def close_the_agent_event_loop() -> None:
    """Stop and close the loop of the sync agent handler singleton, and forget it.

    The handler runs a loop thread that stop() ends without closing the loop; an
    unclosed loop fails whichever test the garbage collector finalizes it in under
    -W error."""
    handler = SyncGuardAgentHandler._instance
    if handler is None:
        return
    loop = handler._loop
    if loop.is_running():
        loop.call_soon_threadsafe(loop.stop)
        handler._thread.join(timeout=5)
    if not loop.is_running() and not loop.is_closed():
        loop.close()
    SyncGuardAgentHandler._instance = None
