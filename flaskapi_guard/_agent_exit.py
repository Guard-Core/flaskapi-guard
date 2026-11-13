import atexit
import logging
import threading

from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol

# How long process exit waits for an agent to flush and stop: its own stop() retries
# a refused endpoint for 14 s and a black-holed one for over a minute.
_AGENT_EXIT_WAIT_SECONDS = 5.0
_agent_exit_registered: set[int] = set()
_agent_exit_lock = threading.Lock()


def _agent_already_stopped(handler: SyncAgentHandlerProtocol) -> bool:
    """True when the handler's loop thread has ended or its loop is closed (the
    user stopped it): a second stop() would wait on a loop that never runs."""
    thread = getattr(handler, "_thread", None)
    loop = getattr(handler, "_loop", None)
    return (thread is not None and not thread.is_alive()) or (
        loop is not None and loop.is_closed()
    )


def _stop_agent_within(
    handler: SyncAgentHandlerProtocol, seconds: float, logger: logging.Logger
) -> None:
    if _agent_already_stopped(handler):
        return

    def stop() -> None:
        try:
            handler.stop()
        except Exception as error:
            logger.error("Guard Agent did not stop cleanly at exit: %s", error)

    worker = threading.Thread(target=stop, name="guard-agent-exit", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        logger.warning(
            "Guard Agent did not finish flushing within %.1f s at exit: the events "
            "it still held are dropped",
            seconds,
        )


def _stop_agent_at_exit(
    handler: SyncAgentHandlerProtocol, logger: logging.Logger
) -> None:
    """Flush and stop the agent once at process exit, waiting at most
    `_AGENT_EXIT_WAIT_SECONDS`. Registered once per handler."""
    with _agent_exit_lock:
        if id(handler) in _agent_exit_registered:
            return
        _agent_exit_registered.add(id(handler))
    atexit.register(_stop_agent_within, handler, _AGENT_EXIT_WAIT_SECONDS, logger)
