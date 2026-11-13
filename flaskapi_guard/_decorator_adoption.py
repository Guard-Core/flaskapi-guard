import weakref

from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator as CoreSecurityDecorator
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard._view_routes import route_ids_of_view

_created: list[weakref.ReferenceType[BaseSecurityDecorator]] = []


class SecurityDecorator(CoreSecurityDecorator):
    def __init__(self, config: SecurityConfig[SyncGuardRequest]) -> None:
        super().__init__(config)
        _created.append(weakref.ref(self))


def alive_decorators() -> list[BaseSecurityDecorator]:
    alive = [decorator for ref in _created if (decorator := ref()) is not None]
    _created[:] = [weakref.ref(decorator) for decorator in alive]
    return alive


def decorators_holding_routes_of(
    app: Flask, alive: list[BaseSecurityDecorator]
) -> list[BaseSecurityDecorator]:
    """A decorator built for another app (or left alive by an earlier one) is not a
    candidate: only one that holds a route id stamped on this app's views is."""
    route_ids = {
        route_id
        for view in app.view_functions.values()
        for _, route_id in route_ids_of_view(view, None)
    }
    return [
        decorator
        for decorator in alive
        if any(decorator.get_route_config(rid) is not None for rid in route_ids)
    ]


def ambiguity_message(alive: list[BaseSecurityDecorator]) -> str:
    names = ", ".join(
        f"{type(decorator).__module__}.{type(decorator).__qualname__} "
        f"at {hex(id(decorator))}"
        for decorator in alive
    )
    return (
        f"{len(alive)} SecurityDecorator instances decorate routes of this app "
        f"({names}) and FlaskAPIGuard.set_decorator_handler was not called to say "
        "which one to use, so none of their route decorators are enforced. Call "
        "set_decorator_handler with the decorator the routes use, or share one "
        "decorator instance across the app."
    )
