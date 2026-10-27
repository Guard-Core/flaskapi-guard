import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from typing import TypeGuard, TypeVar

from flask import Flask, Request, Response, g
from flask.sansio.blueprints import Blueprint
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync import apply_security_headers_settings
from guard_core.sync._utils.app_scope import hold_app_scope, release_app_scope
from guard_core.sync._utils.sampling import observe_sampled_key
from guard_core.sync.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.sync.core.bypass import BypassContext, BypassHandler
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.checks.route_prefixes import template_route_prefix
from guard_core.sync.core.events import MetricsCollector, SecurityEventBus
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.sync.core.routing import RouteConfigResolver, RoutingContext
from guard_core.sync.core.validation import RequestValidator, ValidationContext
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.cors_handler import (
    CorsHandler,
    CorsPreflightResponse,
    is_preflight,
)
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.agent_protocol import (
    JsonValue,
    SyncAgentHandlerProtocol,
)
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip, setup_custom_logging
from werkzeug.exceptions import HTTPException
from werkzeug.security import safe_join

from flaskapi_guard.adapters import (
    FlaskGuardRequest,
    FlaskGuardResponse,
    FlaskResponseFactory,
    set_cors_headers,
    unwrap_response,
)

_T = TypeVar("_T")


def _config_and_logger_resolved(
    guard: "FlaskAPIGuard",
) -> TypeGuard[SyncGuardMiddlewareProtocol]:
    # the middleware protocol wants a config and a logger, the extension holds
    # them as None until init_app resolves them: that is the only mismatch
    return guard.config is not None and guard.logger is not None


def _present(value: _T | None, name: str) -> _T:
    if value is None:
        raise RuntimeError(f"{name} is not initialized")
    return value


def _path_params(values: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((name, str(value)) for name, value in values.items()))


_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS = 60
_INIT_OUTAGE_SAMPLE_KEY = "redis_unavailable_during_initialization"
_init_outage_lock = threading.Lock()
_init_outage_samples: OrderedDict[str, float] = OrderedDict()


def _sample_init_outage_line() -> bool:
    return observe_sampled_key(
        _init_outage_samples,
        _init_outage_lock,
        _INIT_OUTAGE_SAMPLE_KEY,
        window=_INIT_OUTAGE_SAMPLE_WINDOW_SECONDS,
        max_tracked=1,
    )


class FlaskAPIGuard:
    def __init__(
        self,
        app: Flask | None = None,
        *,
        config: "SecurityConfig[SyncGuardRequest] | None" = None,
    ) -> None:
        self.config: SecurityConfig[SyncGuardRequest] | None = config
        self.logger: logging.Logger | None = None
        self.last_cloud_ip_refresh: int = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup: float = 0
        self.rate_limit_handler: RateLimitManager | None = None
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler: SyncGeoIPHandler | None = None
        self.redis_handler: SyncRedisHandlerProtocol | None = None
        self.agent_handler: SyncAgentHandlerProtocol | None = None
        self.security_pipeline: SecurityCheckPipeline | None = None
        self.event_bus: SecurityEventBus | None = None
        self.metrics_collector: MetricsCollector | None = None
        self.handler_initializer: HandlerInitializer | None = None
        self.response_factory: ErrorResponseFactory | None = None
        self.route_resolver: RouteConfigResolver | None = None
        self.validator: RequestValidator | None = None
        self.bypass_handler: BypassHandler | None = None
        self.behavioral_processor: BehavioralProcessor | None = None
        self._global_throttle_rules = False
        self._cors_handler: CorsHandler | None = None
        self._app: Flask | None = None
        self._initialized: bool = False
        self._guard_response_factory = FlaskResponseFactory()

        if app is not None:
            self.init_app(app, config=config)

    def _resolve_config(
        self, config: "SecurityConfig[SyncGuardRequest] | None"
    ) -> None:
        if config is not None:
            self.config = config
        elif self.config is None:
            raise ValueError("SecurityConfig must be provided")

    def _init_geo_ip_handler(self) -> None:
        config = _present(self.config, "config")
        configured = config.geo_ip_handler
        if configured is not None and not isinstance(configured, SyncGeoIPHandler):
            raise TypeError(
                f"geo_ip_handler must be a geo handler, got {type(configured).__name__}"
            )
        self.geo_ip_handler = configured

    def _init_redis_handler(self) -> None:
        config = _present(self.config, "config")
        self.redis_handler = None
        if config.enable_redis:
            from guard_core.sync.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

    def _init_agent_handler(self) -> None:
        config = _present(self.config, "config")
        logger = _present(self.logger, "logger")
        self.agent_handler = None
        if not config.enable_agent:
            return

        agent_config = config.to_agent_config()
        if not agent_config:
            logger.warning(
                "Agent enabled but configuration is invalid. "
                "Check agent_api_key and other required fields."
            )
            return

        try:
            from guard_agent import SyncGuardAgentHandler

            self.agent_handler = SyncGuardAgentHandler(agent_config)
            logger.info("Guard Agent initialized successfully")
        except ImportError:
            logger.warning(
                "Agent enabled but guard_agent package not installed. "
                "Install with: uv add guard-agent"
            )
        except Exception as e:
            logger.error(f"Failed to initialize Guard Agent: {e}")
            logger.warning("Continuing without agent functionality")

    def _init_core_components(self) -> None:
        config = _present(self.config, "config")
        _present(self.logger, "logger")

        self.handler_initializer = HandlerInitializer(
            config=config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
            adapter="flaskapi-guard",
        )
        self.geo_ip_handler = self.handler_initializer.geo_ip_handler

    def _init_route_resolver(self) -> None:
        config = _present(self.config, "config")
        logger = _present(self.logger, "logger")

        routing_context = RoutingContext(
            config=config,
            logger=logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

    def _build_event_bus_and_contexts(self) -> None:
        config = _present(self.config, "config")
        logger = _present(self.logger, "logger")
        route_resolver = _present(self.route_resolver, "route_resolver")
        handler_initializer = _present(self.handler_initializer, "handler_initializer")

        if handler_initializer.composite_handler is not None:
            self.event_bus = handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = handler_initializer.build_metrics_collector()
        else:
            self.event_bus = SecurityEventBus(
                self.agent_handler, config, self.geo_ip_handler
            )
            self.metrics_collector = MetricsCollector(self.agent_handler, config)

        response_context = ResponseContext(
            config=config,
            logger=logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            redis_handler=self.redis_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        validation_context = ValidationContext(
            config=config,
            logger=logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=config,
            logger=logger,
            event_bus=self.event_bus,
            route_resolver=route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=config,
            logger=logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
            behavior_tracker=handler_initializer.behavior_tracker,
            middleware=self,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)
        self._global_throttle_rules = any(
            rule.action == "throttle" for rule in config.global_behavior_rules
        )

    def init_app(
        self, app: Flask, config: "SecurityConfig[SyncGuardRequest] | None" = None
    ) -> None:
        self._resolve_config(config)
        resolved = _present(self.config, "config")

        self.logger = setup_custom_logging(
            resolved.custom_log_file, log_format=resolved.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(resolved)
        self._initialized = False

        self._configure_security_headers(resolved)
        self._init_geo_ip_handler()
        self._init_redis_handler()
        self._init_agent_handler()
        self._init_core_components()
        self._init_route_resolver()
        self._build_event_bus_and_contexts()

        self._app = app

        app.extensions["flaskapi_guard"] = {
            "guard": self,
            "config": resolved,
            "guard_decorator": self.guard_decorator,
        }

        self._build_security_pipeline()
        self._cors_handler = CorsHandler(resolved) if resolved.enable_cors else None

        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_request(self._teardown_request)

    def _initialize_handlers(self) -> None:
        handler_initializer = _present(self.handler_initializer, "handler_initializer")
        handler_initializer.guard_decorator = self.guard_decorator
        handler_initializer.initialize_redis_handlers()
        self.geo_ip_handler = handler_initializer.geo_ip_handler
        handler_initializer.initialize_agent_integrations()

        if handler_initializer.composite_handler is not None:
            self.agent_handler = handler_initializer.composite_handler
            self._build_event_bus_and_contexts()

    def _redis_unavailable_response(self) -> Response:
        guard_response = self.create_error_response(
            503, "Service temporarily unavailable"
        )
        guard_response.headers["Retry-After"] = "5"
        return unwrap_response(guard_response)

    def _ensure_initialized(self) -> Response | None:
        logger = _present(self.logger, "logger")
        if self._initialized:
            return None
        try:
            self._initialize_handlers()
        except GuardRedisError as e:
            if self.config is not None and self.config.passive_mode:
                if _sample_init_outage_line():
                    logger.error(
                        "Redis unavailable during initialization: %s "
                        "(passive_mode=True, request passed through unguarded)",
                        e,
                    )
                g.guard_init_passthrough = True
                return None
            logger.error("Redis unavailable during initialization: %s", e)
            return self._redis_unavailable_response()
        self._initialized = True
        return None

    def _build_security_pipeline(self) -> None:
        logger = _present(self.logger, "logger")
        from guard_core.sync.core.checks import build_default_pipeline

        middleware = self
        if not _config_and_logger_resolved(middleware):
            raise ValueError("SecurityConfig and logger must be resolved first")
        pipeline = build_default_pipeline(middleware)
        self.security_pipeline = pipeline
        logger.info(
            f"Security pipeline initialized with {len(pipeline)} checks: "
            f"{pipeline.get_check_names()}"
        )

    def _configure_security_headers(
        self, config: "SecurityConfig[SyncGuardRequest]"
    ) -> None:
        apply_security_headers_settings(security_headers_manager, config)

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        self.guard_decorator = decorator_handler
        if self.route_resolver:
            self.route_resolver.context.guard_decorator = decorator_handler
        if self.behavioral_processor:
            self.behavioral_processor.context.guard_decorator = decorator_handler
        if self.response_factory:
            self.response_factory.context.guard_decorator = decorator_handler
        if self.handler_initializer:
            self.handler_initializer.guard_decorator = decorator_handler
        if self._app is not None:
            ext = self._app.extensions.get("flaskapi_guard")
            if isinstance(ext, dict):
                ext["guard_decorator"] = decorator_handler

    @property
    def guard_response_factory(self) -> FlaskResponseFactory:
        return self._guard_response_factory

    @property
    def agent_stats(self) -> dict[str, JsonValue]:
        if self.agent_handler is None:
            return {"enabled": False}
        handler_stats = self.agent_handler.get_stats()
        return {"enabled": True, **handler_stats}

    def _execute_security_pipeline(
        self, guard_request: FlaskGuardRequest
    ) -> Response | None:
        if self.security_pipeline:
            result = self.security_pipeline.execute(guard_request)
            if result is not None:
                return unwrap_response(result)
        return None

    def _process_behavioral_usage(
        self,
        guard_request: FlaskGuardRequest,
        client_ip: str,
        route_config: RouteConfig | None,
    ) -> Response | None:
        behavioral_processor = self.behavioral_processor
        if behavioral_processor is None:
            raise RuntimeError("behavioral_processor is not initialized")
        has_route_rules = route_config is not None and bool(route_config.behavior_rules)
        if not client_ip or not (has_route_rules or self._global_throttle_rules):
            return None
        refused = behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        return None if refused is None else unwrap_response(refused)

    def _populate_guard_state(self, guard_request: FlaskGuardRequest) -> None:
        from flask import current_app, request

        if not request.endpoint:
            guard_request.state.guard_route_unresolved = True
            return
        view_func = current_app.view_functions.get(request.endpoint)
        if not view_func:
            guard_request.state.guard_route_unresolved = True
            return
        guard_request.state.guard_route_template = getattr(
            request.url_rule, "rule", None
        )
        guard_request.state.guard_endpoint_id = (
            f"{view_func.__module__}.{view_func.__qualname__}"
        )
        route_id = getattr(view_func, "_guard_route_id", None)
        if route_id is not None:
            guard_request.state.guard_route_id = route_id
        if getattr(self.security_pipeline, "needs_route_identity", False):
            guard_request.state.guard_route_identity = (
                view_func,
                _path_params(request.view_args or {}),
            )

    def resolve_route(
        self, path: str
    ) -> tuple[tuple[object, tuple[tuple[str, str], ...]], ...]:
        from flask import current_app

        url_adapter = current_app.url_map.bind("")
        identities: dict[tuple[object, tuple[tuple[str, str], ...]], None] = {}
        for method in url_adapter.allowed_methods(path):
            endpoint, args = url_adapter.match(path, method=method)
            identities[
                (current_app.view_functions.get(endpoint), _path_params(args))
            ] = None
        return tuple(identities)

    def _endpoint_and_args(self, path: str) -> tuple[str, Mapping[str, object]] | None:
        from flask import current_app, has_request_context, request

        if has_request_context() and request.endpoint and request.path == path:
            return request.endpoint, request.view_args or {}
        try:
            endpoint, args = current_app.url_map.bind("").match(path, method="GET")
        except HTTPException:
            return None
        return endpoint, args

    def static_file_exists(self, path: str) -> bool:
        from flask import current_app

        matched = self._endpoint_and_args(path)
        if matched is None:
            return False
        endpoint, args = matched
        if endpoint == "static":
            owner: Flask | Blueprint | None = current_app
        elif endpoint.endswith(".static"):
            owner = current_app.blueprints.get(endpoint.removesuffix(".static"))
        else:
            return False
        folder = getattr(owner, "static_folder", None)
        filename = args.get("filename")
        if folder is None or not isinstance(filename, str):
            return False
        served = safe_join(os.fspath(folder), filename)
        return served is not None and os.path.isfile(served)

    def allowed_methods(self, path: str) -> tuple[str, ...]:
        from flask import current_app

        return tuple(current_app.url_map.bind("").allowed_methods(path))

    def static_route_prefixes(self) -> tuple[str, ...]:
        from flask import current_app, has_app_context

        if not has_app_context():
            return ("/",)
        return tuple(
            template_route_prefix(rule.rule)
            for rule in current_app.url_map.iter_rules()
        )

    def _handle_preflight(
        self,
        guard_request: FlaskGuardRequest,
        method: str,
        request_headers: dict[str, str],
    ) -> Response | None:
        if self._cors_handler is None:
            return None
        if not is_preflight(method, request_headers):
            return None
        blocking = self._execute_security_pipeline(guard_request)
        if blocking is not None:
            return self._attach_cors_to_blocked(blocking, request_headers)
        preflight = self._cors_handler.build_preflight_response(request_headers)
        return self._build_flask_preflight_response(preflight)

    def _call_view(self, _guard_request: object) -> FlaskGuardResponse:
        from flask import current_app, request

        endpoint = request.endpoint
        if endpoint is None:
            raise RuntimeError("the request matched no endpoint")
        view = current_app.ensure_sync(current_app.view_functions[endpoint])
        rv = view(**(request.view_args or {}))
        return FlaskGuardResponse(current_app.make_response(rv))

    def _early_response(
        self, early: GuardResponse | None, request_headers: dict[str, str]
    ) -> Response | None:
        if early is None:
            return None
        return self._attach_cors_to_blocked(unwrap_response(early), request_headers)

    def _guard_request_phase(
        self,
        config: SecurityConfig[SyncGuardRequest],
        bypass_handler: BypassHandler,
        route_resolver: RouteConfigResolver,
    ) -> Response | None:
        from flask import request

        init_failure = self._ensure_initialized()
        if g.get("guard_init_passthrough", False):
            return None
        request_headers = dict(request.headers)
        if init_failure is not None:
            return self._attach_cors_to_blocked(init_failure, request_headers)

        g.request_start_time = time.time()
        guard_request = FlaskGuardRequest(request)
        self._populate_guard_state(guard_request)

        preflight_response = self._handle_preflight(
            guard_request, request.method, request_headers
        )
        if preflight_response is not None:
            return preflight_response

        early = self._early_response(
            bypass_handler.handle_passthrough(guard_request, self._call_view),
            request_headers,
        )
        if early is not None:
            return early

        client_ip = extract_client_ip(guard_request, config, self.agent_handler)
        route_config = route_resolver.get_route_config(guard_request)

        g.client_ip = client_ip
        g.route_config = route_config

        early = self._early_response(
            bypass_handler.handle_security_bypass(
                guard_request, self._call_view, route_config
            ),
            request_headers,
        )
        if early is not None:
            return early

        blocking = self._execute_security_pipeline(guard_request)
        if blocking is not None:
            return self._attach_cors_to_blocked(blocking, request_headers)

        throttled = self._process_behavioral_usage(
            guard_request, client_ip, route_config
        )
        if throttled is not None:
            return self._attach_cors_to_blocked(throttled, request_headers)
        return None

    def _before_request(self) -> Response | None:
        config = self.config
        bypass_handler = self.bypass_handler
        route_resolver = self.route_resolver
        if config is None or bypass_handler is None or route_resolver is None:
            raise RuntimeError("the extension is not initialized")
        early = self._guard_request_phase(config, bypass_handler, route_resolver)
        # After the phase: the app's scope exists once its lazy init has run.
        g.guard_app_scope_token = hold_app_scope(config)
        if early is None and not g.get("guard_init_passthrough", False):
            g.guard_response_pass = True
        return early

    def _teardown_request(self, error: BaseException | None = None) -> None:
        release_app_scope(g.pop("guard_app_scope_token", None))

    def _after_request(self, response: Response) -> Response:
        response_factory = self.response_factory
        if response_factory is None:
            raise RuntimeError("response_factory is not initialized")
        behavioral_processor = self.behavioral_processor
        if behavioral_processor is None:
            raise RuntimeError("behavioral_processor is not initialized")
        from flask import request

        if not getattr(g, "guard_response_pass", False):
            return response

        start_time = getattr(g, "request_start_time", time.time())
        response_time = time.time() - start_time
        route_config = getattr(g, "route_config", None)

        guard_request = FlaskGuardRequest(request)
        guard_response = FlaskGuardResponse(response)
        result = response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=behavioral_processor.process_return_rules,
            process_global_behavioral_rules=(
                behavioral_processor.process_global_return_rules
            ),
        )
        flask_response = unwrap_response(result)

        if self._cors_handler is not None:
            set_cors_headers(
                flask_response,
                self._cors_handler.build_response_headers(dict(request.headers)),
            )

        return flask_response

    def _attach_cors_to_blocked(
        self, response: Response, request_headers: dict[str, str]
    ) -> Response:
        if self._cors_handler is not None:
            set_cors_headers(
                response, self._cors_handler.build_response_headers(request_headers)
            )
        return response

    def _build_flask_preflight_response(
        self, preflight: CorsPreflightResponse
    ) -> Response:
        flask_response = Response(
            preflight.body,
            status=preflight.status_code,
        )
        for k, v in preflight.headers.items():
            flask_response.headers[k] = v
        return flask_response

    def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        validator = self.validator
        if validator is None:
            raise RuntimeError("validator is not initialized")
        result: bool = validator.check_time_window(time_restrictions)
        return result

    def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.sync.core.checks.helpers import check_route_ip_access

        result: bool | None = check_route_ip_access(client_ip, route_config, self)
        return result

    def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.sync.core.checks.helpers import check_user_agent_allowed

        if self.config is None:
            raise ValueError("SecurityConfig must be provided")
        result: bool = check_user_agent_allowed(user_agent, route_config, self.config)
        return result

    def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> Response | None:
        behavioral_processor = self.behavioral_processor
        if behavioral_processor is None:
            raise RuntimeError("behavioral_processor is not initialized")
        guard_request = FlaskGuardRequest(request)
        refused = behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )
        return None if refused is None else unwrap_response(refused)

    def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        behavioral_processor = self.behavioral_processor
        if behavioral_processor is None:
            raise RuntimeError("behavioral_processor is not initialized")
        guard_request = FlaskGuardRequest(request)
        guard_response = FlaskGuardResponse(response)
        behavioral_processor.process_return_rules(
            guard_request, guard_response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Request) -> str:
        behavioral_processor = self.behavioral_processor
        if behavioral_processor is None:
            raise RuntimeError("behavioral_processor is not initialized")
        guard_request = FlaskGuardRequest(request)
        result: str = behavioral_processor.get_endpoint_id(guard_request)
        return result

    def refresh_cloud_ip_ranges(self) -> None:
        config = self.config
        if config is None:
            raise RuntimeError("config is not initialized")

        if not config.block_cloud_providers:
            return

        providers: set[str] = {
            str(provider) for provider in config.block_cloud_providers
        }
        cloud_handler_for(config).refresh_async(providers)
        self.last_cloud_ip_refresh = int(time.time())

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        response_factory = self.response_factory
        if response_factory is None:
            raise RuntimeError("response_factory is not initialized")
        result: GuardResponse = response_factory.create_error_response(
            status_code, default_message
        )
        return result

    def reset(self) -> None:
        rate_limit_handler = _present(self.rate_limit_handler, "rate_limit_handler")
        rate_limit_handler.reset()
