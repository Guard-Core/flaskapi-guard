import io
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import IO, Protocol

from flask import Request, Response
from flask.ctx import _AppCtxGlobals
from guard_core.exceptions import BodyReadStalledError
from guard_core.protocols.request_protocol import GuardRequestHeaders
from guard_core.protocols.response_protocol import GuardResponse, GuardResponseHeaders
from werkzeug.exceptions import RequestEntityTooLarge

_READ_CHUNK_BYTES = 65536
_SERVER_SOCKET_KEYS = ("werkzeug.socket", "gunicorn.socket")


def _empty_when_oversize(read: Callable[[], bytes]) -> bytes:
    # MAX_CONTENT_LENGTH is Flask's to enforce: the view's own read answers 413.
    try:
        return read()
    except RequestEntityTooLarge:
        return b""


def _caused_by_timeout(error: BaseException | None) -> bool:
    seen: set[int] = set()
    while error is not None and id(error) not in seen:
        if isinstance(error, TimeoutError):
            return True
        seen.add(id(error))
        error = error.__cause__ or error.__context__
    return False


class _TimeoutSocket(Protocol):
    def gettimeout(self) -> float | None: ...

    def settimeout(self, value: float | None, /) -> None: ...


class _ReplayStream:
    def __init__(self, prefix: bytes, rest: IO[bytes]) -> None:
        self._prefix = io.BytesIO(prefix)
        self._rest = rest

    def read(self, size: int = -1) -> bytes:
        head = self._prefix.read(size)
        if size is None or size < 0:
            return head + self._rest.read()
        if len(head) == size:
            return head
        return head + self._rest.read(size - len(head))

    def readline(self, size: int = -1) -> bytes:
        head = self._prefix.readline(size)
        if head.endswith(b"\n") or (size is not None and 0 <= size <= len(head)):
            return head
        remaining = -1 if size is None or size < 0 else size - len(head)
        return head + self._rest.readline(remaining)

    def readlines(self) -> list[bytes]:
        return list(self)

    def __iter__(self) -> Iterator[bytes]:
        while line := self.readline():
            yield line


@contextmanager
def _idle_socket_timeout(
    environ: Mapping[str, _TimeoutSocket], idle_timeout: float
) -> Iterator[None]:
    server_socket = next(
        (environ[key] for key in _SERVER_SOCKET_KEYS if key in environ), None
    )
    if server_socket is None:
        yield
        return
    previous = server_socket.gettimeout()
    server_socket.settimeout(idle_timeout)
    try:
        yield
    finally:
        server_socket.settimeout(previous)


class FlaskGuardRequest:
    def __init__(self, request: Request) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        result: str = self._request.path
        return result

    @property
    def url_scheme(self) -> str:
        result: str = self._request.scheme
        return result

    @property
    def url_full(self) -> str:
        result: str = self._request.url
        return result

    def url_replace_scheme(self, scheme: str) -> str:
        url: str = self._request.url
        if url.startswith("http://"):
            return scheme + "://" + url[7:]
        if url.startswith("https://"):
            return scheme + "://" + url[8:]
        return url

    @property
    def method(self) -> str:
        result: str = self._request.method
        return result

    @property
    def client_host(self) -> str | None:
        result: str | None = self._request.remote_addr
        return result

    @property
    def headers(self) -> GuardRequestHeaders:
        return self._request.headers

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.args

    def body(self) -> bytes:
        return _empty_when_oversize(self._request.get_data)

    def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        return _empty_when_oversize(lambda: self._request.get_data()[:max_bytes])

    def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        return _empty_when_oversize(
            lambda: self._read_prefix_until_idle(max_bytes, idle_timeout)
        )

    def _read_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        if max_bytes <= 0:
            return b""
        cached = getattr(self._request, "_cached_data", None)
        if isinstance(cached, bytes):
            return cached[:max_bytes]
        stream = self._request.stream
        chunks: list[bytes] = []
        received = 0
        try:
            with _idle_socket_timeout(self._request.environ, idle_timeout):
                while received < max_bytes:
                    piece = stream.read(min(_READ_CHUNK_BYTES, max_bytes - received))
                    if not piece:
                        break
                    chunks.append(piece)
                    received += len(piece)
        except Exception as exc:
            if _caused_by_timeout(exc):
                raise BodyReadStalledError() from exc
            raise
        finally:
            prefix = b"".join(chunks)
            self._restore_consumed_prefix(prefix, stream)
        return prefix

    def _restore_consumed_prefix(self, prefix: bytes, stream: IO[bytes]) -> None:
        environ = self._request.environ
        environ["wsgi.input"] = _ReplayStream(prefix, environ["wsgi.input"])
        self._request.__dict__["stream"] = _ReplayStream(prefix, stream)

    @property
    def state(self) -> _AppCtxGlobals:
        from flask import g

        return g

    @property
    def scope(self) -> dict[str, object]:
        return {"environ": self._request.environ}


class StreamedBodyUnavailable(AttributeError):
    pass


class _TeedResponseBody:
    def __init__(self, original: object, source: Iterator[bytes], head: list[bytes]):
        self._original = original
        self._source = source
        self.head = head

    def read_until(self, wanted: int) -> None:
        received = sum(map(len, self.head))
        if received >= wanted:
            return
        for chunk in self._source:
            self.head.append(chunk)
            received += len(chunk)
            if received >= wanted:
                return

    def __iter__(self) -> Iterator[bytes]:
        while self.head:
            yield self.head.pop(0)
        yield from self._source

    def close(self) -> None:
        close = getattr(self._original, "close", None)
        if close is not None:
            close()


class FlaskGuardResponse:
    body_is_materialized: bool

    def __init__(self, response: Response) -> None:
        self._response = response
        # read here, before anything calls .data or get_data(): they buffer a
        # generator body and flip is_streamed
        self.body_is_materialized = not response.is_streamed

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> GuardResponseHeaders:
        return self._response.headers

    @property
    def body(self) -> bytes | None:
        if self._response.is_streamed:
            raise StreamedBodyUnavailable(
                "the response is streamed; read a bounded prefix with "
                "read_body_prefix instead of buffering the whole body"
            )
        return self._response.get_data()

    def read_body_prefix(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        if not self._response.is_streamed:
            result: bytes = self._response.get_data()[:max_bytes]
            return result
        return self._streamed_prefix(max_bytes)

    def _streamed_prefix(self, max_bytes: int) -> bytes:
        teed = self._response.response
        if not isinstance(teed, _TeedResponseBody):
            teed = _TeedResponseBody(teed, self._response.iter_encoded(), [])
            self._response.response = teed
        # a declared length within the cap is read to its end; any other stream
        # stops at the first non-empty chunk, so an endless stream never stalls
        declared = self._response.content_length
        teed.read_until(
            declared if declared is not None and declared <= max_bytes else 1
        )
        return b"".join(teed.head)[:max_bytes]


class FlaskResponseFactory:
    def create_response(self, content: str, status_code: int) -> FlaskGuardResponse:
        return FlaskGuardResponse(
            Response(content, status=status_code, mimetype="text/plain")
        )

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> FlaskGuardResponse:
        from flask import redirect

        redirected = redirect(url, code=status_code)
        if isinstance(redirected, Response):
            return FlaskGuardResponse(redirected)
        # flask.redirect returns Werkzeug's own Response outside an app context
        return FlaskGuardResponse(
            Response(
                redirected.response,
                status=redirected.status_code,
                headers=redirected.headers,
            )
        )


def unwrap_response(guard_response: GuardResponse) -> Response:
    if isinstance(guard_response, FlaskGuardResponse):
        return guard_response._response
    return Response(
        guard_response.body,
        status=guard_response.status_code,
        headers=dict(guard_response.headers),
    )


def merge_vary(existing: list[str], required: str) -> str:
    present = ", ".join(value for value in existing if value.strip())
    if not present:
        return required
    tokens = {token.strip().lower() for token in present.split(",")}
    if tokens & {required.lower(), "*"}:
        return present
    return f"{present}, {required}"


def set_cors_headers(response: Response, cors_headers: Mapping[str, str]) -> None:
    for key, value in cors_headers.items():
        if key.lower() == "vary":
            value = merge_vary(response.headers.getlist("Vary"), value)
        response.headers[key] = value
