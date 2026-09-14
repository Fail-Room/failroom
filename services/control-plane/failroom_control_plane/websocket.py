"""Bounded WebSocket authorization and terminal relay transport."""

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import uuid4

from failroom_sandbox.pty import PtyError
from failroom_sandbox.terminal_gateway import GatewayAttachment
from failroom_state import AttachmentLease
from fastapi import FastAPI, WebSocket
from starlette.websockets import WebSocketDisconnect

from .terminal import TerminalError, TerminalSession

Clock = Callable[[], datetime]


@dataclass(frozen=True)
class WebSocketLimits:
    authorization_timeout_seconds: int
    max_frame_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    max_rows: int
    max_columns: int
    poll_interval_seconds: float

    def __post_init__(self) -> None:
        if (
            type(self.authorization_timeout_seconds) is not int
            or not 1 <= self.authorization_timeout_seconds <= 30
            or type(self.max_frame_bytes) is not int
            or not 128 <= self.max_frame_bytes <= 1_048_576
            or type(self.max_input_bytes) is not int
            or not 1 <= self.max_input_bytes <= self.max_frame_bytes
            or type(self.max_output_bytes) is not int
            or not 1 <= self.max_output_bytes <= 1_048_576
            or type(self.max_rows) is not int
            or not 1 <= self.max_rows <= 500
            or type(self.max_columns) is not int
            or not 1 <= self.max_columns <= 1_000
            or type(self.poll_interval_seconds) not in (int, float)
            or not 0.001 <= self.poll_interval_seconds <= 1.0
        ):
            raise ValueError("invalid websocket limits")


@runtime_checkable
class TerminalGatewayProtocol(Protocol):
    def authorize_and_lease(
        self,
        token: str,
        *,
        gateway_session_id: str,
        idempotency_key: str,
        now: Clock,
    ) -> GatewayAttachment: ...


@runtime_checkable
class TerminalAttachmentProtocol(Protocol):
    def attach(self, lease: AttachmentLease) -> TerminalSession: ...


class _FrameError(Exception):
    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(code)


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid constant: {value}")


async def _receive_frame(websocket: WebSocket, maximum: int) -> dict[str, object]:
    message = await websocket.receive()
    if message.get("type") != "websocket.receive":
        raise WebSocketDisconnect(code=1000)
    text = message.get("text")
    if type(text) is not str:
        raise _FrameError(4400)
    if len(text.encode("utf-8")) > maximum:
        raise _FrameError(4409)
    try:
        frame = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except Exception:
        raise _FrameError(4400) from None
    if type(frame) is not dict:
        raise _FrameError(4400)
    return frame


def _exact_keys(frame: dict[str, object], *keys: str) -> bool:
    return set(frame) == set(keys)


async def serve_terminal(
    websocket: WebSocket,
    gateway: TerminalGatewayProtocol,
    terminal: TerminalAttachmentProtocol,
    limits: WebSocketLimits,
    now: Clock,
) -> None:
    """Authorize one socket and relay only bounded terminal control frames."""

    await websocket.accept()
    close_lock = asyncio.Lock()
    close_sent = False
    disconnected = False
    requested_close_code: int | None = None
    session: TerminalSession | None = None
    output_task: asyncio.Task[None] | None = None

    async def close_once(code: int) -> None:
        nonlocal close_sent
        async with close_lock:
            if close_sent:
                return
            close_sent = True
            try:
                await websocket.close(code=code)
            except (RuntimeError, WebSocketDisconnect):
                pass

    async def send_json(payload: dict[str, str]) -> None:
        async with close_lock:
            if close_sent:
                return
            await websocket.send_json(payload)

    async def relay_output() -> None:
        if session is None:
            return
        while True:
            try:
                data = await asyncio.to_thread(session.read, limits.max_output_bytes)
            except (PtyError, TerminalError, OSError):
                await close_once(1011)
                return
            except Exception:
                await close_once(1011)
                return
            if data:
                try:
                    await send_json(
                        {"type": "output", "data": data.decode("utf-8", "replace")}
                    )
                except (RuntimeError, WebSocketDisconnect):
                    return
            else:
                await asyncio.sleep(limits.poll_interval_seconds)

    try:
        try:
            frame = await asyncio.wait_for(
                _receive_frame(websocket, limits.max_frame_bytes),
                timeout=limits.authorization_timeout_seconds,
            )
        except TimeoutError:
            await close_once(4408)
            return
        except WebSocketDisconnect:
            disconnected = True
            return
        except _FrameError as error:
            await close_once(error.code)
            return

        capability = frame.get("capability")
        if (
            not _exact_keys(frame, "type", "capability")
            or frame.get("type") != "authorize"
            or type(capability) is not str
            or not capability
        ):
            await close_once(4400)
            return

        session_id = uuid4().hex
        try:
            attachment = await asyncio.to_thread(
                gateway.authorize_and_lease,
                capability,
                gateway_session_id=session_id,
                idempotency_key=session_id,
                now=now,
            )
        except Exception:
            await close_once(4403)
            return

        try:
            session = await asyncio.to_thread(terminal.attach, attachment.lease)
        except TerminalError as error:
            await close_once(4403 if error.code == "ATTACHMENT_DENIED" else 1011)
            return
        except Exception:
            await close_once(1011)
            return

        await send_json({"type": "authorized"})
        output_task = asyncio.create_task(relay_output())

        while True:
            try:
                frame = await _receive_frame(websocket, limits.max_frame_bytes)
            except WebSocketDisconnect:
                disconnected = True
                break
            except _FrameError as error:
                await close_once(error.code)
                break

            frame_type = frame.get("type")
            if frame_type == "close" and _exact_keys(frame, "type"):
                requested_close_code = 1000
                break
            if frame_type == "input" and _exact_keys(frame, "type", "data"):
                data = frame.get("data")
                if (
                    type(data) is not str
                    or len(data.encode("utf-8")) > limits.max_input_bytes
                ):
                    await close_once(4409)
                    break
                try:
                    await asyncio.to_thread(session.write, data.encode("utf-8"))
                except (PtyError, TerminalError, OSError):
                    await close_once(1011)
                    break
                except Exception:
                    await close_once(1011)
                    break
                continue
            if frame_type == "resize" and _exact_keys(frame, "type", "rows", "columns"):
                rows = frame.get("rows")
                columns = frame.get("columns")
                if (
                    type(rows) is not int
                    or type(columns) is not int
                    or not 1 <= rows <= limits.max_rows
                    or not 1 <= columns <= limits.max_columns
                ):
                    await close_once(4400)
                    break
                try:
                    await asyncio.to_thread(session.resize, rows, columns)
                except (PtyError, TerminalError, OSError):
                    await close_once(1011)
                    break
                except Exception:
                    await close_once(1011)
                    break
                continue
            if frame_type == "signal" and _exact_keys(frame, "type", "value"):
                value = frame.get("value")
                if type(value) is not int or not 1 <= value <= 64:
                    await close_once(4400)
                    break
                try:
                    await asyncio.to_thread(session.signal, value)
                except (PtyError, TerminalError, OSError):
                    await close_once(1011)
                    break
                except Exception:
                    await close_once(1011)
                    break
                continue
            await close_once(4400)
            break
    finally:
        if output_task is not None:
            output_task.cancel()
            await asyncio.gather(output_task, return_exceptions=True)
        if session is not None:
            try:
                await asyncio.to_thread(session.close)
            except Exception:
                pass
        if not disconnected:
            await close_once(requested_close_code or 1000)


def mount_terminal_route(
    app: FastAPI,
    *,
    gateway: TerminalGatewayProtocol,
    terminal: TerminalAttachmentProtocol,
    limits: WebSocketLimits,
    now: Clock,
) -> None:
    """Mount the terminal transport without exposing capability details."""

    if not isinstance(gateway, TerminalGatewayProtocol) or not isinstance(
        terminal, TerminalAttachmentProtocol
    ):
        raise ValueError("invalid terminal dependencies")

    @app.websocket("/v1/terminal")
    async def terminal_endpoint(websocket: WebSocket) -> None:
        await serve_terminal(websocket, gateway, terminal, limits, now)
