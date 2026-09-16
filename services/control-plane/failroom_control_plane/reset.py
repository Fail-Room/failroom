"""Owner-scoped Reset Room request facade without resource identifiers."""

from collections.abc import Callable
from datetime import datetime

from failroom_state import Attempt, BackendStore, StoreError, UserIdentity

from .lifecycle import RoomStatus

Clock = Callable[[], datetime]


class ResetError(RuntimeError):
    """A fixed Reset Room failure without sandbox or runtime details."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if code in {"ATTEMPT_UNAVAILABLE", "NOT_AUTHORIZED", "INVALID_REQUEST"}
            else "ATTEMPT_UNAVAILABLE"
        )
        super().__init__(self.code)


def _status(attempt: Attempt) -> RoomStatus:
    return RoomStatus(
        attempt_id=attempt.attempt_id,
        room_id=attempt.room_id,
        state=attempt.state,
        expires_at=attempt.expires_at,
        destroy_intent=attempt.destroy_intent,
    )


class RoomResetService:
    """Reserve a replacement generation for one owned ready Room attempt."""

    def __init__(self, backend: BackendStore, *, now: Clock) -> None:
        if type(backend) is not BackendStore or not callable(now):
            raise ResetError("INVALID_REQUEST")
        self._backend = backend
        self._now = now

    def reset(self, identity: UserIdentity, attempt_id: str, *, key: str) -> RoomStatus:
        try:
            attempt = self._backend.inspect(identity, attempt_id)
            self._backend.begin_reset(identity, attempt.ref, key=key, now=self._now)
            return _status(self._backend.inspect(identity, attempt_id))
        except StoreError as error:
            raise ResetError(error.code) from None
