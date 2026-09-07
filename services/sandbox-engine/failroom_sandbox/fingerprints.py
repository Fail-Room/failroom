"""Version-stable fingerprints of explicit JSON configuration documents."""

import hashlib
import json


def _validate_json(value: object, ancestors: set[int]) -> None:
    if value is None or type(value) in (bool, int, float, str):
        return
    if type(value) not in (dict, list) or id(value) in ancestors:
        raise ValueError("INVALID_CONFIGURATION")
    ancestors.add(id(value))
    try:
        if isinstance(value, dict):
            for key, child in value.items():
                if type(key) is not str:
                    raise ValueError("INVALID_CONFIGURATION")
                _validate_json(child, ancestors)
        elif isinstance(value, list):
            for child in value:
                _validate_json(child, ancestors)
    finally:
        ancestors.remove(id(value))


def configuration_digest(configuration: dict[str, object]) -> str:
    """Hash a full JSON object; this does not validate the security of its values.

    Configuration loaders must supply explicit, complete configuration. The
    caller must serialize access to mutable inputs during fingerprinting.
    """
    try:
        if type(configuration) is not dict:
            raise ValueError("INVALID_CONFIGURATION")
        _validate_json(configuration, set())
        canonical = json.dumps(
            configuration,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise ValueError("INVALID_CONFIGURATION") from None
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
