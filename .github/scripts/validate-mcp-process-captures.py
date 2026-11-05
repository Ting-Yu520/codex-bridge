from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


SCHEMA_SHA256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "mcp-2026-07-28.json"
CAPTURES = {
    "server-discover": "DiscoverResultResponse",
    "tools-list": "ListToolsResultResponse",
    "resources-list": "ListResourcesResultResponse",
    "resources-read": "ReadResourceResultResponse",
    "resources-read-invalid": "JSONRPCErrorResponse",
}


def fail(category: str, *, name: str = "mcp-process-schema", digest: str | None = None) -> int:
    suffix = f" sha256={digest}" if digest else ""
    print(f"FAIL test={name} error_category={category}{suffix}")
    return 1


def response_object(raw: bytes, content_type: str) -> dict[str, Any] | None:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "application/json":
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    if media_type != "text/event-stream":
        return None

    text = raw.decode("utf-8")
    responses: list[dict[str, Any]] = []
    for event in text.replace("\r\n", "\n").split("\n\n"):
        data_lines = [line[5:].lstrip() for line in event.splitlines() if line.startswith("data:")]
        if not data_lines:
            continue
        try:
            value = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("jsonrpc") == "2.0":
            responses.append(value)
    return responses[0] if len(responses) == 1 else None


def main() -> int:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    capture_value = os.environ.get("CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR")
    if not runner_temp_value or not capture_value:
        return fail("capture_environment_missing")

    runner_temp = Path(runner_temp_value).resolve()
    capture_dir = Path(capture_value).resolve()
    if capture_dir.parent != runner_temp:
        return fail("capture_directory_outside_runner_temp")

    security_state_path = runner_temp / "codex-bridge-b1-egress-state.json"
    if not security_state_path.is_file():
        return fail("security_state_missing", name="mcp-process-security-gate")
    try:
        security_state = json.loads(security_state_path.read_bytes())
        levels = security_state["network"]["levels"]
        security_ready = (
            security_state.get("schema") == "codex-bridge-b1-egress-recovery/v2"
            and security_state.get("phase") == "guard-active"
            and levels.get("L4") == "PASS"
            and security_state["network"].get("serviceStartAllowed") is True
        )
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        return fail("security_state_invalid", name="mcp-process-security-gate")
    if not security_ready:
        return fail("process_tree_egress_isolation_unavailable", name="mcp-process-security-gate")
    print("PASS test=mcp-process-security-gate isolation_level=L4")

    if not SCHEMA_PATH.is_file():
        return fail("pinned_schema_missing")

    schema_bytes = SCHEMA_PATH.read_bytes()
    schema_digest = hashlib.sha256(schema_bytes).hexdigest().upper()
    if schema_digest != SCHEMA_SHA256:
        return fail("pinned_schema_hash_mismatch", digest=schema_digest)
    try:
        schema = json.loads(schema_bytes)
        Draft202012Validator.check_schema(schema)
    except Exception:
        return fail("pinned_schema_invalid", digest=schema_digest)

    if not capture_dir.is_dir():
        return fail("capture_directory_missing", digest=schema_digest)
    expected_files = {
        f"{name}.{suffix}"
        for name in CAPTURES
        for suffix in ("body", "content-type")
    }
    actual_files = {entry.name for entry in capture_dir.iterdir() if entry.is_file()}
    if actual_files != expected_files or any(entry.is_dir() for entry in capture_dir.iterdir()):
        return fail("capture_set_incomplete_or_unexpected", digest=schema_digest)

    print(f"PASS test=pinned-schema sha256={schema_digest}")
    for name, definition in CAPTURES.items():
        raw = (capture_dir / f"{name}.body").read_bytes()
        body_digest = hashlib.sha256(raw).hexdigest().upper()
        content_type = (capture_dir / f"{name}.content-type").read_text(encoding="utf-8")
        try:
            response = response_object(raw, content_type)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return fail("invalid_json_or_sse", name=name, digest=body_digest)
        if response is None:
            return fail("response_or_content_type_invalid", name=name, digest=body_digest)

        target = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
        try:
            Draft202012Validator.check_schema(target)
            Draft202012Validator(target).validate(response)
        except ValidationError as error:
            category = {
                "required": "schema_required_property",
                "type": "schema_type",
                "enum": "schema_enum",
                "const": "schema_const",
                "additionalProperties": "schema_additional_property",
                "oneOf": "schema_one_of",
                "anyOf": "schema_any_of",
            }.get(str(error.validator), "schema_validation")
            return fail(category, name=name, digest=body_digest)
        except Exception:
            return fail("schema_validator_error", name=name, digest=body_digest)

        print(f"PASS test={name} schema={definition} sha256={body_digest}")

    print(f"PASS test=actual-process-response-count count={len(CAPTURES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
