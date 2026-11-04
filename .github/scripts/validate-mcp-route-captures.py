from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_SHA256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "mcp-2026-07-28.json"
CAPTURE_NAMES = {
    "server-discover.json": "DiscoverResultResponse",
    "tools-list.json": "ListToolsResultResponse",
    "resources-list.json": "ListResourcesResultResponse",
    "prompts-list.json": "ListPromptsResultResponse",
    "resources-templates-list.json": "ListResourceTemplatesResultResponse",
    "resources-read-default.json": "ReadResourceResultResponse",
    "resources-read-explicit-cache.json": "ReadResourceResultResponse",
    "resources-read-input-required.json": "ReadResourceResultResponse",
    "resources-read-jsonrpc-error.json": "JSONRPCErrorResponse",
}


def fail(category: str, *, name: str = "schema-validation", digest: str | None = None) -> int:
    suffix = f" sha256={digest}" if digest else ""
    print(f"FAIL test={name} error_category={category}{suffix}")
    return 1


def main() -> int:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    capture_value = os.environ.get("CODEX_BRIDGE_MCP_CAPTURE_DIR")
    if not runner_temp_value or not capture_value:
        return fail("capture_environment_missing")

    runner_temp = Path(runner_temp_value).resolve()
    capture_dir = Path(capture_value).resolve()
    if capture_dir.parent != runner_temp:
        return fail("capture_directory_outside_runner_temp")
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
    actual_names = {path.name for path in capture_dir.glob("*.json") if path.is_file()}
    if actual_names != set(CAPTURE_NAMES):
        return fail("capture_set_incomplete_or_unexpected", digest=schema_digest)

    print(f"PASS test=pinned-schema sha256={schema_digest}")
    for filename, definition in CAPTURE_NAMES.items():
        path = capture_dir / filename
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest().upper()
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return fail("invalid_json", name=filename, digest=digest)

        root = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
        try:
            Draft202012Validator.check_schema(root)
            Draft202012Validator(root).validate(response)
        except ValidationError as error:
            category = {
                "required": "schema_required_property",
                "type": "schema_type",
                "enum": "schema_enum",
                "const": "schema_const",
                "additionalProperties": "schema_additional_property",
                "oneOf": "schema_one_of",
                "anyOf": "schema_any_of",
                "minimum": "schema_minimum",
                "maxItems": "schema_max_items",
            }.get(str(error.validator), "schema_validation")
            return fail(category, name=filename, digest=digest)
        except Exception:
            return fail("schema_validator_error", name=filename, digest=digest)

        print(f"PASS test={filename} schema={definition} sha256={digest}")

    print(f"PASS test=actual-route-capture-count count={len(CAPTURE_NAMES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
