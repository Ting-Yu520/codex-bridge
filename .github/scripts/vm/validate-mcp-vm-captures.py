from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


EXPECTED_BUILD_RUN_ID = 41665722609
EXPECTED_PRODUCTION_COMMIT = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
EXPECTED_PORTABLE_SHA256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
EXPECTED_SERVICE_SHA256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
EXPECTED_SCHEMA_SHA256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
# This source revision has no independent authenticated host-evidence anchor.
VMN5_TRUST_ANCHOR_CONFIGURED = False
EXPECTED_PYTHON_PACKAGES = {
    "attrs": "25.3.0",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.4.1",
    "referencing": "0.36.2",
    "rpds-py": "0.25.1",
}
EXPECTED_REQUIREMENTS_LOCK = (
    "attrs==25.3.0",
    "jsonschema==4.26.0",
    "jsonschema-specifications==2025.4.1",
    "referencing==0.36.2",
    "rpds-py==0.25.1",
)
REQUIRED_MEDIA_DEPENDENCIES = {
    "portable-zip",
    "test-source-bundle",
    "swift-6.3.3-toolchain",
    "swiftpm-pinned-source-cache",
    "visual-studio-cpp-sdk",
    "windows-adk-oscdimg",
    "vcpkg-x64-windows-sqlite",
    "python-3.13.11-runtime",
    "python-3.13.11-wheelhouse",
    "windows-x64-base-image",
}
REQUIRED_MEDIA_DEPENDENCY_PATHS = {
    "portable-zip": "codex-bridge-windows-x64.zip",
    "test-source-bundle": "codex-bridge-vm-test-source.zip",
    "swiftpm-pinned-source-cache": "swiftpm-pinned-source-cache.zip",
}
CAPTURES = {
    "server-discover": ("DiscoverResultResponse", 801),
    "tools-list": ("ListToolsResultResponse", 802),
    "resources-list": ("ListResourcesResultResponse", 803),
    "resources-read": ("ReadResourceResultResponse", 804),
    "resources-read-invalid": ("JSONRPCErrorResponse", 805),
}
PROTOCOL_VERSION = "2026-07-28"
VALID_RESOURCE_URI = "ui://codex-bridge/file-transfer.html"


class ValidationFailure(Exception):
    def __init__(self, category: str, name: str = "vm-preflight") -> None:
        super().__init__(category)
        self.category = category
        self.name = name


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def fail(category: str, name: str = "vm-validation", digest: str | None = None) -> int:
    suffix = f" sha256={digest}" if digest else ""
    print(f"FAIL test={name} error_category={category}{suffix}")
    return 1


def read_json(path: Path, category: str) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValidationFailure(category) from None


def require(condition: bool, category: str, name: str = "vm-preflight") -> None:
    if not condition:
        raise ValidationFailure(category, name)


def safe_child(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    require(not candidate.is_absolute() and ".." not in candidate.parts, "media_path_invalid")
    joined = root / candidate
    cursor = root
    for part in candidate.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), "media_reparse_point_not_allowed")
    full = joined.resolve(strict=True)
    root_real = root.resolve(strict=True)
    require(full == root_real or root_real in full.parents, "media_path_outside_root")
    require(not full.is_symlink() and full.is_file(), "media_file_invalid")
    return full


def check_media_manifest(manifest: dict[str, Any], root: Path, expected_commit: str) -> None:
    require(isinstance(manifest, dict), "media_manifest_invalid")
    require(manifest.get("schema") == "codex-bridge-b1-vm-media/v1", "media_manifest_schema_invalid")
    require(manifest.get("testSourceCommit") == expected_commit, "media_source_commit_mismatch")
    require(manifest.get("schemaSha256", "").upper() == EXPECTED_SCHEMA_SHA256, "media_schema_digest_mismatch")
    build = manifest.get("build", {})
    require(isinstance(build, dict), "candidate_build_identity_invalid")
    require(
        build.get("runId") == EXPECTED_BUILD_RUN_ID
        and build.get("productionCommit") == EXPECTED_PRODUCTION_COMMIT
        and build.get("portableZipSha256", "").lower() == EXPECTED_PORTABLE_SHA256
        and build.get("serviceExeSha256", "").lower() == EXPECTED_SERVICE_SHA256,
        "candidate_build_identity_mismatch",
    )
    dependencies = manifest.get("dependencies")
    require(isinstance(dependencies, list) and len(dependencies) > 0, "media_dependencies_missing")
    dependency_names: list[str] = []
    for item in dependencies:
        require(
            isinstance(item, dict)
            and all(isinstance(item.get(key), str) and item[key].strip() for key in ("name", "source", "version", "path"))
            and re.fullmatch(r"[A-Fa-f0-9]{64}", str(item.get("sha256", ""))) is not None,
            "media_dependency_metadata_incomplete",
        )
        dependency_names.append(item["name"])
        if item["name"] in REQUIRED_MEDIA_DEPENDENCY_PATHS:
            require(item["path"].replace("\\", "/") == REQUIRED_MEDIA_DEPENDENCY_PATHS[item["name"]], "media_dependency_path_mismatch")
        path = safe_child(root, item["path"])
        require(sha256(path.read_bytes()).lower() == item["sha256"].lower(), "media_dependency_digest_mismatch")
    require(len(dependency_names) == len(set(dependency_names)), "media_dependency_name_duplicate")
    require(set(dependency_names) == REQUIRED_MEDIA_DEPENDENCIES, "media_required_dependency_set_mismatch")


def check_swift_package_lock(manifest: dict[str, Any], lock_path: Path) -> None:
    lock, _ = read_json(lock_path, "swift_package_lock_invalid")
    require(isinstance(lock, dict), "swift_package_lock_invalid")
    pins = manifest.get("swiftPackages")
    require(isinstance(pins, list) and len(pins) > 0, "swift_package_manifest_missing")
    expected = {}
    for pin in pins:
        require(
            isinstance(pin, dict)
            and all(isinstance(pin.get(key), str) and pin[key] for key in ("identity", "location", "revision")),
            "swift_package_manifest_invalid",
        )
        expected[pin["identity"]] = pin
    actual = {}
    for pin in lock.get("pins", []):
        state = pin.get("state", {})
        actual[pin.get("identity")] = {
            "identity": pin.get("identity"),
            "location": pin.get("location"),
            "revision": state.get("revision"),
            "version": state.get("version"),
        }
    require(set(actual) == set(expected), "swift_package_pin_set_mismatch")
    for identity, pin in expected.items():
        locked = actual[identity]
        require(
            pin["location"] == locked["location"]
            and pin["revision"] == locked["revision"]
            and pin.get("version") == locked.get("version"),
            "swift_package_pin_mismatch",
        )


def check_python_requirements(path: Path) -> None:
    try:
        lines = tuple(line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        raise ValidationFailure("schema_requirements_lock_missing") from None
    require(lines == EXPECTED_REQUIREMENTS_LOCK, "schema_requirements_lock_mismatch")


def check_host_evidence(host: dict[str, Any], context: dict[str, Any]) -> None:
    require(isinstance(host, dict), "host_evidence_invalid")
    require(host.get("schema") == "codex-bridge-b1-vm-host-evidence/v1", "host_evidence_schema_invalid")
    require(
        host.get("vmId") == context.get("vmId")
        and host.get("nonce") == context.get("nonce")
        and host.get("sourceCommit") == context.get("testSourceCommit")
        and re.fullmatch(r"S-1-5-21(?:-\d{1,12}){4}", str(context.get("expectedGuestAccountSid", ""))) is not None
        and host.get("expectedGuestAccountSid") == context.get("expectedGuestAccountSid"),
        "host_context_identity_mismatch",
    )
    build = host.get("build", {})
    require(isinstance(build, dict), "host_build_identity_invalid")
    require(
        build.get("runId") == EXPECTED_BUILD_RUN_ID
        and build.get("productionCommit") == EXPECTED_PRODUCTION_COMMIT
        and build.get("portableZipSha256", "").lower() == EXPECTED_PORTABLE_SHA256
        and build.get("serviceExeSha256", "").lower() == EXPECTED_SERVICE_SHA256,
        "host_candidate_build_identity_mismatch",
    )
    checks = host.get("checks", {})
    observations = host.get("observations", {})
    require(isinstance(checks, dict) and isinstance(observations, dict), "host_evidence_shape_invalid")
    n1 = checks.get("VMN1", {})
    require(
        n1.get("status") == "PASS"
        and observations.get("networkAdapterCount") == 0
        and observations.get("assignedDeviceCount") == 0
        and observations.get("externalPathCount") == 0,
        "vmn1_host_network_boundary_unverified",
    )
    n4 = checks.get("VMN4", {})
    require(
        n4.get("status") == "PASS"
        and observations.get("enhancedSessionEnabled") is False
        and observations.get("clipboardDisabled") is True
        and observations.get("guestServiceInterfaceEnabled") is False
        and observations.get("dataExchangeEnabled") is False
        and observations.get("sharedFolderCount") == 0
        and observations.get("enabledIntegrationServiceCount") == 0
        and observations.get("configuredComPortCount") == 0
        and observations.get("configuredFloppyDriveCount") == 0
        and observations.get("fibreChannelAdapterCount") == 0
        and observations.get("gpuPartitionAdapterCount") == 0
        and observations.get("expectedScratchDiskSet") is True
        and observations.get("hardDiskPathsWithinRunRoot") is True
        and observations.get("outputDiskAttachedExactlyOnce") is True
        and observations.get("offlineMediaAttachedReadOnly") is True
        and observations.get("unapprovedChannels") == [],
        "vmn4_host_channel_boundary_unverified",
    )
    n5 = checks.get("VMN5", {})
    require(
        isinstance(n5, dict)
        and n5.get("status") == "BLOCKED"
        and n5.get("result") == "VM_N5_BLOCKED"
        and n5.get("hashFormatStatus") == (
            "HASH_FORMAT_VALID"
            if re.fullmatch(r"[A-Fa-f0-9]{64}", str(host.get("vmConfigurationSha256", ""))) is not None
            else "HASH_FORMAT_INVALID"
        )
        and n5.get("hashIntegrityStatus") == "HASH_INTEGRITY_NOT_CHECKED"
        and n5.get("trustAnchorStatus") == "TRUST_ANCHOR_UNAVAILABLE"
        and n5.get("reason") == "vmn5_trust_anchor_unavailable",
        "vmn5_status_claim_untrusted",
    )
    require(VMN5_TRUST_ANCHOR_CONFIGURED, "vmn5_trust_anchor_unavailable")
    require(
        re.fullmatch(r"[A-Fa-f0-9]{64}", str(observations.get("controllerSha256", ""))) is not None
        and observations.get("mediaManifestSha256", "").lower() == context.get("mediaManifestSha256", "").lower(),
        "vmn5_host_provenance_unverified",
    )
    require(
        observations.get("offlineMediaSha256", "").lower() == context.get("mediaIsoSha256", "").lower(),
        "vmn5_offline_media_digest_mismatch",
    )


def check_guest_evidence(guest: dict[str, Any], host: dict[str, Any], context: dict[str, Any]) -> None:
    require(isinstance(guest, dict), "guest_evidence_invalid")
    require(isinstance(host, dict), "host_evidence_invalid")
    require(guest.get("schema") == "codex-bridge-b1-vm-guest-evidence/v1", "guest_evidence_schema_invalid")
    require(
        guest.get("vmId") == context.get("vmId") == host.get("vmId")
        and guest.get("nonce") == context.get("nonce")
        and guest.get("sourceCommit") == context.get("testSourceCommit")
        and guest.get("hostEvidenceSha256", "").lower() == context.get("hostEvidenceSha256", "").lower(),
        "guest_host_binding_mismatch",
    )
    require(host.get("nonce") == guest.get("nonce"), "guest_host_nonce_mismatch")
    host_n5 = host.get("checks", {}).get("VMN5", {})
    require(
        isinstance(host_n5, dict)
        and host_n5.get("status") == "BLOCKED"
        and host_n5.get("result") == "VM_N5_BLOCKED"
        and host_n5.get("trustAnchorStatus") == "TRUST_ANCHOR_UNAVAILABLE",
        "host_vmn5_status_claim_untrusted",
    )
    require(VMN5_TRUST_ANCHOR_CONFIGURED, "vmn5_trust_anchor_unavailable")
    platform = guest.get("platform", {})
    require(platform.get("architecture") == "x64", "guest_architecture_invalid")
    require(isinstance(platform.get("windowsVersion"), str) and platform["windowsVersion"], "guest_windows_version_missing")
    checks = guest.get("checks", {})
    n2 = checks.get("VMN2", {})
    require(
        n2.get("status") == "PASS"
        and n2.get("defaultRouteCount") == 0
        and n2.get("activeNonLoopbackAdapterCount") == 0
        and n2.get("proxyPresent") is False
        and n2.get("knownCredentialPresent") is False
        and n2.get("userIsAdministrator") is False
        and n2.get("isolatedTestAccountMatched") is True
        and n2.get("realCodexConfigurationPresent") is False,
        "vmn2_guest_network_or_account_boundary_unverified",
    )
    n3 = checks.get("VMN3", {})
    require(n3.get("status") == "PASS" and n3.get("ipv4Loopback") is True, "vmn3_loopback_unverified")
    n4 = checks.get("VMN4", {})
    require(
        n4.get("status") == "PASS"
        and n4.get("powerShellDirectServiceDisabled") is True
        and n4.get("powerShellDirectServiceStopped") is True
        and n4.get("enhancedSessionDisconnected") is True,
        "vmn4_guest_management_channel_unverified",
    )


def parse_response(raw: bytes, content_type: str) -> dict[str, Any] | None:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "application/json":
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else None
    if media_type != "text/event-stream":
        return None
    text = raw.decode("utf-8")
    values: list[dict[str, Any]] = []
    for event in text.replace("\r\n", "\n").split("\n\n"):
        lines = [line[5:].lstrip() for line in event.splitlines() if line.startswith("data:")]
        if not lines:
            continue
        value = json.loads("\n".join(lines))
        if isinstance(value, dict) and value.get("jsonrpc") == "2.0":
            values.append(value)
    return values[0] if len(values) == 1 else None


def check_semantics(name: str, response: dict[str, Any], expected_id: int) -> None:
    require(response.get("jsonrpc") == "2.0" and response.get("id") == expected_id, "jsonrpc_envelope_mismatch", name)
    if name == "resources-read-invalid":
        error = response.get("error")
        require("result" not in response and isinstance(error, dict), "jsonrpc_error_shape_mismatch", name)
        require(error.get("code") == -32602, "jsonrpc_error_code_mismatch", name)
        require(error.get("message") == "Invalid params: Unknown resource URI.", "jsonrpc_error_message_mismatch", name)
        detail_data = error.get("data")
        require(isinstance(detail_data, dict) and detail_data.get("detail") == "Unknown resource URI.", "jsonrpc_error_detail_mismatch", name)
        return

    result = response.get("result")
    require(isinstance(result, dict) and "error" not in response, "jsonrpc_result_shape_mismatch", name)
    require(result.get("resultType") == "complete", "result_type_mismatch", name)
    require(result.get("ttlMs") == 0 and result.get("cacheScope") == "private", "cache_policy_mismatch", name)
    if name == "server-discover":
        require(PROTOCOL_VERSION in result.get("supportedVersions", []), "protocol_version_missing", name)
    elif name == "tools-list":
        require(isinstance(result.get("tools"), list), "tools_list_missing", name)
    elif name == "resources-list":
        require(
            isinstance(result.get("resources"), list)
            and any(item.get("uri") == VALID_RESOURCE_URI for item in result["resources"] if isinstance(item, dict)),
            "resource_list_missing_synthetic_uri",
            name,
        )
    elif name == "resources-read":
        contents = result.get("contents")
        require(isinstance(contents, list) and len(contents) > 0, "resource_contents_missing", name)
        content = contents[0]
        require(
            isinstance(content, dict)
            and content.get("uri") == VALID_RESOURCE_URI
            and isinstance(content.get("text"), str)
            and bool(content["text"])
            and isinstance(content.get("_meta"), dict)
            and isinstance(result.get("_meta"), dict)
            and "io.modelcontextprotocol/serverInfo" in result["_meta"],
            "resource_metadata_mismatch",
            name,
        )


def validate_captures(capture_dir: Path, schema: dict[str, Any], output_path: Path, summary: dict[str, Any]) -> None:
    require(VMN5_TRUST_ANCHOR_CONFIGURED, "vmn5_trust_anchor_unavailable")
    require(capture_dir.is_dir() and not capture_dir.is_symlink(), "capture_directory_invalid")
    expected = {f"{name}.{suffix}" for name in CAPTURES for suffix in ("body", "content-type")}
    entries = list(capture_dir.iterdir())
    require(
        all(entry.is_file() and not entry.is_symlink() for entry in entries)
        and {entry.name for entry in entries} == expected,
        "capture_set_incomplete_or_unexpected",
    )
    summaries: dict[str, dict[str, str]] = {}
    for name, (definition, request_id) in CAPTURES.items():
        body = (capture_dir / f"{name}.body").read_bytes()
        digest = sha256(body)
        content_type = (capture_dir / f"{name}.content-type").read_text(encoding="utf-8")
        try:
            response = parse_response(body, content_type)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValidationFailure("response_json_invalid", name) from None
        require(response is not None, "response_content_type_invalid", name)
        target = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{definition}"}
        try:
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
            raise ValidationFailure(category, name) from None
        check_semantics(name, response, request_id)
        summaries[name] = {"status": "PASS", "schema": definition, "sha256": digest}
        print(f"PASS test={name} schema={definition} sha256={digest}")

    summary["protocol"] = {
        "status": "PASS",
        "schemaSha256": EXPECTED_SCHEMA_SHA256,
        "responses": summaries,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"PASS test=actual-route-responses count={len(summaries)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate real Codex Bridge VM route captures without printing response bodies.")
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--expected-context-sha256", required=True)
    parser.add_argument("--host-evidence", required=True, type=Path)
    parser.add_argument("--host-evidence-sha256", required=True, type=Path)
    parser.add_argument("--guest-evidence", required=True, type=Path)
    parser.add_argument("--media-manifest", required=True, type=Path)
    parser.add_argument("--media-root", required=True, type=Path)
    parser.add_argument("--package-resolved", required=True, type=Path)
    parser.add_argument("--requirements-lock", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--capture-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    try:
        for package, version in EXPECTED_PYTHON_PACKAGES.items():
            require(importlib.metadata.version(package) == version, "schema_python_dependency_version_mismatch")
        require(sys.version_info[:3] == (3, 13, 11), "python_version_mismatch")
        check_python_requirements(args.requirements_lock)
        print("PASS test=python-schema-runtime python=3.13.11 dependencies=pinned")

        context, context_raw = read_json(args.context, "run_context_invalid")
        require(sha256(context_raw).lower() == args.expected_context_sha256.lower(), "run_context_digest_mismatch")
        require(context.get("schema") == "codex-bridge-b1-vm-run-context/v1", "run_context_schema_invalid")
        require(re.fullmatch(r"[0-9a-f]{40}", str(context.get("testSourceCommit", ""))) is not None, "test_source_commit_invalid")
        require(re.fullmatch(r"[A-Fa-f0-9]{64}", str(context.get("hostEvidenceSha256", ""))) is not None, "host_evidence_digest_missing")
        require(re.fullmatch(r"[A-Fa-f0-9]{64}", str(context.get("mediaManifestSha256", ""))) is not None, "media_manifest_digest_missing")

        host, host_raw = read_json(args.host_evidence, "host_evidence_invalid")
        actual_host_digest = sha256(host_raw)
        expected_sidecar = args.host_evidence_sha256.read_text(encoding="ascii").strip().split()[0]
        require(
            actual_host_digest.lower() == context["hostEvidenceSha256"].lower() == expected_sidecar.lower(),
            "host_evidence_digest_mismatch",
        )
        check_host_evidence(host, context)
        print(f"PASS test=host-isolation-evidence sha256={actual_host_digest}")

        manifest, manifest_raw = read_json(args.media_manifest, "media_manifest_invalid")
        manifest_digest = sha256(manifest_raw)
        require(manifest_digest.lower() == context["mediaManifestSha256"].lower(), "media_manifest_digest_mismatch")
        check_media_manifest(manifest, args.media_root, context["testSourceCommit"])
        check_swift_package_lock(manifest, args.package_resolved)
        print(f"PASS test=offline-media-manifest sha256={manifest_digest}")

        guest, _ = read_json(args.guest_evidence, "guest_evidence_invalid")
        check_guest_evidence(guest, host, context)
        print("PASS test=guest-isolation-evidence VMN2=PASS VMN3=PASS")

        schema_raw = args.schema.read_bytes()
        schema_digest = sha256(schema_raw)
        require(schema_digest == EXPECTED_SCHEMA_SHA256, "pinned_schema_hash_mismatch")
        schema = json.loads(schema_raw.decode("utf-8"))
        Draft202012Validator.check_schema(schema)
        print(f"PASS test=fixed-mcp-2026-07-28-schema sha256={schema_digest}")

        if args.preflight_only:
            print("PASS test=vm-safety-and-offline-dependency-preflight")
            return 0
        require(args.capture_dir is not None and args.output is not None, "capture_or_output_path_missing")

        summary: dict[str, Any] = {
            "schema": "codex-bridge-b1-vm-protocol-summary/v1",
            "sourceCommit": context["testSourceCommit"],
            "buildRunId": EXPECTED_BUILD_RUN_ID,
            "productionCommit": EXPECTED_PRODUCTION_COMMIT,
            "portableSha256": EXPECTED_PORTABLE_SHA256,
            "serviceExeSha256": EXPECTED_SERVICE_SHA256,
            "vmIsolation": {name: ("BLOCKED" if name == "VMN5" else "NOT_TESTED") for name in ("VMN1", "VMN2", "VMN3", "VMN4", "VMN5")},
        }
        validate_captures(args.capture_dir, schema, args.output, summary)
        return 0
    except ValidationFailure as error:
        return fail(error.category, error.name)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, json.JSONDecodeError):
        return fail("validator_input_or_runtime_error")


if __name__ == "__main__":
    sys.exit(main())
