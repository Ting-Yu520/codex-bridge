import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate-mcp-vm-captures.py"
SPEC = importlib.util.spec_from_file_location("validate_mcp_vm_captures", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def host_evidence(n5_status: str = "BLOCKED") -> tuple[dict, dict]:
    vm_id = "9d468b50-193d-4531-84d1-0c3a799bb8ba"
    nonce = "synthetic-nonce-001"
    source_commit = "5d0e0904221a8185c66ae301ece3ea05e81810b4"
    media_hash = "b" * 64
    iso_hash = "c" * 64
    configuration_hash = "a" * 64
    n5 = {
        "status": n5_status,
        "result": "VM_N5_BLOCKED" if n5_status == "BLOCKED" else "VM_N5_PASS",
        "hashFormatStatus": "HASH_FORMAT_VALID",
        "hashIntegrityStatus": "HASH_INTEGRITY_NOT_CHECKED",
        "trustAnchorStatus": "TRUST_ANCHOR_UNAVAILABLE",
        "reason": "vmn5_trust_anchor_unavailable",
    }
    host = {
        "schema": "codex-bridge-b1-vm-host-evidence/v1",
        "vmId": vm_id,
        "nonce": nonce,
        "sourceCommit": source_commit,
        "expectedGuestAccountSid": "S-1-5-21-1000-2000-3000-1101",
        "vmConfigurationSha256": configuration_hash,
        "build": {
            "runId": validator.EXPECTED_BUILD_RUN_ID,
            "productionCommit": validator.EXPECTED_PRODUCTION_COMMIT,
            "portableZipSha256": validator.EXPECTED_PORTABLE_SHA256,
            "serviceExeSha256": validator.EXPECTED_SERVICE_SHA256,
        },
        "checks": {
            "VMN1": {"status": "PASS"},
            "VMN4": {"status": "PASS"},
            "VMN5": n5,
        },
        "observations": {
            "networkAdapterCount": 0,
            "assignedDeviceCount": 0,
            "externalPathCount": 0,
            "enhancedSessionEnabled": False,
            "clipboardDisabled": True,
            "guestServiceInterfaceEnabled": False,
            "dataExchangeEnabled": False,
            "sharedFolderCount": 0,
            "enabledIntegrationServiceCount": 0,
            "configuredComPortCount": 0,
            "configuredFloppyDriveCount": 0,
            "fibreChannelAdapterCount": 0,
            "gpuPartitionAdapterCount": 0,
            "expectedScratchDiskSet": True,
            "hardDiskPathsWithinRunRoot": True,
            "outputDiskAttachedExactlyOnce": True,
            "offlineMediaAttachedReadOnly": True,
            "unapprovedChannels": [],
            "controllerSha256": "d" * 64,
            "mediaManifestSha256": media_hash,
            "offlineMediaSha256": iso_hash,
        },
    }
    context = {
        "vmId": vm_id,
        "nonce": nonce,
        "testSourceCommit": source_commit,
        "expectedGuestAccountSid": host["expectedGuestAccountSid"],
        "hostEvidenceSha256": "e" * 64,
        "mediaManifestSha256": media_hash,
        "mediaIsoSha256": iso_hash,
    }
    return host, context


class VmN5FailClosedTests(unittest.TestCase):
    def test_valid_sha256_without_anchor_remains_blocked(self) -> None:
        host, context = host_evidence()
        with self.assertRaises(validator.ValidationFailure) as caught:
            validator.check_host_evidence(host, context)
        self.assertEqual(caught.exception.category, "vmn5_trust_anchor_unavailable")

    def test_forged_n5_pass_is_rejected(self) -> None:
        host, context = host_evidence("PASS")
        with self.assertRaises(validator.ValidationFailure) as caught:
            validator.check_host_evidence(host, context)
        self.assertEqual(caught.exception.category, "vmn5_status_claim_untrusted")

    def test_guest_cannot_promote_unanchored_host(self) -> None:
        host, context = host_evidence()
        guest = {
            "schema": "codex-bridge-b1-vm-guest-evidence/v1",
            "vmId": host["vmId"],
            "nonce": host["nonce"],
            "sourceCommit": host["sourceCommit"],
            "hostEvidenceSha256": context["hostEvidenceSha256"],
        }
        with self.assertRaises(validator.ValidationFailure) as caught:
            validator.check_guest_evidence(guest, host, context)
        self.assertEqual(caught.exception.category, "vmn5_trust_anchor_unavailable")

    def test_schema_capture_validation_is_blocked_without_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            capture_dir = Path(root) / "captures"
            capture_dir.mkdir()
            with self.assertRaises(validator.ValidationFailure) as caught:
                validator.validate_captures(capture_dir, {}, Path(root) / "summary.json", {"vmIsolation": {"VMN5": "PASS"}})
            self.assertEqual(caught.exception.category, "vmn5_trust_anchor_unavailable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
