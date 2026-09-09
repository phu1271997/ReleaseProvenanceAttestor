import hashlib
import json
from datetime import datetime, timezone

import pytest


CONTRACT = "contracts/release_provenance_attestor.py"
API_PATTERN = r"api\.github\.com/repos/acme/widget/releases/tags/"
RAW_PATTERN = r"raw\.githubusercontent\.com/acme/widget/"
COUNTER_PATTERN = r"gist\.example\.org/counter"

OWNER = "0x1111111111111111111111111111111111111111"
OTHER = "0x2222222222222222222222222222222222222222"
OWNER_B = bytes.fromhex(OWNER[2:])
OTHER_B = bytes.fromhex(OTHER[2:])

COMMIT = "a" * 40
TAG = "v1.4.0"
POLICY = ("Every release MUST document all breaking changes and disclose any fixed "
          "security advisories with their CVE identifiers before it may ship.")
POLICY_DIGEST = hashlib.sha256(POLICY.encode()).hexdigest()
COUNTER_URL = "https://gist.example.org/counter"

BASE = datetime(2026, 9, 7, 10, 0, 0, tzinfo=timezone.utc)
BASE_ISO = BASE.isoformat()
NOW = int(BASE.timestamp())
START = NOW - 120
END = NOW + 7 * 24 * 3600
AFTER_ISO = datetime.fromtimestamp(END + 60, tz=timezone.utc).isoformat()
PUBLISHED_ISO = "2026-09-07T10:05:00Z"          # NOW + 300, inside the window
EARLY_ISO = "2026-09-07T09:00:00Z"              # before the channel opened


def deploy(direct_vm, direct_deploy):
    direct_vm.warp(BASE_ISO)
    direct_vm.strict_mocks = True
    direct_vm.check_pickling = True
    with direct_vm.prank(OWNER_B):
        return direct_deploy(CONTRACT)


def open_channel(contract, direct_vm, **changes):
    values = dict(
        repo_owner="acme",
        repo_name="widget",
        maintainers="alice,bob",
        policy_commit=COMMIT,
        policy_path="SECURITY/release-policy.md",
        policy_sha256=POLICY_DIGEST,
        required_asset=".sha256",
        allow_prerelease=False,
        starts_at=START,
        ends_at=END,
    )
    values.update(changes)
    with direct_vm.prank(OWNER_B):
        return contract.open_channel(**values)


def release_payload(**changes):
    value = dict(
        tag_name=TAG,
        draft=False,
        prerelease=False,
        published_at=PUBLISHED_ISO,
        author={"login": "Alice"},
        assets=[{"name": "widget-1.4.0.tar.gz"}, {"name": "widget-1.4.0.SHA256"}],
        body="Breaking: removed the legacy v0 API. Security: fixed CVE-2026-0001 in the parser.",
    )
    value.update(changes)
    return value


def mocks(direct_vm, payload=None, policy=POLICY, api_status=200, policy_status=200,
          verdict="COMPLIANT", confidence=90, llm=True):
    direct_vm.mock_web(API_PATTERN, {"method": "GET", "status": api_status,
                                     "body": json.dumps(payload or release_payload())})
    if api_status == 200:
        direct_vm.mock_web(RAW_PATTERN, {"method": "GET", "status": policy_status, "body": policy})
    if llm:
        direct_vm.mock_llm("RELEASE_POLICY_ALIGNMENT_V1", {"verdict": verdict, "confidence": confidence})


def attest(contract, direct_vm, tag=TAG, **mock_args):
    mocks(direct_vm, **mock_args)
    with direct_vm.prank(OWNER_B):
        return contract.attest_release(0, tag)


def test_minimal_no_constructor_and_sealed_channel(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    channel_id = open_channel(contract, direct_vm)
    record = contract.get_channel(channel_id)
    assert record.owner.as_hex == OWNER
    assert record.maintainers == "alice,bob"
    assert record.policy_commit == COMMIT
    assert record.policy_sha256 == POLICY_DIGEST
    assert record.state == "OPEN"
    assert contract.get_config()["version"] == "RELEASE_PROVENANCE_ATTESTOR_V1"


@pytest.mark.parametrize("field,value,error", [
    ("policy_commit", "main", "INVALID_COMMIT"),
    ("policy_path", "../secret", "INVALID_POLICY_PATH"),
    ("policy_sha256", "A" * 64, "INVALID_DIGEST"),
    ("maintainers", "", "INVALID_MAINTAINER"),
    ("maintainers", "-bad", "INVALID_MAINTAINER"),
    ("repo_owner", "bad owner", "INVALID_REPO_OWNER"),
])
def test_invalid_inputs_do_not_create_channel(direct_vm, direct_deploy, field, value, error):
    contract = deploy(direct_vm, direct_deploy)
    with direct_vm.expect_revert(error):
        open_channel(contract, direct_vm, **{field: value})
    assert contract.get_config()["channel_count"] == 0


def test_happy_path_attests_compliant_release(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    aid = attest(contract, direct_vm)
    attestation = contract.get_attestation(aid)
    attempt = contract.get_attempt(aid, 1)
    assert attestation.state == "ATTESTED"
    assert attestation.reason_code == "RELEASE_COMPLIANT"
    assert attestation.verdict == "COMPLIANT"
    assert attestation.confidence_band == 2
    assert len(attestation.evidence_digest) == 64
    assert attempt.policy_alignment == "COMPLIANT"
    assert contract.get_channel(0).unresolved == 0


@pytest.mark.parametrize("verdict,state,reason", [
    ("VIOLATION", "NON_COMPLIANT", "POLICY_VIOLATION"),
    ("PARTIAL", "REVIEW_REQUIRED", "SEMANTIC_RESULT_UNCLEAR"),
])
def test_semantic_results_are_bounded(direct_vm, direct_deploy, verdict, state, reason):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm, verdict=verdict)
    assert contract.get_attestation(0).state == state
    assert contract.get_attestation(0).reason_code == reason


@pytest.mark.parametrize("changes,reason", [
    ({"tag_name": "v9.9.9"}, "TAG_MISMATCH"),
    ({"author": {"login": "mallory"}}, "AUTHOR_NOT_ALLOWED"),
    ({"draft": True}, "NOT_PUBLISHED"),
    ({"prerelease": True}, "NOT_PUBLISHED"),
    ({"published_at": EARLY_ISO}, "OUTSIDE_CHANNEL_WINDOW"),
    ({"assets": [{"name": "widget.tar.gz"}]}, "PROVENANCE_ASSET_MISSING"),
])
def test_deterministic_binding_failures(direct_vm, direct_deploy, changes, reason):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm, payload=release_payload(**changes))
    attestation = contract.get_attestation(0)
    assert attestation.state == "NON_COMPLIANT"
    assert attestation.reason_code == reason


def test_policy_digest_mismatch_cannot_attest(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm, policy=POLICY + " tampered")
    assert contract.get_attestation(0).state == "NON_COMPLIANT"
    assert contract.get_attestation(0).reason_code == "POLICY_DIGEST_MISMATCH"


def test_prerelease_allowed_when_channel_opts_in(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm, allow_prerelease=True)
    attest(contract, direct_vm, payload=release_payload(prerelease=True))
    assert contract.get_attestation(0).state == "ATTESTED"


def test_http_failure_is_retry_safe_and_append_only(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm, api_status=503, llm=False)
    first = contract.get_attempt(0, 1)
    assert first.source_status == "UNAVAILABLE"
    assert contract.get_attestation(0).state == "REVIEW_REQUIRED"
    direct_vm.clear_mocks()
    mocks(direct_vm)
    with direct_vm.prank(OWNER_B):
        contract.retry_attest(0)
    assert contract.get_attestation(0).state == "ATTESTED"
    assert contract.get_attempt(0, 1) == first
    assert contract.get_attempt(0, 2).source_status == "VERIFIED"


def test_malformed_model_output_fails_to_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    mocks(direct_vm, llm=False)
    direct_vm.mock_llm("RELEASE_POLICY_ALIGNMENT_V1", {"decision": "ship it"})
    with direct_vm.prank(OWNER_B):
        contract.attest_release(0, TAG)
    assert contract.get_attestation(0).state == "REVIEW_REQUIRED"
    assert contract.get_attestation(0).reason_code == "SEMANTIC_RESULT_UNCLEAR"


def test_retry_limit_preserves_all_attempts(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    for number in range(3):
        if number:
            direct_vm.clear_mocks()
        mocks(direct_vm, verdict="PARTIAL", confidence=40)
        with direct_vm.prank(OWNER_B):
            if number == 0:
                contract.attest_release(0, TAG)
            else:
                contract.retry_attest(0)
    before = contract.get_attestation(0)
    with direct_vm.prank(OWNER_B), direct_vm.expect_revert("ATTEMPT_LIMIT_REACHED"):
        contract.retry_attest(0)
    assert contract.get_attestation(0) == before
    assert [contract.get_attempt(0, i).attempt for i in (1, 2, 3)] == [1, 2, 3]


def test_owner_only_and_replay(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    mocks(direct_vm)
    with direct_vm.prank(OTHER_B), direct_vm.expect_revert("CHANNEL_OWNER_ONLY"):
        contract.attest_release(0, TAG)
    with direct_vm.prank(OWNER_B):
        contract.attest_release(0, TAG)
    with direct_vm.prank(OWNER_B), direct_vm.expect_revert("TAG_ALREADY_AUDITED"):
        contract.attest_release(0, TAG)
    with direct_vm.prank(OWNER_B), direct_vm.expect_revert("ATTESTATION_TERMINAL"):
        contract.retry_attest(0)


def test_dispute_can_overturn_a_ruling(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm)                      # ATTESTED / COMPLIANT
    assert contract.get_attestation(0).state == "ATTESTED"
    # Anyone may dispute a terminal ruling.
    with direct_vm.prank(OTHER_B):
        contract.dispute(0, COUNTER_URL, "notes hid a breaking change")
    assert contract.get_attestation(0).state == "DISPUTED"
    assert contract.get_channel(0).open_disputes == 1
    direct_vm.clear_mocks()
    mocks(direct_vm, llm=False)
    direct_vm.mock_web(COUNTER_PATTERN, {"method": "GET", "status": 200,
                                         "body": "Proof: the release silently dropped a public method."})
    direct_vm.mock_llm("RELEASE_POLICY_ALIGNMENT_V1", {"verdict": "VIOLATION", "confidence": 88})
    with direct_vm.prank(OTHER_B):
        contract.resolve_dispute(0)
    resolved = contract.get_attestation(0)
    assert resolved.state == "OVERTURNED"
    assert resolved.verdict == "VIOLATION"
    assert resolved.reason_code == "DISPUTE_OVERTURNED"
    assert contract.get_channel(0).open_disputes == 0
    assert contract.get_attempt(0, 2).kind == "APPEAL"
    assert contract.get_attempt(0, 2).overturned == "YES"


def test_dispute_upheld_keeps_verdict(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm)
    with direct_vm.prank(OTHER_B):
        contract.dispute(0, COUNTER_URL, "please re-check the notes")
    direct_vm.clear_mocks()
    mocks(direct_vm, llm=False)
    direct_vm.mock_web(COUNTER_PATTERN, {"method": "GET", "status": 200, "body": "No new evidence here."})
    direct_vm.mock_llm("RELEASE_POLICY_ALIGNMENT_V1", {"verdict": "COMPLIANT", "confidence": 90})
    with direct_vm.prank(OWNER_B):
        contract.resolve_dispute(0)
    resolved = contract.get_attestation(0)
    assert resolved.state == "UPHELD"
    assert resolved.verdict == "COMPLIANT"
    assert resolved.reason_code == "DISPUTE_UPHELD"


def test_close_requires_owner_window_and_no_outstanding(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm)
    with direct_vm.prank(OTHER_B), direct_vm.expect_revert("CHANNEL_OWNER_ONLY"):
        contract.close_channel(0)
    with direct_vm.prank(OWNER_B), direct_vm.expect_revert("CHANNEL_STILL_ACTIVE"):
        contract.close_channel(0)
    direct_vm.warp(AFTER_ISO)
    with direct_vm.prank(OWNER_B):
        contract.close_channel(0)
    assert contract.get_channel(0).state == "CLOSED"


def test_close_rejects_unresolved_review(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm, verdict="PARTIAL", confidence=40)
    assert contract.get_channel(0).unresolved == 1
    direct_vm.warp(AFTER_ISO)
    with direct_vm.prank(OWNER_B), direct_vm.expect_revert("ATTESTATION_OUTSTANDING"):
        contract.close_channel(0)


def test_validator_refetches_and_rejects_changed_sources(direct_vm, direct_deploy):
    contract = deploy(direct_vm, direct_deploy)
    open_channel(contract, direct_vm)
    attest(contract, direct_vm)
    assert direct_vm.run_validator() is True
    keys = ("source_status", "tag_binding", "author_binding", "publication_binding",
            "timing_binding", "asset_binding", "policy_binding", "policy_alignment",
            "confidence_band", "evidence_digest", "published_at")
    attempt = contract.get_attempt(0, 1)
    leader = {k: getattr(attempt, k) for k in keys}
    leader["confidence_band"] = int(leader["confidence_band"])
    leader["published_at"] = int(leader["published_at"])
    direct_vm.clear_mocks()
    mocks(direct_vm, policy=POLICY + " mutated")
    assert direct_vm.run_validator(leader_result=leader) is False


def test_source_has_no_arbitrary_url_admin_or_custody():
    source = open(CONTRACT, encoding="utf-8").read()
    assert source.startswith('# v0.2.16\n# { "Depends": "py-genlayer:')
    assert "api.github.com" in source
    assert "raw.githubusercontent.com" in source
    assert "run_nondet_unsafe" in source
    assert "@gl.public.write.payable" not in source
    assert "emit_transfer" not in source
    for forbidden in ("set_admin", "set_source", "submitted_result"):
        assert forbidden not in source
