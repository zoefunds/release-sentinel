import ast
from pathlib import Path


SOURCE = Path(__file__).parents[2] / "contracts" / "release_sentinel.py"


def _tree():
    return ast.parse(SOURCE.read_text())


def _contract():
    return next(
        node
        for node in _tree().body
        if isinstance(node, ast.ClassDef) and node.name == "ReleaseSentinel"
    )


def test_contract_parses_and_has_expected_storage():
    contract = _contract()
    annotations = {
        node.target.id: ast.unparse(node.annotation)
        for node in contract.body
        if isinstance(node, ast.AnnAssign)
    }
    assert annotations == {
        "steward": "Address",
        "voyage_count": "u256",
        "voyages": "TreeMap[str, str]",
        "routes": "TreeMap[str, str]",
        "observations": "TreeMap[str, str]",
        "attempts": "TreeMap[str, str]",
        "disputes": "TreeMap[str, str]",
        "notarizations": "TreeMap[str, str]",
        "events": "TreeMap[str, str]",
        "event_count": "u256",
    }


def test_public_api_is_complete():
    methods = {node.name for node in _contract().body if isinstance(node, ast.FunctionDef)}
    assert {
        "open_voyage",
        "discover_chart",
        "add_route",
        "anchor_baseline",
        "seal_chart",
        "bind_candidate",
        "observe_route",
        "derive_readiness",
        "open_dispute",
        "notarize",
        "get_protocol_identity",
        "get_voyage",
        "get_route",
        "get_observation",
        "get_dispute",
        "get_notarization",
        "list_voyages",
        "get_events",
    } <= methods


def test_contract_identity_is_fully_renamed():
    source = SOURCE.read_text()
    assert "harborlight" not in source.lower()
    assert 'PROTOCOL_ID="release-sentinel.release-notary.v1"' in source
    assert '"release-sentinel.manifest.v1"' in source
    assert '/.well-known/release-sentinel.json' in source
    for rule_id in ("rs-security", "rs-function", "rs-claims", "rs-access"):
        assert rule_id in source


def test_consensus_time_and_nondeterministic_validators_are_guarded():
    source = SOURCE.read_text()
    assert 'gl.message_raw["datetime"]' in source
    assert "datetime.now" not in source
    assert source.count("gl.vm.run_nondet_unsafe(leader,validator)") == 6
    assert source.count("isinstance(result,gl.vm.Return)") >= 5


def test_limits_and_terminal_notarization_guards_are_present():
    source = SOURCE.read_text()
    assert "count>=MAX_ATTEMPTS" in source
    assert "count>=MAX_DISPUTES" in source
    assert 'v["state"]!="CLEAR" or v["open_dispute"]' in source
    assert 'v["observed_generation"]!=v["generation"]' in source
    assert '_now()<v["review_deadline"]' in source


def test_add_route_accepts_native_rule_list():
    method = next(node for node in _contract().body if isinstance(node, ast.FunctionDef) and node.name == "add_route")
    annotations = {arg.arg: ast.unparse(arg.annotation) for arg in method.args.args if arg.annotation}
    assert annotations["custom_rules"] == "list"
    assert "custom_rules_json" not in SOURCE.read_text()
