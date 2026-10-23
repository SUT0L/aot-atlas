from copy import deepcopy

from compatibility_checks import facts, preserve


def reject(expected, actual, label):
    try:
        preserve(facts(expected), facts(actual), label, set())
    except AssertionError:
        return
    raise RuntimeError(f"Compatibility comparison accepted changed {label}")


baseline = {
    "extraction_stages": {
        "dictionary_signatures": "complete",
        "dictionary_bindings": "available",
    },
    "fields": [{
        "signature_context": {
            "type_signature_id": 7,
            "type_arguments": [{"kind": "RuntimeType", "type_address": 0x140001000}],
            "method_arguments": [],
        },
    }],
    "allocated_bytes": 1024,
    "analysis_seconds": 0.1,
}

changed = deepcopy(baseline)
changed["extraction_stages"]["dictionary_bindings"] = "unavailable"
reject(baseline, changed, "extraction status")

changed = deepcopy(baseline)
changed["fields"][0]["signature_context"]["type_arguments"][0]["type_address"] += 8
reject(baseline, changed, "signature context")

changed = deepcopy(baseline)
changed["allocated_bytes"] *= 2
changed["analysis_seconds"] *= 2
preserve(facts(baseline), facts(changed), "measurements", set())

print("Compatibility comparison rejects changed statuses and signature contexts while ignoring measurements.")
