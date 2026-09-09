# ReleaseProvenanceAttestor

A reusable **GenLayer Intelligent Contract** primitive for open-source and
supply-chain **release governance**. It decides — on-chain, with a decentralized
LLM jury — whether a published GitHub release is authorized *and* whether its
notes honour a sealed, human-language security policy, and it exposes a
permissionless **appeal** path that can overturn a ruling.

- **Network:** GenLayer studionet (chain id `61999`, rpc `https://studio.genlayer.com/api`)
- **Live contract:** [`0x7D63C69f23e4362974E2831b3F6926935B327cC4`](https://studio.genlayer.com/contracts)
- **Contribution type:** Builder → Intelligent Contracts (standalone primitive, no frontend)

---

## Why this needs GenLayer (and Solidity can't do it)

A release is *partly* a machine fact (right tag, allow-listed maintainer,
published, provenance asset attached) and *partly* a judgement call (do the notes
actually disclose the breaking changes and CVEs the policy demands?). The second
half requires reading two live web documents and interpreting natural language —
impossible on a deterministic chain without a trusted oracle.

`ReleaseProvenanceAttestor` reads **both sources directly on-chain** and splits
the decision into two layers:

1. **Deterministic bindings** — computed from the structured **GitHub Releases
   API** with no model in the loop: `tag`, `author` (maintainer allow-list),
   `publication` (published, not draft, prerelease policy), `timing` (inside the
   channel window), `asset` (a required provenance/checksums/SBOM asset is
   present), and `policy` (the policy document still hashes to the sealed
   `sha256`). Any failure ⇒ `NON_COMPLIANT` with a specific reason code.
2. **Meaning consensus** — a decentralized LLM jury reads the release notes
   against the sealed policy text and rules `COMPLIANT | PARTIAL | VIOLATION`
   with a confidence band.

## How consensus is used (the part that isn't a thin wrapper)

The non-deterministic block runs through `gl.vm.run_nondet_unsafe(leader_fn,
validator_fn)` with a **custom validator**. Every validator independently
**refetches both the GitHub release and the policy document** and recomputes the
whole observation. Consensus holds only when **all six deterministic bindings,
the verdict, the confidence band, and the evidence digest match**.

Two validators may write different prose, but they must reach the **same verdict**
to finalize — a `PARTIAL`↔`COMPLIANT` disagreement fails consensus rather than
being averaged. The verdict is compared as a category and the confidence as a
3-level band (`<35 / 35-79 / 80+`), so honest model variation does not break
consensus while a genuine disagreement about *meaning* does.

## Appeal round (backward state transition)

Any account — not just the channel owner — may `dispute` a terminal ruling with a
**counter-evidence URL** and a reason. `resolve_dispute` runs a second jury that
re-reads the release notes together with the counter-evidence page and returns a
fresh verdict. Whether the ruling is **OVERTURNED** is **derived from the verdict
delta**, never trusted from a free-form model flag — that is what makes the
appeal consensus-meaningful. The state machine therefore has a real backward
edge:

```
PENDING ─▶ ATTESTED ─────┐
        └▶ NON_COMPLIANT ─┼─▶ DISPUTED ─▶ OVERTURNED
        └▶ REVIEW_REQUIRED┘             └▶ UPHELD
                 ▲   (retry, bounded by MAX_ATTEMPTS)
```

This is exactly where GenLayer's Optimistic Democracy appeal cycle creates value
a Solidity contract cannot reproduce.

## Public API

| Method | Kind | Purpose |
|---|---|---|
| `open_channel(repo_owner, repo_name, maintainers, policy_commit, policy_path, policy_sha256, required_asset, allow_prerelease, starts_at, ends_at)` | write | Seal a repo + pinned policy + release envelope. Returns `channel_id`. |
| `attest_release(channel_id, tag)` | write | Audit one published release. Returns `attestation_id`. Owner-only, one attestation per `(channel, tag)`. |
| `retry_attest(attestation_id)` | write | Re-run after a transient source/model failure (`REVIEW_REQUIRED`). |
| `dispute(attestation_id, counter_evidence_url, reason)` | write | **Permissionless.** Challenge a terminal ruling with counter-evidence. |
| `resolve_dispute(attestation_id)` | write | Appellate jury; may `OVERTURN` or `UPHOLD`. |
| `close_channel(channel_id)` | write | Owner closes after the window, once nothing is outstanding. |
| `get_config` / `get_channel` / `get_attestation` / `get_attempt` / `list_disputed` | view | Read config, records, and the full per-attempt audit trail. |

## State design

- `channels: TreeMap[u256, Channel]` — sealed policy + envelope + counters
  (`unresolved`, `open_disputes`) that gate `close_channel`.
- `attestations: TreeMap[u256, Attestation]` — one lifecycle per audited release.
- `attempts: TreeMap[str, AttemptRecord]` — append-only audit trail
  (`AUDIT` / `APPEAL`) keyed `"{attestation_id}:{attempt}"`; retries never
  overwrite prior attempts.
- `audited_tags: TreeMap[str, bool]` — replay guard; a `(channel, tag)` is
  audited once.

## Edge cases handled (see tests)

Invalid inputs never create a channel · GitHub 5xx/429 ⇒ retry-safe
`UNAVAILABLE`, 4xx ⇒ `INVALID` · policy digest drift can never authorize ·
draft/prerelease/out-of-window/missing-asset each map to a distinct reason ·
malformed model output fails to `REVIEW_REQUIRED`, never a silent pass ·
attempt-limit and terminal states preserve all prior records · owner-only writes ·
close blocked while any attestation or dispute is outstanding · the validator
rejects a mutated policy on refetch.

## Tests

`tests/test_release_provenance_attestor.py` — **28 tests**, GenLayer Test direct
mode with mocked web + LLM. Run:

```bash
pip install -r requirements.txt
pytest -q
```

## Deploy

```bash
npm install
source ~/.genlayer/env.sh      # exports GENLAYER_PRIVATE_KEY (a funded studionet key)
node scripts/deploy.mjs        # sanity first, then the contract; prints the address
```

The deployer key is read from the shell, never committed. `.env` records the
live studionet address.

## Source layout

```
contracts/release_provenance_attestor.py   # the primitive (ASCII-only, # v0.2.16)
tests/test_release_provenance_attestor.py  # 28 gltest cases
sanity/storage_test.py                     # deploy-first sanity contract
scripts/deploy.mjs                         # studionet deployer
docs/SPECIFICATION.md                      # detailed spec
```
