# ReleaseProvenanceAttestor — Specification

`VERSION = "RELEASE_PROVENANCE_ATTESTOR_V1"` · header `# v0.2.16` · ASCII-only.

## Sources

| Source | URL | Read as |
|---|---|---|
| GitHub Releases API | `https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}` | structured JSON (`gl.nondet.web.get`) |
| Sealed policy doc | `https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{path}` | text, pinned by `sha256` |

Both hosts are compile-time constants; the contract accepts no arbitrary URL for
the primary evidence. Counter-evidence in the appeal round is a caller-supplied
`https://` URL (validated), used only as *additional* context.

## Deterministic bindings (GitHub API → MATCH/MISMATCH)

| Binding | Rule | Failure reason |
|---|---|---|
| `tag_binding` | `tag_name == requested tag` | `TAG_MISMATCH` |
| `author_binding` | `author.login` ∈ maintainer allow-list | `AUTHOR_NOT_ALLOWED` |
| `publication_binding` | not draft, prerelease allowed only if opted-in, `published_at` present | `NOT_PUBLISHED` |
| `timing_binding` | `max(starts_at, created_at) ≤ published_at ≤ ends_at` | `OUTSIDE_CHANNEL_WINDOW` |
| `asset_binding` | some asset name contains `required_asset` (`""` = no requirement) | `PROVENANCE_ASSET_MISSING` |
| `policy_binding` | `sha256(policy) == policy_sha256` | `POLICY_DIGEST_MISMATCH` |

## Meaning layer (LLM)

Prompt tag `RELEASE_POLICY_ALIGNMENT_V1`. Returns
`{"verdict": COMPLIANT|PARTIAL|VIOLATION, "confidence": 0-100}`. Verdict is
normalized; confidence is bucketed to a band `0:<35 / 1:35-79 / 2:80+`. Policy
and notes are labelled untrusted data in the prompt (prompt-injection resistant).

## Consensus (`run_nondet_unsafe`)

Observation dict compared field-by-field by the validator after an independent
refetch of both sources:

```
source_status, tag_binding, author_binding, publication_binding,
timing_binding, asset_binding, policy_binding, policy_alignment,
confidence_band, evidence_digest, published_at
```

`evidence_digest = sha256(canonical(release_facts, policy_sha256))`. A transient
GitHub/policy 5xx/429 ⇒ `UNAVAILABLE`; any other failure ⇒ `INVALID`; both yield
an all-`UNCLEAR` observation ⇒ `REVIEW_REQUIRED` (retry-safe).

## Derivation

```
source != VERIFIED                      -> REVIEW_REQUIRED / SOURCE_NOT_VERIFIED
any binding != MATCH                     -> NON_COMPLIANT  / <binding reason>
verdict == VIOLATION                     -> NON_COMPLIANT  / POLICY_VIOLATION
verdict != COMPLIANT                     -> REVIEW_REQUIRED / SEMANTIC_RESULT_UNCLEAR
else                                     -> ATTESTED       / RELEASE_COMPLIANT
```

## Appeal (full re-audit, deterministic bindings re-enforced)

`dispute` (permissionless) moves a terminal ruling to `DISPUTED`, records a
counter-evidence URL, and resets `resolve_attempts`. It is allowed only when
`effective_state ∈ {ATTESTED, NON_COMPLIANT}`.

`resolve_dispute` calls the **same** `_observe` (with `counter_url` set), so the
validators re-fetch release + policy, recompute **all six deterministic
bindings**, and fold the counter page into the semantic prompt. The result is run
through the **same `_derive()`**:

```
appeal source != VERIFIED  -> record APPEAL attempt; resolve_attempts += 1;
                              if resolve_attempts >= MAX_APPEAL_ATTEMPTS
                                  -> state=UPHELD, reason=DISPUTE_ABANDONED_UNVERIFIABLE,
                                     open_disputes -= 1   (bounded terminal recovery)
                              else stay DISPUTED (retry when the source recovers)
derive == REVIEW_REQUIRED   -> UPHELD / DISPUTE_INCONCLUSIVE  (an unclear appeal cannot overturn)
derive terminal (ATTESTED|NON_COMPLIANT):
    new == effective_state  -> UPHELD  (effective_state unchanged)
    new != effective_state  -> OVERTURNED, effective_state := new, reason := derive reason
```

Because the appeal derives through the bindings, a NON_COMPLIANT caused by a
deterministic failure (e.g. `AUTHOR_NOT_ALLOWED`, `POLICY_DIGEST_MISMATCH`) can
only become `ATTESTED` if that binding actually passes on refetch — a semantic
"COMPLIANT" alone can never overturn it.

## Terminal recovery (no stuck state)

- `abandon_review(attestation_id)` — owner-only; when `state == REVIEW_REQUIRED`
  and `attempt_count >= MAX_ATTEMPTS`, retires it to terminal `ABANDONED` and
  decrements `unresolved`.
- Unverifiable dispute — auto-`UPHELD` after `MAX_APPEAL_ATTEMPTS`, decrementing
  `open_disputes`.

Together these guarantee `close_channel`'s `unresolved == 0` and
`open_disputes == 0` gates are always reachable.

## Limits

`MAX_ATTEMPTS=3`, `MAX_DISPUTES=3`, `MAX_APPEAL_ATTEMPTS=3`, window ≤ 180 days,
≤ 20 maintainers, policy ≤ 32 KiB, release JSON ≤ 256 KiB, counter ≤ 64 KiB. No
payable methods, no custody, no admin setter, no mutable source configuration
after `open_channel`.
