# Design decisions & interview Q&A

Short answers you should be able to give *without looking at the code*.

**1. Why does the proxy hold only public keys?**
So compromising the proxy does not let an attacker impersonate services. Identity = possession of a private key that matches a registered public key (the SPIFFE/mTLS trust model). There is deliberately **no** endpoint that mints tokens for a service.

**2. Why Ed25519 instead of RSA or HMAC?**
Small keys/signatures, fast signing and verification, no parameter pitfalls. HMAC (HS256) would need a *shared* secret on the proxy, which breaks point 1. Note: Ed25519 is *not* quantum-resistant (Shor's algorithm breaks elliptic curves) — don't claim it is.

**3. What is "algorithm pinning" and which attacks does it stop?**
The verifier uses its own allow-list (`EdDSA`) and never trusts the token's `alg` header. That stops `alg=none` (no signature) and the HS256-confusion attack (signing with the public key as an HMAC secret). Both are reproduced in the simulator.

**4. Why single-use tokens?**
A stolen bearer token is otherwise valid until expiry. With a jti store, a replay is rejected. Cost: a store lookup per request, and services must sign a fresh token per call (Ed25519 signing is microseconds). The replay check runs *after* signature verification so an attacker cannot burn someone else's jti with forged tokens.

**5. What breaks with multiple proxy replicas?**
The jti store, rate limiter, risk state and quarantine are in-memory, i.e. per process. Horizontally scaling needs shared state; for jti it is one atomic Redis command (`SET jti 1 NX EXAT exp`). The `JtiStore` interface exists for exactly this swap.

**6. How is the risk score computed — is it ML?**
No. It is a sum of named, additive factors (see `src/risk/riskEngine.ts`), so every score is explainable. Hard failures (bad signature, replay, no policy) skip scoring and are rejected with a fixed severity. I chose explainability over a model because I have no labelled attack data and a security team must be able to justify a block.

**7. Why is lateral movement a separate hard rule instead of just +50 points?**
A pivoting attacker could otherwise stay under the block threshold by keeping other factors low. A rule guarantees containment for that pattern.

**8. What are the false-positive risks?**
(a) A legitimately deep, fast call chain can look like lateral movement — tune `lateral.minHops/windowMs`. (b) Auto-quarantine takes a healthy service offline on a false positive — hence short duration + manual release. (c) The statistical payload check needs history and only learns from unflagged payloads (to avoid baseline poisoning).

**9. Why can't someone frame a service by sending forged tokens in its name?**
Auth failures are tracked per **IP**, not per claimed service id, and quarantine only happens after identity is *verified*. There is a test for this.

**10. What does the audit hash chain prove — and not prove?**
It makes edits/deletions inside the retained window detectable (each hash covers the previous one). It cannot prove the newest entries weren't truncated; for that you'd ship periodic checkpoint hashes to external write-once storage.

**11. Why TOTP implemented by hand?**
~40 lines, no dependency, verified against the RFC 4226/6238 test vectors, and codes are single-use (RFC 6238 §5.2).

**12. What would you do next?**
mTLS between proxy and services, Redis-backed state, policy hot-reload from a signed file, OpenTelemetry traces, and replace the fixed-window limiter with a token bucket.
