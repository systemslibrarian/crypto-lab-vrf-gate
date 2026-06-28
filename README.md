# crypto-lab-vrf-gate

## What It Is

This demo combines ECVRF-P256-SHA256 and a Wesolowski VDF over an RSA-style group to show how public randomness can be both verifiable and delayed. The VRF side solves the problem of proving that a deterministic pseudorandom output came from one specific public key and input without exposing the secret key. The VDF side solves the problem of forcing a sequential delay before the final randomness can be known while keeping verification much cheaper than evaluation. The security model is asymmetric and publicly verifiable, uses WebCrypto plus exact BigInt arithmetic, and is not post-quantum secure.

The VRF is **byte-exact RFC 9381** (ciphersuite ECVRF-P256-SHA256-TAI): try-and-increment hash-to-curve, an RFC 6979 deterministic nonce, the `s = k + c·x` response, and SEC1 compressed points. A known-answer test (`npm run check:rfc9381`) reproduces the standard's official Appendix B.1 test vector — H, k, U, V, π, and β all match — and runs in CI before every deploy, so the outputs here would be accepted by any conforming verifier. The VDF is an intentionally small "toy" Wesolowski construction for in-browser speed; production VDFs use 2048-bit RSA moduli or class groups of unknown order. Each exhibit has a layered **"See the math"** panel that exposes these intermediate values live.

## When to Use It

- Use it to teach validator selection or randomness beacons in proof-of-stake systems. The demo shows why a VRF gives unique verifiable contributions while a VDF delays strategic prediction.
- Use it to compare deterministic public-key randomness against plain hashing. The VRF exhibit shows that the same key and input always yield the same verifiable output, which a plain hash cannot restrict to one producer.
- Use it to explain last-reveal bias in commit-reveal protocols. The beacon simulation shows how withholding changes the RANDAO branch and why the VDF turns that into a blind choice.
- Use it to inspect toy VDF timing and proof verification tradeoffs. The VDF exhibit exposes the delay parameter slider, progress bar, and proof verification path directly in the browser.
- Do NOT use it as a production cryptography library. The implementation is educational, uses a toy RSA-style modulus for the VDF, and is not a post-quantum-secure or hardened deployment package.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-vrf-gate](https://systemslibrarian.github.io/crypto-lab-vrf-gate/)**

In the browser you can generate and verify VRF outputs, run the VDF with a live delay progress bar, and simulate a RANDAO-style beacon round with optional malicious withholding. The demo exposes the VRF input field, the VDF delay slider, the validator-count slider, and the malicious-validator toggle so the user can change parameters and observe the proof flow directly. There is no encrypt/decrypt path in this demo because the code is about verifiable randomness and delay, not confidentiality.

## What Can Go Wrong

- A VRF needs a unique, secret-derived nonce; a biased or reused nonce in the `s = k + c·x` response can leak the secret key, the same class of failure that breaks ECDSA.
- Hash-to-curve must be implemented carefully (try-and-increment, correct ciphersuite tag); a flawed mapping can bias outputs or break verifier interoperability.
- The toy Wesolowski VDF here uses a small modulus and offers no real delay guarantee; a production VDF needs a 2048-bit RSA modulus or a class group of unknown order.
- VDF security assumes inherently sequential computation; specialized or parallel hardware can shrink the intended delay below the protocol's assumptions.
- In commit-reveal beacons the last participant to reveal can choose to withhold and bias the result — the "last-revealer" problem a VDF is meant to neutralize.

## Real-World Usage

- Proof-of-stake leader and committee selection: protocols such as Algorand and Cardano's Ouroboros Praos use VRFs to pick block proposers verifiably and unpredictably.
- On-chain randomness services: Chainlink VRF supplies smart contracts with publicly verifiable random values for games, NFTs, and sampling.
- Ethereum's beacon chain uses RANDAO commit-reveal randomness, with VDFs long studied as a way to remove the last-revealer bias.
- Verifiable delay functions are also explored for timestamping, proof-of-replication, and other applications needing publicly checkable elapsed time.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-vrf-gate
cd crypto-lab-vrf-gate
npm install
npm run dev
```

## Related Demos
- [crypto-lab-drbg-arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) — deterministic random bit generators, the NIST SP 800-90A side of randomness.
- [crypto-lab-corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — what happens when a random number generator is backdoored or biased.
- [crypto-lab-commit-gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/) — the commitment schemes behind commit-reveal randomness beacons.

## Verification

```bash
npm run check   # phase logic checks + RFC 9381 known-answer test
npm run e2e     # headless Chromium: drives the real UI + axe accessibility scan
```

`npm run check` proves the VRF reproduces the RFC 9381 Appendix B.1 vector. `npm run e2e` builds the app, boots it in headless Chromium, exercises VRF compute/verify/tamper and VDF evaluate/verify, asserts no console errors and no horizontal overflow at a 360px viewport, and runs an [axe-core](https://github.com/dequelabs/axe-core) accessibility scan (WCAG 2.0/2.1 A + AA) in both dark and light themes — currently zero violations. Both run in CI before every deploy.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
