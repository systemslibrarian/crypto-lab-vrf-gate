# crypto-lab-vrf-gate

## What It Is

This demo combines ECVRF-P256-SHA256 and a Wesolowski VDF over an RSA-style group to show how public randomness can be both verifiable and delayed. The VRF side solves the problem of proving that a deterministic pseudorandom output came from one specific public key and input without exposing the secret key. The VDF side solves the problem of forcing a sequential delay before the final randomness can be known while keeping verification much cheaper than evaluation. The security model is asymmetric and publicly verifiable, uses WebCrypto plus exact BigInt arithmetic, and is not post-quantum secure.

The VRF is **byte-exact RFC 9381** (ciphersuite ECVRF-P256-SHA256-TAI): try-and-increment hash-to-curve, an RFC 6979 deterministic nonce, the `s = k + c·x` response, and SEC1 compressed points. A known-answer test (`npm run check:rfc9381`) reproduces the standard's official Appendix B.1 test vector — H, k, U, V, π, and β all match — and runs in CI before every deploy, so the outputs here would be accepted by any conforming verifier. The VDF is an intentionally small "toy" Wesolowski construction for in-browser speed; production VDFs use 2048-bit RSA moduli or class groups of unknown order. Each exhibit has a layered **"See the math"** panel that exposes these intermediate values live.

## When to Use It

- Use it to teach validator selection or randomness beacons in proof-of-stake systems. The demo shows why a VRF gives unique verifiable contributions while a VDF delays strategic prediction.
- Use it to compare deterministic public-key randomness against plain hashing. The VRF exhibit shows that the same key and input always yield the same verifiable output, which a plain hash cannot restrict to one producer.
- Use it to explain last-reveal bias in commit-reveal protocols. The beacon simulation shows how withholding changes the RANDAO branch and why the VDF turns that into a blind choice.
- Use it to inspect toy VDF timing and proof verification tradeoffs. The VDF exhibit exposes the delay parameter slider, progress bar, and proof verification path directly in the browser.
- Do not use it as a production cryptography library. The implementation is educational, uses a toy RSA-style modulus for the VDF, and is not a post-quantum-secure or hardened deployment package.

## Live Demo

[Live demo](https://systemslibrarian.github.io/crypto-lab-vrf-gate/)

In the browser you can generate and verify VRF outputs, run the VDF with a live delay progress bar, and simulate a RANDAO-style beacon round with optional malicious withholding. The demo exposes the VRF input field, the VDF delay slider, the validator-count slider, and the malicious-validator toggle so the user can change parameters and observe the proof flow directly. There is no encrypt/decrypt path in this demo because the code is about verifiable randomness and delay, not confidentiality.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-vrf-gate
cd crypto-lab-vrf-gate
npm install
npm run dev
```

There are no environment variables.

## Verification

```bash
npm run check   # phase logic checks + RFC 9381 known-answer test
npm run e2e     # headless Chromium: drives the real UI + axe accessibility scan
```

`npm run check` proves the VRF reproduces the RFC 9381 Appendix B.1 vector. `npm run e2e` builds the app, boots it in headless Chromium, exercises VRF compute/verify/tamper and VDF evaluate/verify, asserts no console errors and no horizontal overflow at a 360px viewport, and runs an [axe-core](https://github.com/dequelabs/axe-core) accessibility scan (WCAG 2.0/2.1 A + AA) in both dark and light themes — currently zero violations. Both run in CI before every deploy.

## Part of the Crypto-Lab Suite

One of 60+ live browser demos at [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*