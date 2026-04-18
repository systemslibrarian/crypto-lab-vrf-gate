# crypto-lab-vrf-gate

Browser-based demo of Verifiable Random Functions (VRFs, RFC 9381) and Verifiable Delay Functions (VDFs, Wesolowski 2018) — the cryptographic primitives behind Ethereum's randomness beacon research, Chainlink VRF-style public randomness, Filecoin leader election, and Cardano's Ouroboros protocol.

## What It Is

A VRF is a public-key hash: only the keyholder can compute the output, but anyone can verify it. Deterministic yet pseudorandom. This repo implements an educational ECVRF-inspired flow over P-256 with try-and-increment hash-to-curve, Schnorr-style proof equations, and SHA-256 output hashing. Key generation, hashing, randomness, and ECDH cross-checks use WebCrypto. Full point arithmetic is implemented directly in TypeScript because WebCrypto does not expose general point addition or arbitrary-point scalar multiplication transcripts needed for full proof verification.

A VDF requires sequential work to evaluate but much less work to verify. This repo implements repeated squaring over a toy RSA-style modulus with exact BigInt arithmetic and a simplified Wesolowski proof flow:

- Evaluation: $y = g^{2^T} \bmod N$ via actual repeated squaring
- Proof: derive $\ell$ as the first prime at or above $H(g, y, T)$ and compute the quotient exponent for $\pi$
- Verification: check $\pi^\ell \cdot g^r \equiv y \pmod N$ where $r = 2^T \bmod \ell$

The demo then combines VRF outputs into a RANDAO-style XOR mix and delays the final public randomness with a VDF so that withholding remains a blind choice instead of an informed one.

## When to Use It

- Understanding why blockchain randomness cannot safely rely on timestamps, blockhashes, or plain commit-reveal
- Teaching the difference between key-based unpredictability and time-based unpredictability
- Demonstrating why a VDF delay must exceed the period in which an attacker can still choose to reveal or withhold
- Showing that VRF determinism and VDF sequentiality solve different parts of the randomness problem

## Live Demo

https://systemslibrarian.github.io/crypto-lab-vrf-gate/

## What Can Go Wrong

- This is an educational ECVRF-inspired implementation, not a production RFC 9381 conformance library. Browser APIs do not expose all low-level elliptic-curve operations directly, so the full proof transcript uses explicit P-256 point arithmetic in TypeScript with WebCrypto used for key material, hashing, randomness, and ECDH x-coordinate validation.
- The hash-to-curve step uses try-and-increment over P-256 in the spirit of RFC 9381, but production deployments need a carefully reviewed, constant-time implementation and full RFC validation rules.
- The VDF uses a toy modulus for browser speed. Real deployments use much larger groups and much slower sequential evaluation than this demo.
- The Wesolowski proof path here is honest about its simplification: it uses a practical first-prime-above-hash construction rather than a full formal hash-to-prime proof system.
- A malicious validator who withholds still has residual bias: they choose between $2^k$ branches where $k$ is the number of validators they control. The VDF prevents them from knowing which branch they prefer before the delay completes, but it does not make withholding impossible.
- Neither primitive shown here is post-quantum secure. P-256 and RSA-style groups are both vulnerable to Shor's algorithm. Post-quantum VDFs remain an open research problem as of 2026.

## Real-World Usage

RFC 9381 standardized modern ECVRF ciphersuites in 2023. Cardano Ouroboros uses VRFs for slot leadership, Filecoin uses VRFs for leader election, and Algorand uses VRF-style private committee selection. Chainlink VRF uses a similar verifiable-randomness model for on-chain applications across multiple networks.

Ethereum's beacon chain uses RANDAO today. The idea of adding a VDF to reduce last-reveal advantages remains part of the broader Ethereum randomness and VDF research conversation rather than a universally deployed mainnet reality. That distinction matters: RANDAO is production, VDF integration is still a harder engineering and hardware problem.

## Development

- Install dependencies: `npm install`
- Run the app: `npm run dev`
- Build for GitHub Pages: `npm run build`
- Run primitive checks: `npm run check:phase1`, `npm run check:phase2`, `npm run check:phase3`

## Repository Description

Browser-based VRF and VDF demo (RFC 9381-inspired) — ECVRF P-256 prove/verify, Wesolowski-style VDF repeated squaring with proof, RANDAO+VDF randomness beacon simulation with last-reveal attack and VDF protection. Chainlink VRF, Ethereum RANDAO, Filecoin leader election. No backends. No simulated math shortcuts.

## Suggested GitHub Topics

- cryptography
- vrf
- vdf
- verifiable-random-function
- verifiable-delay-function
- blockchain
- randomness-beacon
- ethereum
- chainlink
- ecvrf
- rfc9381
- browser-demo
- educational
- typescript
- vite