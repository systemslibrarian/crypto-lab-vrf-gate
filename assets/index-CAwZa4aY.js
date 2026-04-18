(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))a(r);new MutationObserver(r=>{for(const o of r)if(o.type==="childList")for(const i of o.addedNodes)i.tagName==="LINK"&&i.rel==="modulepreload"&&a(i)}).observe(document,{childList:!0,subtree:!0});function n(r){const o={};return r.integrity&&(o.integrity=r.integrity),r.referrerPolicy&&(o.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?o.credentials="include":r.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function a(r){if(r.ep)return;r.ep=!0;const o=n(r);fetch(r.href,o)}})();function B(...e){const t=e.reduce((r,o)=>r+o.length,0),n=new Uint8Array(t);let a=0;for(const r of e)n.set(r,a),a+=r.length;return n}function w(e){return Array.from(e,t=>t.toString(16).padStart(2,"0")).join("")}function P(e){const t=e.trim().replace(/^0x/,"").toLowerCase();if(t.length===0)return new Uint8Array;if(t.length%2!==0||/[^0-9a-f]/.test(t))throw new Error("Invalid hex string");const n=new Uint8Array(t.length/2);for(let a=0;a<n.length;a+=1)n[a]=Number.parseInt(t.slice(a*2,a*2+2),16);return n}function A(e){return new TextEncoder().encode(e)}function k(e){let t=0n;for(const n of e)t=t<<8n|BigInt(n);return t}function F(e,t){if(e<0n)throw new Error("Negative bigint values are not supported");const n=[];let a=e;for(;a>0n;)n.unshift(Number(a&0xffn)),a>>=8n;const r=Uint8Array.from(n.length>0?n:[0]);if(t===void 0)return r;if(r.length>t)throw new Error("BigInt does not fit in requested size");const o=new Uint8Array(t);return o.set(r,t-r.length),o}function E(e,t){if(e.length!==t.length)return!1;let n=0;for(let a=0;a<e.length;a+=1)n|=e[a]^t[a];return n===0}function J(e){if(e.length===0)return new Uint8Array;const t=e[0].length,n=new Uint8Array(t);for(const a of e){if(a.length!==t)throw new Error("XOR inputs must have equal length");for(let r=0;r<t;r+=1)n[r]^=a[r]}return n}function ke(e,t){if(!Number.isInteger(e)||e<0)throw new Error("Expected a non-negative integer");const n=new Uint8Array(t);let a=e;for(let r=t-1;r>=0;r-=1)n[r]=a&255,a>>>=8;if(a!==0)throw new Error("Integer does not fit in requested size");return n}const f=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,Q=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,Ve=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,C=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,Z={x:0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,y:0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n};function d(e,t){const n=e%t;return n>=0n?n:n+t}function Ae(e,t,n){let a=1n,r=d(e,n),o=t;for(;o>0n;)(o&1n)===1n&&(a=d(a*r,n)),r=d(r*r,n),o>>=1n;return a}function ee(e,t){let n=0n,a=1n,r=t,o=d(e,t);for(;o!==0n;){const i=r/o;[n,a]=[a,n-i*a],[r,o]=[o,r-i*o]}if(r!==1n)throw new Error("Value is not invertible");return d(n,t)}function Fe(e){const t=Ae(e,f+1n>>2n,f);return d(t*t,f)===d(e,f)?t:null}function te(e){if(e.x<0n||e.x>=f||e.y<0n||e.y>=f)return!1;const t=d(e.y*e.y,f),n=d(e.x*e.x*e.x+Q*e.x+Ve,f);return t===n}function K(e,t){if(e===null)return t;if(t===null)return e;if(e.x===t.x)return d(e.y+t.y,f)===0n?null:ne(e);const n=d((t.y-e.y)*ee(t.x-e.x,f),f),a=d(n*n-e.x-t.x,f),r=d(n*(e.x-a)-e.y,f);return{x:a,y:r}}function ne(e){if(e===null||e.y===0n)return null;const t=d((3n*e.x*e.x+Q)*ee(2n*e.y,f),f),n=d(t*t-2n*e.x,f),a=d(t*(e.x-n)-e.y,f);return{x:n,y:a}}function R(e,t){if(t===null||e===0n)return null;let n=null,a=t,r=d(e,C);for(;r>0n;)(r&1n)===1n&&(n=K(n,a)),a=ne(a),r>>=1n;return n}function D(e){const t=new Uint8Array(65);return t[0]=4,t.set(F(e.x,32),1),t.set(F(e.y,32),33),t}function q(e){if(e.length!==65||e[0]!==4)throw new Error("Expected uncompressed P-256 point bytes");const t={x:k(e.slice(1,33)),y:k(e.slice(33,65))};if(!te(t))throw new Error("Point is not on the P-256 curve");return t}function Re(e){return F(d(e,C),32)}function ae(e){const t=k(e);if(t<=0n||t>=C)throw new Error("Invalid scalar encoding");return t}const re=A("ECVRF-P256-SHA256"),Ee=A("ECVRF_proof_to_hash");function oe(e){const t=new Uint8Array(e.length);return t.set(e),t.buffer}async function Y(...e){const t=await crypto.subtle.digest("SHA-256",oe(B(...e)));return new Uint8Array(t)}function T(e,t){if(e===null)throw new Error(`${t} is the point at infinity`);return e}async function Pe(e){const t=await crypto.subtle.exportKey("jwk",e);if(typeof t.d!="string")throw new Error("Private key scalar is unavailable");return ae(De(t.d))}function De(e){const t=e.replace(/-/g,"+").replace(/_/g,"/"),n=t.padEnd(Math.ceil(t.length/4)*4,"="),a=atob(n),r=new Uint8Array(a.length);for(let o=0;o<a.length;o+=1)r[o]=a.charCodeAt(o);return r}async function Te(e){return crypto.subtle.importKey("raw",oe(e),{name:"ECDH",namedCurve:"P-256"},!0,[])}async function $e(e,t){const n=await Te(t),a=await crypto.subtle.deriveBits({name:"ECDH",public:n},e,256);return new Uint8Array(a)}async function Ce(e,t,n){const a=await $e(e,t),r=F(n.x,32);if(!E(a,r))throw new Error("WebCrypto ECDH cross-check failed")}async function Ne(){const e=new Uint8Array(32);for(;;){crypto.getRandomValues(e);const t=d(k(e),C);if(t!==0n)return t}}async function se(){const e=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},!0,["deriveBits"]),t=new Uint8Array(await crypto.subtle.exportKey("raw",e.publicKey));return{privateKey:e.privateKey,publicKey:e.publicKey,publicKeyBytes:t}}async function ie(e,t){for(let n=0;n<65536;n+=1){const a=await Y(re,e,t,ke(n,4)),r=d(k(a),f),o=d(r*r*r-3n*r+0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,f),i=Fe(o);if(i!==null){const l={x:r,y:(i&1n)===0n?i:f-i};if(te(l))return D(l)}}throw new Error("hashToCurve failed after exhausting try-and-increment counters")}async function ce(e,t,n,a){return(await Y(re,new Uint8Array([2]),e,t,n,a)).slice(0,16)}async function j(e){return Y(Ee,e)}async function L(e,t){const n=await Pe(e.privateKey),a=await ie(e.publicKeyBytes,t),r=q(a),o=T(R(n,r),"Gamma");await Ce(e.privateKey,a,o);const i=await Ne(),l=T(R(i,Z),"U"),v=D(l),h=T(R(i,r),"V"),m=D(o),V=D(h),p=await ce(a,m,v,V),y=k(p),N=Re(d(i-y*n,C)),g=await j(m);return{alpha:t.slice(),beta:g,proof:{gamma:m,c:p,s:N}}}async function le(e,t,n){try{const a=q(e),r=await ie(e,t),o=q(r),i=q(n.proof.gamma),l=ae(n.proof.s),v=k(n.proof.c),h=T(K(R(l,Z),R(v,a)),"U"),m=T(K(R(l,o),R(v,i)),"V"),V=await ce(r,n.proof.gamma,D(h),D(m)),p=await j(n.proof.gamma),y=E(V,n.proof.c)&&E(p,n.beta);return y?{valid:y,beta:p}:{valid:y}}catch{return{valid:!1}}}function x(e,t){const n=e%t;return n>=0n?n:n+t}function $(e,t,n){if(n<=1n)throw new Error("Modulus must be greater than 1");let a=1n,r=x(e,n),o=t;for(;o>0n;)(o&1n)===1n&&(a=x(a*r,n)),r=x(r*r,n),o>>=1n;return a}function Se(e,t,n,a){if(!Number.isInteger(n)||n<0)throw new Error("Squaring count must be a non-negative integer");let r=x(e,t);const o=Math.max(1,Math.floor(n/100));for(let i=0;i<n;i+=1)r=x(r*r,t),a&&(i+1===n||(i+1)%o===0)&&a(Math.round((i+1)/n*100),i+1);return r}function de(e,t){if(!Number.isInteger(e)||e<0)throw new Error("Exponent must be a non-negative integer");if(t<=0n)throw new Error("Modulus must be positive");let n=0n,a=1n;for(let r=0;r<e;r+=1){const o=a<<1n,i=o/t;a=o%t,n=(n<<1n)+i}return{quotient:n,remainder:a}}function qe(e,t){return de(e,t).remainder}const Oe=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,Le=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;async function fe(...e){const t=B(...e),n=new Uint8Array(t.length);n.set(t);const a=await crypto.subtle.digest("SHA-256",n.buffer);return new Uint8Array(a)}function Me(e,t){return x(e,t-3n)+2n}function X(e){return F(e,Math.max(1,Math.ceil(e.toString(16).length/2)))}function Be(e){return(e&1n)===1n}function Ue(e){let t=0n,n=e-1n;for(;(n&1n)===0n;)n>>=1n,t+=1n;return{r:t,d:n}}function Ie(e,t=20){if(e<2n)return!1;const n=[2n,3n,5n,7n,11n,13n,17n,19n,23n,29n,31n,37n];for(const l of n){if(e===l)return!0;if(e%l===0n)return!1}if(!Be(e))return!1;const{r:a,d:r}=Ue(e),o=[2n,325n,9375n,28178n,450775n,9780504n,1795265022n,7952650221n,113n],i=Math.min(t,o.length);for(let l=0;l<i;l+=1){const v=x(o[l],e-3n)+2n;let h=$(v,r,e);if(h===1n||h===e-1n)continue;let m=!0;for(let V=1n;V<a;V+=1n)if(h=$(h,2n,e),h===e-1n){m=!1;break}if(m)return!1}return!0}async function W(e,t){const n=await fe(e);return Me(k(n),t)}async function ue(e,t,n){const a=await fe(X(e),X(t),F(BigInt(n),8));let r=k(a)|1n;for(r<3n&&(r=3n);!Ie(r);)r+=2n;return r}function He(e,t,n){const a=performance.now(),r=Se(e,t.N,t.T,n),o=performance.now()-a;return{y:r,timeMs:o,squarings:t.T}}async function pe(e,t,n){return typeof Worker>"u"||typeof window>"u"?He(e,t,n):new Promise((a,r)=>{const o=new Worker(new URL("/crypto-lab-vrf-gate/assets/vdfWorker-Cs_o19uS.js",import.meta.url),{type:"module"});o.onmessage=i=>{if(i.data.type==="progress"&&n&&typeof i.data.pct=="number"&&typeof i.data.squarings=="number"){n(i.data.pct,i.data.squarings);return}if(i.data.type==="done"&&typeof i.data.y=="bigint"&&typeof i.data.timeMs=="number"&&typeof i.data.squarings=="number"){o.terminate(),a({y:i.data.y,timeMs:i.data.timeMs,squarings:i.data.squarings});return}i.data.type==="error"&&(o.terminate(),r(new Error(i.data.message??"Unknown VDF worker error")))},o.onerror=i=>{o.terminate(),r(i instanceof ErrorEvent?new Error(i.message):new Error("Unknown VDF worker error"))},o.postMessage({g:e,N:t.N,T:t.T})})}async function ve(e,t,n){const a=await ue(e,t,n.T),{quotient:r}=de(n.T,a);return{proof:$(e,r,n.N),prime:a}}async function he(e,t,n,a){const r=await ue(e,t,a.T),o=qe(a.T,r);return x($(n,r,a.N)*$(e,o,a.N),a.N)===x(t,a.N)}const _e={N:Oe*Le,T:65536,T_exp:16};function H(e){const t=e/1e6;return{seconds:t,minutes:t/60,hours:t/3600}}async function G(...e){const t=B(...e),n=new Uint8Array(t.length);n.set(t);const a=await crypto.subtle.digest("SHA-256",n.buffer);return new Uint8Array(a)}function Ke(e,t){if(!e)throw new Error(`${t} is missing`);return e}function Ge(e){const t=e.validators.filter(n=>n.revealed&&!n.withheld&&n.vrfOutput).map(n=>{var a;return Ke((a=n.vrfOutput)==null?void 0:a.beta,`VRF beta for ${n.id}`)});if(t.length===0)throw new Error("No revealed VRF outputs are available");return t}async function Ye(e,t){const n=[];for(let a=0;a<e;a+=1)n.push({id:`V${a+1}`,keyPair:await se(),committed:!1,revealed:!1,withheld:!1});return{epochSeed:t.slice(),validators:n,commitments:new Map}}async function je(e){for(const t of e.validators){const n=await L(t.keyPair,e.epochSeed);t.vrfOutput=n,t.committed=!0,t.revealed=!1,t.withheld=!1,e.commitments.set(t.id,await G(n.beta))}return e}async function We(e,t=[]){const n=new Set(t);for(const a of e.validators){if(!a.committed||!a.vrfOutput)throw new Error(`Validator ${a.id} has not committed a VRF output`);a.withheld=n.has(a.id),a.revealed=!a.withheld}return e.randaoMix=me(e),e}function me(e){return J(Ge(e))}async function Xe(e,t){const n=[];for(const a of e.validators){if(!a.committed||!a.vrfOutput){n.push(`${a.id} did not commit a VRF output`);continue}const r=e.commitments.get(a.id);if(!r){n.push(`${a.id} is missing its commitment`);continue}const o=await G(a.vrfOutput.beta);E(r,o)||n.push(`${a.id} commitment does not match its VRF output`),a.withheld||(await le(a.keyPair.publicKeyBytes,e.epochSeed,a.vrfOutput)).valid||n.push(`${a.id} VRF proof failed verification`)}if(e.randaoMix){const a=me(e);E(a,e.randaoMix)||n.push("RANDAO mix does not match the revealed VRF outputs")}if(e.vdfResult&&e.randaoMix&&(await W(e.randaoMix,t.N)!==e.vdfResult.input&&n.push("VDF input does not match hashToGroup(RANDAO)"),await he(e.vdfResult.input,e.vdfResult.output,e.vdfResult.proof,t)||n.push("VDF proof failed verification"),e.finalRandomness)){const o=await G(F(e.vdfResult.output));E(o,e.finalRandomness)||n.push("Final randomness does not match SHA-256(y)")}return{valid:n.length===0,failures:n}}const ze=[{title:"Attempt 1: block.timestamp",body:"Validators can move timestamps within a permitted range and pick favorable outcomes.",attack:"Grinding timestamps until the lottery or leader election looks profitable."},{title:"Attempt 2: future blockhash",body:"A miner who owns that block can discard an unfavorable block and try again.",attack:"Grinding future block production when the reward is worth more than the discarded block."},{title:"Attempt 3: commit-reveal",body:"The last revealer sees everyone else first and can choose not to reveal.",attack:"Last-reveal bias: abstain when the XOR output is not the one you wanted."}],Je=[{title:"Ethereum RANDAO + VDF",detail:"RANDAO is live for validator shuffling and committee selection. VDF integration remains an active engineering effort rather than a completed mainnet primitive.",note:"Use: beacon-chain randomness. Status: RANDAO deployed, VDF research and integration ongoing."},{title:"Chainlink VRF v2",detail:"An on-chain verifiable randomness service built on similar principles to ECVRF, used for NFT mints, games, lotteries, and betting markets across multiple chains.",note:"Use: verifiable request-response randomness. Not this exact ciphersuite."},{title:"Filecoin Leader Election",detail:"Storage providers run VRFs over epoch data to determine whether they won the right to propose a block in a given round.",note:"Use: leader election proportional to storage power."},{title:"Cardano Ouroboros",detail:"Cardano uses VRFs to determine slot leadership and committee assignments with deterministic verifiability.",note:"Use: slot leader selection. RFC 9381-standardized VRF family relevance is direct here."},{title:"Algorand",detail:"Participants privately determine if they are selected, revealing the proof only when selected, reducing targeted denial-of-service risk.",note:"Use: private committee sampling with later reveal."},{title:"drand",detail:"A distributed randomness beacon based on threshold cryptography rather than VRFs or VDFs, useful as a contrast point for public randomness design.",note:"Use: public beacon consumed by Filecoin and others."}],c={vrf:{keyPair:null,output:null,uniquenessRuns:[],comparison:null},vdf:{inputHex:"",groupElement:null,result:null,verifyMs:null,progress:0,squarings:0,elapsedMs:0,etaMs:0},beacon:{round:null,logLines:[],progress:0,squarings:0,summary:"Run a beacon round to see how withholding changes the RANDAO mix and why the VDF still blocks selective prediction."}},be=document.querySelector("#app");if(!be)throw new Error("App root not found");const ye=be;function u(e,t=12){if(e===null)return"—";const n=typeof e=="bigint"?e.toString(16):w(e);return n.length<=t*2?n:`${n.slice(0,t)}...${n.slice(-t)}`}function s(e){const t=document.querySelector(e);if(!t)throw new Error(`Missing element: ${e}`);return t}function b(e,t,n){e.textContent=t,e.dataset.tone=n}function z(e){return JSON.stringify({gamma:w(e.gamma),c:w(e.c),s:w(e.s)},null,2)}function Qe(e){const t=JSON.parse(e);return{gamma:P(t.gamma),c:P(t.c),s:P(t.s)}}async function ge(...e){const t=B(...e),n=new Uint8Array(t.length);n.set(t);const a=await crypto.subtle.digest("SHA-256",n.buffer);return new Uint8Array(a)}function U(e){const t=e??Number(s("#vdf-exp").value);return{..._e,T_exp:t,T:1<<t}}function Ze(){ye.innerHTML=`
    <main class="page-shell">
      <header class="hero-panel">
        <div class="hero-copy">
          <p class="kicker">crypto-lab-vrf-gate</p>
          <h1>VRFs and VDFs: Provable Randomness in Time</h1>
          <p class="hero-text">
            A browser lab for deterministic public-key randomness, sequential time-locks, and why
            blockchains need both when the cost of bias is high.
          </p>
          <div class="hero-ribbon">
            <span class="badge beta">VRF: sealed output</span>
            <span class="badge proof">VDF: elapsed time proof</span>
            <span class="badge valid">No fake math</span>
          </div>
        </div>
        <div class="hero-ornament" aria-hidden="true">
          <div class="clock-face">
            <span class="clock-core"></span>
            <span class="clock-hand clock-hand-hour"></span>
            <span class="clock-hand clock-hand-minute"></span>
          </div>
          <div class="seal-stack">
            <div class="seal-card">
              <span class="seal-title">Verifier</span>
              <span class="seal-stamp">✓ public proof</span>
            </div>
            <div class="seal-card offset">
              <span class="seal-title">Producer</span>
              <span class="seal-stamp">sk → β, π</span>
            </div>
          </div>
        </div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode" aria-pressed="false">🌙</button>
      </header>

      <section class="section-card split-pane" id="exhibit-vrf">
        <div class="section-heading">
          <p class="section-index">Exhibit 1</p>
          <h2>What Is a VRF? The Public-Key Hash</h2>
          <p>
            The output is deterministic for the same secret key and input, yet publicly verifiable by
            anyone holding only the public key.
          </p>
        </div>
        <div class="vrf-grid">
          <article class="pane-card producer-card">
            <div class="pane-header">
              <span class="pane-label">Producer</span>
              <span class="tiny-note">Only the keyholder can compute the proof</span>
            </div>
            <div class="field-group">
              <label for="vrf-alpha">Input α</label>
              <input id="vrf-alpha" type="text" value="block-1847-leader-selection" />
            </div>
            <div class="info-strip">
              <div>
                <span class="strip-label">Secret key</span>
                <strong>sk = ●●●●●●●●</strong>
              </div>
              <div>
                <span class="strip-label">Public key</span>
                <code id="vrf-public-key" class="proof-bytes" role="code" aria-label="VRF public key bytes">loading...</code>
              </div>
            </div>
            <div class="button-row">
              <button id="vrf-compute" type="button">Compute VRF Output</button>
              <button id="vrf-uniqueness" class="ghost-button" type="button">Run 5× Uniqueness</button>
            </div>
            <div class="result-panel">
              <div>
                <span class="strip-label">Output β</span>
                <code id="vrf-beta" class="proof-bytes beta-text" role="code" aria-label="VRF output beta">—</code>
              </div>
              <div>
                <span class="strip-label">Proof π</span>
                <pre id="vrf-proof" class="proof-box proof-text" role="code" aria-label="VRF proof bytes">—</pre>
              </div>
            </div>
            <div class="property-grid">
              <article class="property-card">
                <h3>Uniqueness</h3>
                <p id="vrf-uniqueness-result">Run the deterministic check to compare five proofs.</p>
              </article>
              <article class="property-card">
                <h3>Pseudorandomness</h3>
                <p id="vrf-compare-result">Change α and compare outputs that look unrelated to the eye.</p>
              </article>
            </div>
          </article>

          <article class="pane-card verifier-card">
            <div class="pane-header">
              <span class="pane-label">Verifier</span>
              <span class="tiny-note">Anyone with the public key can check the proof</span>
            </div>
            <div class="field-group">
              <label for="vrf-verify-alpha">Input α</label>
              <input id="vrf-verify-alpha" type="text" />
            </div>
            <div class="field-group">
              <label for="vrf-verify-beta">Beta β</label>
              <textarea id="vrf-verify-beta" rows="3"></textarea>
            </div>
            <div class="field-group">
              <label for="vrf-verify-proof">Proof π</label>
              <textarea id="vrf-verify-proof" rows="7"></textarea>
            </div>
            <div class="button-row">
              <button id="vrf-verify" type="button">Verify</button>
              <button id="vrf-tamper" class="ghost-button" type="button">Tamper with β</button>
            </div>
            <p id="vrf-verify-status" class="status-pill" data-tone="neutral">Verification status is waiting for a proof.</p>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-vdf">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 2</p>
          <h2>What Is a VDF? The Time-Lock</h2>
          <p>
            Evaluation requires real sequential squarings. Verification checks a proof that is far
            cheaper than replaying the whole delay.
          </p>
        </div>
        <div class="split-pane vdf-layout">
          <article class="pane-card vdf-card">
            <p class="warning-banner">TOY VDF — NOT PRODUCTION SECURE</p>
            <div class="field-group">
              <label for="vdf-input">Input x (hex)</label>
              <textarea id="vdf-input" rows="3"></textarea>
            </div>
            <div class="slider-row">
              <label for="vdf-exp">Delay T</label>
              <input id="vdf-exp" type="range" min="12" max="18" value="16" />
              <span id="vdf-exp-label">2^16 = 65,536 squarings</span>
            </div>
            <div class="metric-grid">
              <div class="metric-card">
                <span class="strip-label">Toy modulus N</span>
                <code id="vdf-modulus" class="proof-bytes" role="code" aria-label="Toy VDF modulus">—</code>
              </div>
              <div class="metric-card">
                <span class="strip-label">g = H(x) mod N</span>
                <code id="vdf-group" class="proof-bytes" role="code" aria-label="VDF group element">—</code>
              </div>
            </div>
            <div class="button-row">
              <button id="vdf-evaluate" type="button">Evaluate VDF</button>
              <button id="vdf-verify" class="ghost-button" type="button">Verify Proof</button>
            </div>
            <div class="progress-block">
              <div class="progress-headline">
                <span>Progress</span>
                <strong id="vdf-progress-text">0%</strong>
              </div>
              <div id="vdf-progress" class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                <span class="progress-fill amber-fill"></span>
              </div>
              <div class="metric-grid timing-grid">
                <div class="metric-card">
                  <span class="strip-label">Elapsed</span>
                  <strong id="vdf-elapsed">0 ms</strong>
                </div>
                <div class="metric-card">
                  <span class="strip-label">ETA</span>
                  <strong id="vdf-eta">—</strong>
                </div>
                <div class="metric-card">
                  <span class="strip-label">Squarings</span>
                  <strong id="vdf-squarings">0</strong>
                </div>
              </div>
            </div>
          </article>

          <article class="pane-card proof-card">
            <div class="metric-grid">
              <div class="metric-card">
                <span class="strip-label">Result y</span>
                <code id="vdf-output" class="proof-bytes beta-text" role="code" aria-label="VDF output">—</code>
              </div>
              <div class="metric-card">
                <span class="strip-label">Prime ℓ</span>
                <code id="vdf-prime" class="proof-bytes proof-text" role="code" aria-label="VDF Wesolowski prime">—</code>
              </div>
              <div class="metric-card wide">
                <span class="strip-label">Proof π</span>
                <code id="vdf-proof" class="proof-bytes proof-text" role="code" aria-label="VDF proof value">—</code>
              </div>
            </div>
            <p id="vdf-verify-status" class="status-pill" data-tone="neutral">Evaluate the VDF to produce a proof bundle.</p>
            <div class="timing-callouts">
              <div class="callout-card">
                <h3>Measured in this browser</h3>
                <p id="vdf-speedup">Verification will report its speedup after a proof is checked.</p>
              </div>
              <div class="callout-card">
                <h3>Real-world scaling</h3>
                <p id="vdf-estimate"></p>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-problem">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 3</p>
          <h2>The Blockchain Randomness Problem</h2>
          <p>Bias enters any protocol where a validator can still choose after partial information is revealed.</p>
        </div>
        <div class="attempt-grid">
          ${ze.map(e=>`
                <article class="attempt-card">
                  <h3>${e.title}</h3>
                  <p>${e.body}</p>
                  <p class="attack-note">Attack: ${e.attack}</p>
                </article>
              `).join("")}
        </div>
        <div class="timeline-grid">
          <article class="timeline-card danger">
            <h3>Commit-reveal without VDF</h3>
            <pre class="timeline-block">Round: Block 100
Validators commit hashes.

Round: Block 101 reveal
A reveals r_A.
B reveals r_B.
C sees the partial XOR and asks:
  reveal -> final_1
  withhold -> final_2

If C dislikes final_1, C withholds.
Result: the final randomness is biased.</pre>
          </article>
          <article class="timeline-card good">
            <h3>RANDAO followed by VDF</h3>
            <pre class="timeline-block">Reveal closes.
RANDAO mix is fixed.

Now the attacker still has a binary choice,
but cannot know which branch gives the preferred
future outcome without evaluating the VDF first.

The delay turns strategic choice into blind choice.</pre>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-beacon">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 4</p>
          <h2>Live Beacon Simulation</h2>
          <p>Simulate validators, VRF commitments, withholding, RANDAO mixing, and the delayed VDF output.</p>
        </div>
        <div class="split-pane beacon-layout">
          <article class="pane-card beacon-controls">
            <div class="slider-row">
              <label for="beacon-validators">Validators</label>
              <input id="beacon-validators" type="range" min="3" max="8" value="4" />
              <span id="beacon-validators-label">4 validators</span>
            </div>
            <div class="slider-row">
              <label for="beacon-exp">VDF delay</label>
              <input id="beacon-exp" type="range" min="12" max="18" value="14" />
              <span id="beacon-exp-label">2^14 squarings</span>
            </div>
            <label class="switch-row" for="beacon-malicious">
              <span>Add malicious validator</span>
              <input id="beacon-malicious" type="checkbox" checked />
            </label>
            <button id="beacon-run" type="button">Run Full Beacon Round</button>
            <div class="progress-block compact-progress">
              <div class="progress-headline">
                <span>Beacon VDF</span>
                <strong id="beacon-progress-text">0%</strong>
              </div>
              <div id="beacon-progress" class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                <span class="progress-fill green-fill"></span>
              </div>
            </div>
            <p id="beacon-summary" class="summary-copy">${c.beacon.summary}</p>
          </article>
          <article class="pane-card beacon-log-card">
            <div class="log-heading">
              <h3>Epoch 42 Randomness Beacon</h3>
              <span class="tiny-note">aria-live log for the current round</span>
            </div>
            <div id="beacon-log" class="beacon-log" role="log" aria-live="polite"></div>
          </article>
        </div>
      </section>

      <section class="section-card" id="exhibit-deployments">
        <div class="section-heading compact">
          <p class="section-index">Exhibit 5</p>
          <h2>Real-World Deployments</h2>
          <p>VRFs and VDF-adjacent randomness beacons already shape production consensus, lotteries, and validator selection.</p>
        </div>
        <div class="deployment-grid">
          ${Je.map((e,t)=>`
                <details class="deployment-card" ${t===0?"open":""}>
                  <summary>${t+1}. ${e.title}</summary>
                  <p>${e.detail}</p>
                  <p class="tiny-note">${e.note}</p>
                </details>
              `).join("")}
        </div>
        <div class="comparison-wrap">
          <table class="comparison-table">
            <thead>
              <tr>
                <th>Property</th>
                <th>VRF</th>
                <th>VDF</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Key required?</td><td>Yes</td><td>No</td></tr>
              <tr><td>Deterministic output?</td><td>Yes</td><td>Yes</td></tr>
              <tr><td>Verifiable?</td><td>Yes</td><td>Yes</td></tr>
              <tr><td>Unpredictable without secret?</td><td>Yes</td><td>Only after T sequential steps</td></tr>
              <tr><td>Sequential computation?</td><td>No</td><td>Yes</td></tr>
              <tr><td>Resists last-reveal alone?</td><td>Partially</td><td>Helps by delaying prediction</td></tr>
              <tr><td>Post-quantum secure?</td><td>No</td><td>No</td></tr>
            </tbody>
          </table>
        </div>
        <article class="post-quantum-note">
          <h3>Post-Quantum Caveat</h3>
          <p>
            Neither construction shown here is post-quantum secure. P-256 and RSA-style groups are both
            vulnerable to Shor's algorithm. Post-quantum VRFs exist only as emerging designs, and
            post-quantum VDFs remain an open research problem as of 2026.
          </p>
        </article>
      </section>

      <footer>
        <p>"Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God." — 1 Corinthians 10:31</p>
      </footer>
    </main>
  `}function et(){const e=document.documentElement,t=s("#theme-toggle"),n=r=>{e.setAttribute("data-theme",r),localStorage.setItem("theme",r),t.textContent=r==="dark"?"🌙":"☀️",t.setAttribute("aria-label",r==="dark"?"Switch to light mode":"Switch to dark mode"),t.setAttribute("aria-pressed",r==="light"?"true":"false")},a=e.getAttribute("data-theme")==="light"?"light":"dark";n(a),t.addEventListener("click",()=>{const r=e.getAttribute("data-theme")==="light"?"dark":"light";n(r)})}function _(e,t,n,a){const r=s("#vdf-progress"),o=s("#vdf-progress .progress-fill"),i=s("#vdf-progress-text");r.setAttribute("aria-valuenow",String(e)),o.style.width=`${e}%`,i.textContent=`${e}%`,s("#vdf-squarings").textContent=t.toLocaleString(),s("#vdf-elapsed").textContent=`${n.toFixed(0)} ms`,s("#vdf-eta").textContent=a>0?`${a.toFixed(0)} ms`:"—"}function O(e,t){const n=s("#beacon-progress"),a=s("#beacon-progress .progress-fill");n.setAttribute("aria-valuenow",String(e)),a.style.width=`${e}%`,s("#beacon-progress-text").textContent=`${e}% (${t.toLocaleString()} sq)`}function S(e){const t=s("#beacon-log");t.innerHTML=e.map(n=>`<p>${n}</p>`).join("")}async function we(e){const t=c.vrf.keyPair;if(!t)return;const n=A(e),a=await L(t,n),r=A("block-1848-leader-selection"),o=await L(t,r);c.vrf.output=a,c.vrf.comparison={current:u(a.beta),changed:u(o.beta)},s("#vrf-public-key").textContent=w(t.publicKeyBytes),s("#vrf-beta").textContent=w(a.beta),s("#vrf-proof").textContent=z(a.proof),s("#vrf-verify-alpha").value=e,s("#vrf-verify-beta").value=w(a.beta),s("#vrf-verify-proof").value=z(a.proof),s("#vrf-compare-result").textContent=`α = "${e}" -> β = ${u(a.beta)}; α = "block-1848-leader-selection" -> β = ${u(o.beta)}.`,b(s("#vrf-verify-status"),"Verification status is waiting for a proof.","neutral")}async function xe(){const e=c.vrf.keyPair,t=s("#vrf-alpha").value;if(!e)return;const n=A(t),a=await Promise.all(Array.from({length:5},async()=>L(e,n)));c.vrf.uniquenessRuns=a.map((r,o)=>`run ${o+1}: ${u(r.beta)}`),s("#vrf-uniqueness-result").textContent=c.vrf.uniquenessRuns.join(" • ")}async function tt(){const e=c.vrf.keyPair;if(e)try{const t=A(s("#vrf-verify-alpha").value),n=P(s("#vrf-verify-beta").value),a=Qe(s("#vrf-verify-proof").value);if((await le(e.publicKeyBytes,t,{alpha:t,beta:n,proof:a})).valid){b(s("#vrf-verify-status"),"✓ VALID — β is the unique VRF output for this public key and input.","good");return}b(s("#vrf-verify-status"),"✗ INVALID — the proof or beta has been modified.","bad")}catch(t){b(s("#vrf-verify-status"),`✗ INVALID — ${t.message}`,"bad")}}async function M(){const e=s("#vdf-input"),t=U(),n=P(e.value),a=await W(n,t.N);c.vdf.inputHex=e.value,c.vdf.groupElement=a,s("#vdf-modulus").textContent=u(t.N,20),s("#vdf-group").textContent=u(a,20),s("#vdf-exp-label").textContent=`2^${t.T_exp} = ${t.T.toLocaleString()} squarings`;const r=H(t.T),o=H(1<<20),i=H(1<<25);s("#vdf-estimate").textContent=`Toy estimate at ${t.T.toLocaleString()} squarings: ${r.seconds.toFixed(2)}s if the machine sustains 1M squarings/s. Real RSA-2048 VDFs are much slower. At 2^20 squarings that same back-of-envelope rate is ${o.seconds.toFixed(2)}s, and at 2^25 it is ${i.hours.toFixed(2)}h before accounting for the larger modulus cost.`}async function nt(){const e=s("#vdf-evaluate");e.disabled=!0;try{if(await M(),c.vdf.groupElement===null)throw new Error("VDF group element is unavailable");const t=U(),n=performance.now();_(0,0,0,0);const a=await pe(c.vdf.groupElement,t,(o,i)=>{const l=performance.now()-n,v=i>0?l/i*(t.T-i):0;_(o,i,l,v),c.vdf.progress=o,c.vdf.squarings=i,c.vdf.elapsedMs=l,c.vdf.etaMs=v}),r=await ve(c.vdf.groupElement,a.y,t);c.vdf.result={input:c.vdf.groupElement,output:a.y,proof:r.proof,prime:r.prime,steps:a.squarings,timeMs:a.timeMs},c.vdf.verifyMs=null,_(100,a.squarings,a.timeMs,0),s("#vdf-output").textContent=u(a.y,24),s("#vdf-prime").textContent=u(r.prime,24),s("#vdf-proof").textContent=u(r.proof,24),b(s("#vdf-verify-status"),`VDF output computed in ${a.timeMs.toFixed(0)}ms. Verify the proof to compare costs.`,"warn"),s("#vdf-speedup").textContent=`Evaluation took ${a.timeMs.toFixed(0)}ms for ${a.squarings.toLocaleString()} sequential squarings.`}catch(t){b(s("#vdf-verify-status"),t.message,"bad")}finally{e.disabled=!1}}async function at(){const e=c.vdf.result;if(!e){b(s("#vdf-verify-status"),"Evaluate the VDF before verifying it.","bad");return}const t=U(),n=performance.now(),a=await he(e.input,e.output,e.proof,t),r=performance.now()-n;if(c.vdf.verifyMs=r,a){const o=e.timeMs/Math.max(r,.001);b(s("#vdf-verify-status"),`✓ VERIFIED in ${r.toFixed(2)}ms using the simplified Wesolowski check π^ℓ · g^r = y mod N.`,"good"),s("#vdf-speedup").textContent=`Verification took ${r.toFixed(2)}ms versus ${e.timeMs.toFixed(0)}ms to evaluate. Observed speedup: ${o.toFixed(1)}×.`;return}b(s("#vdf-verify-status"),"✗ INVALID — the VDF proof did not verify.","bad")}async function rt(e){return ge(F(e))}function ot(e){return e.validators.map(t=>{var n;return(n=t.vrfOutput)==null?void 0:n.beta}).filter(t=>t instanceof Uint8Array)}async function st(){var t,n;const e=s("#beacon-run");e.disabled=!0,c.beacon.logLines=[],O(0,0);try{const a=Number(s("#beacon-validators").value),r=Number(s("#beacon-exp").value),o=s("#beacon-malicious").checked,i=U(r),l=await Ye(a,A("epoch-42"));c.beacon.round=l,c.beacon.logLines.push("Phase 1 — VRF Computation"),await je(l);for(const g of l.validators)c.beacon.logLines.push(`${g.id} (${o&&g.id===((t=l.validators.at(-1))==null?void 0:t.id)?"malicious":"honest"}): β = ${u(((n=g.vrfOutput)==null?void 0:n.beta)??null)}`);const v=o&&l.validators.length>0?[l.validators[l.validators.length-1].id]:[];c.beacon.logLines.push("Phase 2 — Reveal and RANDAO"),await We(l,v);const h=J(ot(l));c.beacon.logLines.push(`RANDAO = ${u(l.randaoMix??null)}`),v.length>0?(c.beacon.logLines.push(`${v[0]} withheld its reveal and changed the RANDAO branch.`),c.beacon.logLines.push(`Honest full mix would have been ${u(h)}.`)):c.beacon.logLines.push("All validators revealed, so the RANDAO mix uses every VRF contribution."),c.beacon.logLines.push("Phase 3 — VDF"),S(c.beacon.logLines);const m=await W(l.randaoMix??h,i.N),V=performance.now(),p=await pe(m,i,(g,I)=>{c.beacon.progress=g,c.beacon.squarings=I,O(g,I),S([...c.beacon.logLines,`VDF progress: ${g}% after ${I.toLocaleString()} squarings (${(performance.now()-V).toFixed(0)}ms elapsed).`])}),y=await ve(m,p.y,i);l.vdfResult={input:m,output:p.y,proof:y.proof,prime:y.prime,steps:p.squarings,timeMs:p.timeMs},l.finalRandomness=await rt(p.y),c.beacon.logLines.push(`y = ${u(p.y)} (computed in ${p.timeMs.toFixed(0)}ms)`),c.beacon.logLines.push(`Proof π verified input: ℓ = ${u(y.prime)}`),c.beacon.logLines.push(`Final randomness = SHA-256(y) = ${u(l.finalRandomness)}`);const N=await Xe(l,i);c.beacon.logLines.push(N.valid?"Beacon verification: ✓ all VRF proofs, RANDAO, and VDF checks passed.":`Beacon verification failed: ${N.failures.join("; ")}`),c.beacon.summary=o?"Residual bias remains: a malicious validator still chooses whether to reveal, but the VDF prevents them from knowing which branch they prefer before the delay completes.":"Honest round complete: the final randomness is the VDF-delayed output of the fully revealed RANDAO mix.",s("#beacon-summary").textContent=c.beacon.summary,S(c.beacon.logLines),O(100,p.squarings)}catch(a){c.beacon.summary=a.message,s("#beacon-summary").textContent=c.beacon.summary,c.beacon.logLines.push(`Error: ${a.message}`),S(c.beacon.logLines)}finally{e.disabled=!1}}function it(){s("#vrf-compute").addEventListener("click",async()=>{await we(s("#vrf-alpha").value)}),s("#vrf-uniqueness").addEventListener("click",async()=>{await xe()}),s("#vrf-verify").addEventListener("click",async()=>{await tt()}),s("#vrf-tamper").addEventListener("click",()=>{const e=s("#vrf-verify-beta");try{const t=P(e.value);t[0]^=1,e.value=w(t)}catch{e.value="00"}}),s("#vdf-input").addEventListener("change",async()=>{await M()}),s("#vdf-exp").addEventListener("input",async e=>{const t=Number(e.currentTarget.value);s("#vdf-exp-label").textContent=`2^${t} = ${(1<<t).toLocaleString()} squarings`,await M()}),s("#vdf-evaluate").addEventListener("click",async()=>{await nt()}),s("#vdf-verify").addEventListener("click",async()=>{await at()}),s("#beacon-validators").addEventListener("input",e=>{const t=Number(e.currentTarget.value);s("#beacon-validators-label").textContent=`${t} validators`}),s("#beacon-exp").addEventListener("input",e=>{const t=Number(e.currentTarget.value);s("#beacon-exp-label").textContent=`2^${t} squarings`}),s("#beacon-run").addEventListener("click",async()=>{await st()})}async function ct(){var n;Ze(),et(),it(),c.vrf.keyPair=await se(),await we(s("#vrf-alpha").value),await xe();const e=await ge(A("beacon-seed"));s("#vdf-input").value=w(e),await M(),s("#beacon-validators-label").textContent="4 validators",s("#beacon-exp-label").textContent="2^14 squarings",O(0,0);const t=(n=c.vrf.output)==null?void 0:n.proof;if(t&&c.vrf.output){const a=await j(t.gamma);E(a,c.vrf.output.beta)||b(s("#vrf-verify-status"),"VRF proof-to-hash self-check failed during boot.","bad")}}ct().catch(e=>{ye.innerHTML=`<main class="page-shell"><section class="section-card"><h1>Initialization failed</h1><p>${e.message}</p></section></main>`});
