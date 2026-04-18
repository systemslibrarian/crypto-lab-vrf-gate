import './style.css';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found');
}

app.innerHTML = `
  <main class="app-shell">
    <section class="hero-card">
      <p class="eyebrow">crypto-lab-vrf-gate</p>
      <h1>VRFs and VDFs: Provable Randomness in Time</h1>
      <p>
        This educational demo is being assembled in phases. The repository gate is active and the
        strict TypeScript Vite scaffold is ready.
      </p>
    </section>
  </main>
`;
