/* ================================================================
   soma-audit website — script.js
   Responsibilities:
   1. Hash chain interactive demo (the "forensic terminal" centerpiece)
   2. Scroll-triggered reveal animations
   No external dependencies.
================================================================ */

'use strict';

/* ── 1. HASH CHAIN DEMO ───────────────────────────────────────── */

// Deterministic fake hashes — look real, stable across resets
const CHAIN_DATA = [
  { seq: 1, hash: '3a7f2c',  prevHash: '000000' },
  { seq: 2, hash: 'b81e49',  prevHash: '3a7f2c' },
  { seq: 3, hash: '5d9a0f',  prevHash: 'b81e49' },
  { seq: 4, hash: 'e2c814',  prevHash: '5d9a0f' },
  { seq: 5, hash: '9f3b7a',  prevHash: 'e2c814' },
  { seq: 6, hash: '1c6de8',  prevHash: '9f3b7a' },
];

// Fake tampered hashes — different from originals
const TAMPERED_HASHES = ['aa1f72', 'cc4b39', '??8e1d', '??5a2c', '??d3f9', '??6b4e'];

let tamperedIndex = null; // which block was tampered (null = all good)

function buildChain() {
  const row = document.getElementById('chain-row');
  if (!row) return;
  row.innerHTML = '';

  CHAIN_DATA.forEach((block, i) => {
    // Block node
    const blockEl = document.createElement('div');
    blockEl.className = 'chain-block verified';
    blockEl.setAttribute('role', 'listitem');
    blockEl.setAttribute('tabindex', '0');
    blockEl.setAttribute('aria-label',
      `Block #${block.seq}, hash ${block.hash}, click to tamper`);
    blockEl.dataset.index = i;

    blockEl.innerHTML = `
      <div class="block-seq">
        <span class="block-num">#${block.seq}</span>
        <span class="block-status-icon" aria-hidden="true">✓</span>
      </div>
      <div class="block-hash-label">entry_hash</div>
      <div class="block-hash" data-original="${block.hash}" data-tampered="${TAMPERED_HASHES[i]}">${block.hash}</div>
      <div class="block-prev-label">prev_hash</div>
      <div class="block-prev-hash">${block.prevHash}</div>
      <div class="block-tamper-hint" aria-hidden="true">click to tamper</div>
    `;

    // Interaction: click or keyboard
    const tamper = (e) => {
      if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
      if (e.type === 'keydown') e.preventDefault();
      if (tamperedIndex !== null) return; // already tampered — must reset first
      applyTamper(i);
    };

    blockEl.addEventListener('click', tamper);
    blockEl.addEventListener('keydown', tamper);

    row.appendChild(blockEl);

    // Connector (except after last block)
    if (i < CHAIN_DATA.length - 1) {
      const conn = document.createElement('div');
      conn.className = 'chain-connector';
      conn.setAttribute('aria-hidden', 'true');
      conn.innerHTML = `
        <div class="connector-line" data-conn-index="${i}">
          <div class="connector-arrow"></div>
        </div>
      `;
      row.appendChild(conn);
    }
  });
}

function applyTamper(index) {
  tamperedIndex = index;

  const blocks = document.querySelectorAll('.chain-block');
  const connectors = document.querySelectorAll('.connector-line');

  blocks.forEach((block, i) => {
    const hashEl = block.querySelector('.block-hash');
    const statusIcon = block.querySelector('.block-status-icon');

    if (i < index) {
      // Before tamper point — still verified
      block.className = 'chain-block verified';
      block.setAttribute('aria-label', `Block #${i + 1}, verified`);
      if (statusIcon) statusIcon.textContent = '✓';
    } else if (i === index) {
      // The tampered block itself
      block.className = 'chain-block tampered';
      block.setAttribute('aria-label', `Block #${i + 1}, TAMPERED`);
      if (hashEl) hashEl.textContent = hashEl.dataset.tampered;
      if (statusIcon) statusIcon.textContent = '✗';
    } else {
      // All blocks after — broken (hash chain is invalid)
      block.className = 'chain-block broken';
      block.setAttribute('aria-label', `Block #${i + 1}, chain broken`);
      if (hashEl) hashEl.textContent = '??????';
      if (statusIcon) statusIcon.textContent = '⚠';
    }
  });

  // Connectors: connections after the tamper point are broken
  connectors.forEach((conn, i) => {
    if (i >= index) {
      conn.classList.add('broken-line');
    }
  });

  // Status bar
  const statusBar = document.getElementById('chain-status');
  const statusMsg  = document.getElementById('chain-status-msg');
  if (statusBar) {
    statusBar.className = 'chain-status-bar broken';
  }
  if (statusMsg) {
    statusMsg.textContent = `chain broken at #${index + 1} — ${CHAIN_DATA.length - index - 1} record(s) invalidated`;
  }

  // Callout
  const callout = document.getElementById('chain-callout');
  const calloutText = document.getElementById('callout-text');
  if (calloutText) {
    calloutText.textContent =
      `verify_chain: chain broken at block #${index + 1} — HMAC mismatch propagates to ${CHAIN_DATA.length - index - 1} downstream record(s)`;
  }
  if (callout) {
    callout.classList.add('visible');
  }

  // Update tabindex so tampered blocks can't be re-tampered
  blocks.forEach((block, i) => {
    if (i !== index) block.setAttribute('tabindex', '-1');
  });
}

function resetChain() {
  tamperedIndex = null;

  // Rebuild is cleaner than manual cleanup
  buildChain();

  // Status bar
  const statusBar = document.getElementById('chain-status');
  const statusMsg  = document.getElementById('chain-status-msg');
  if (statusBar) statusBar.className = 'chain-status-bar verified';
  if (statusMsg)  statusMsg.textContent = 'All 6 records verified · HMAC chain intact';

  // Callout
  const callout = document.getElementById('chain-callout');
  if (callout) callout.classList.remove('visible');
}

/* ── 2. SCROLL-TRIGGERED REVEALS ─────────────────────────────── */

function initReveal() {
  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) {
    // Show everything immediately
    document.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
  );

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

/* ── 3. SMOOTH SCROLL (for older browsers that ignore CSS) ─────── */

function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', (e) => {
      const target = document.querySelector(link.getAttribute('href'));
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Move focus for accessibility
      target.setAttribute('tabindex', '-1');
      target.focus({ preventScroll: true });
    });
  });
}

/* ── 4. NAV SHADOW ON SCROLL ──────────────────────────────────── */

function initNavScroll() {
  const nav = document.querySelector('nav');
  if (!nav) return;

  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      nav.style.boxShadow = '0 1px 0 rgba(61,220,132,0.06), 0 8px 32px rgba(0,0,0,0.4)';
    } else {
      nav.style.boxShadow = 'none';
    }
  }, { passive: true });
}

/* ── 5. CHAIN DEMO KEYBOARD ANNOUNCE ─────────────────────────── */

function initChainA11y() {
  // Ensure the chain is keyboard-operable
  // (event listeners already on each block from buildChain)
  // Add global keyboard shortcut: 'R' resets when chain section is visible
  document.addEventListener('keydown', (e) => {
    if ((e.key === 'r' || e.key === 'R') && !e.ctrlKey && !e.metaKey) {
      const section = document.getElementById('chain-demo');
      if (!section) return;
      const rect = section.getBoundingClientRect();
      if (rect.top < window.innerHeight && rect.bottom > 0) {
        if (tamperedIndex !== null) {
          resetChain();
        }
      }
    }
  });
}

/* ── INIT ─────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  buildChain();
  initReveal();
  initSmoothScroll();
  initNavScroll();
  initChainA11y();

  // Reset buttons
  const r1 = document.getElementById('chain-reset');
  const r2 = document.getElementById('chain-reset-2');
  if (r1) r1.addEventListener('click', resetChain);
  if (r2) r2.addEventListener('click', resetChain);
});
