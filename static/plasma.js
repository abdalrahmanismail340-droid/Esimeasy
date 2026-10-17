// Subtle pointer tilt for the glossy balance card (skipped on reduced motion / touch).
(() => {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || matchMedia('(hover: none)').matches) return;
  document.querySelectorAll('.pcard').forEach(card => {
    const wrap = card.parentElement;
    wrap.addEventListener('pointermove', e => {
      const r = wrap.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = `rotateX(${(-y * 18).toFixed(1)}deg) rotateY(${(x * 22).toFixed(1)}deg)`;
    });
    wrap.addEventListener('pointerleave', () => { card.style.transform = ''; });
  });
})();
