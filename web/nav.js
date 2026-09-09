// Vigilarch — behaviour for the header bar both pages share.
//
// base.css carries the bar's appearance; this carries the two things it cannot
// express on its own: the narrow-screen menu's open state, and whether the page
// has scrolled underneath the bar. Nothing here knows anything about the ledger.
//
// It is deliberately its own file rather than a copy inside landing.js and
// app.js. The header is one component, and the reason base.css exists at all is
// that the two pages must not be able to drift apart.

const nav = document.querySelector('.sitenav');

if (nav) {
  const toggle = nav.querySelector('.navtoggle');
  const links = nav.querySelector('.navlinks');

  // --- the narrow-screen menu ----------------------------------------------
  // The menu is CSS-driven: `.is-open` on the bar is the whole state, and the
  // closed state renders nothing, so there is no off-screen drawer holding
  // focusable elements out of view.

  const setOpen = (open) => {
    nav.classList.toggle('is-open', open);
    if (toggle) {
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    }
  };

  if (toggle) {
    toggle.addEventListener('click', () => setOpen(!nav.classList.contains('is-open')));

    // Following a link is the end of the menu's job. This covers the section
    // anchors and the repository link alike.
    nav.addEventListener('click', (e) => {
      if (e.target.closest('a')) setOpen(false);
    });

    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' || !nav.classList.contains('is-open')) return;
      setOpen(false);
      toggle.focus();
    });

    // A click anywhere else closes it, which is what a menu that overlays the
    // page is expected to do.
    document.addEventListener('click', (e) => {
      if (!nav.classList.contains('is-open')) return;
      if (!nav.contains(e.target)) setOpen(false);
    });

    // Widening past the breakpoint puts the links back in the bar; leaving
    // `.is-open` set would then style the desktop row as a panel.
    const wide = window.matchMedia('(min-width: 861px)');
    const onWide = (e) => { if (e.matches) setOpen(false); };
    if (wide.addEventListener) wide.addEventListener('change', onWide);
    else if (wide.addListener) wide.addListener(onWide);
  }

  // --- has the page moved under the bar ------------------------------------

  let ticking = false;
  const sync = () => {
    ticking = false;
    nav.classList.toggle('is-stuck', window.scrollY > 8);
  };
  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(sync);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  sync();

  // Anchor scrolling is CSS (`scroll-behavior`), but a menu link fires its
  // navigation while the panel is still open and the bar is still tall, which
  // lands the target under the header. Closing first, then letting the browser
  // scroll on the next frame, keeps `scroll-padding-top` honest.
  if (links) {
    links.addEventListener('click', (e) => {
      const a = e.target.closest('a[href^="#"]');
      if (!a) return;
      const target = document.getElementById(a.getAttribute('href').slice(1));
      if (!target) return;
      e.preventDefault();
      setOpen(false);
      requestAnimationFrame(() => {
        target.scrollIntoView({
          behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
          block: 'start',
        });
        history.replaceState(null, '', a.getAttribute('href'));
      });
    });
  }
}
