// Progressive enhancement only: the page works fully without this file.
(function () {
  var d = document;
  var root = d.documentElement;
  var nav = navigator;

  // 1. OS hint: restyles the matching download as primary; never hides one.
  var ua = nav.userAgent || '';
  var platform = (nav.userAgentData && nav.userAgentData.platform) || nav.platform || '';
  var os = 'other';
  if (/android|iphone|ipad|ipod/i.test(ua) || (/mac/i.test(platform) && nav.maxTouchPoints > 1)) os = 'mobile';
  else if (/win/i.test(platform) || /windows/i.test(ua)) os = 'windows';
  else if (/cros/i.test(ua)) os = 'other';
  else if (/ubuntu/i.test(ua)) os = 'ubuntu';
  else if (/linux|x11/i.test(platform + ' ' + ua)) os = 'linux';
  else if (/mac/i.test(platform)) os = 'mac';
  root.setAttribute('data-os', os);
  var note = d.querySelector('[data-note]');
  var text = note && note.getAttribute('data-note-' + os);
  if (text) note.textContent = text;

  var reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  // 2. Language choice is remembered for the "/" redirect; in-page anchors open <details>.
  d.addEventListener('click', function (event) {
    var link = event.target.closest && event.target.closest('a');
    if (!link) return;
    var lang = link.getAttribute('data-lang');
    if (lang) {
      d.cookie = 'lang=' + lang + ';path=/;max-age=31536000;samesite=lax' + (location.protocol === 'https:' ? ';secure' : '');
      if (location.hash && !link.hash) link.hash = location.hash;
      return;
    }
    var href = link.getAttribute('href') || '';
    if (href.charAt(0) === '#') {
      var target = d.getElementById(href.slice(1));
      if (target && target.tagName === 'DETAILS') target.open = true;
    }
  });
  var initial = location.hash && d.getElementById(location.hash.slice(1));
  if (initial && initial.tagName === 'DETAILS') initial.open = true;

  // 3. Screenshot gallery: tabs and buttons scroll the strip without moving the page.
  var gallery = d.querySelector('[data-gallery]');
  if (gallery) {
    var track = gallery.querySelector('[data-track]');
    var slides = track.children;
    var tabs = gallery.querySelectorAll('[data-tab]');
    var controls = gallery.querySelector('[data-controls]');
    var prev = gallery.querySelector('[data-prev]');
    var next = gallery.querySelector('[data-next]');
    var current = 0;
    var show = function (index) {
      current = Math.max(0, Math.min(slides.length - 1, index));
      track.scrollTo({ left: slides[current].offsetLeft - slides[0].offsetLeft, behavior: reduced ? 'auto' : 'smooth' });
    };
    var mark = function (index) {
      current = index;
      for (var i = 0; i < tabs.length; i++) {
        if (i === index) tabs[i].setAttribute('aria-current', 'true');
        else tabs[i].removeAttribute('aria-current');
      }
      prev.disabled = index === 0;
      next.disabled = index === slides.length - 1;
    };
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].addEventListener('click', function (event) {
        event.preventDefault();
        show(Number(this.getAttribute('data-tab')));
      });
    }
    prev.addEventListener('click', function () { show(current - 1); });
    next.addEventListener('click', function () { show(current + 1); });
    var frame = 0;
    track.addEventListener('scroll', function () {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(function () {
        var step = slides.length > 1 ? slides[1].offsetLeft - slides[0].offsetLeft : 1;
        mark(Math.max(0, Math.min(slides.length - 1, Math.round(track.scrollLeft / step))));
      });
    }, { passive: true });
    controls.hidden = false;
    mark(0);
  }

  // 4. Pause the hero animation while it is off screen.
  var art = d.querySelector('[data-animate]');
  if (art && 'IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      art.classList.toggle('is-paused', !entries[0].isIntersecting);
    }).observe(art);
  }
})();
