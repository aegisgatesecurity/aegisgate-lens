// AegisGate Lens — util/banner-icons.js
// Inline SVG icons used by the banner. Inlined to avoid any
// network fetch (privacy guarantee #1) and to avoid any
// "icon not found" if the user has aggressive ad blockers.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Each icon is a 16x16 viewBox SVG. Color is controlled by the
  // CSS fill (currentColor).
  var ICONS = {
    // AegisGate shield-with-padlock mark (simplified, single color).
    // The real corporate logo is a detailed metallic shield; this is
    // a single-color version that reads at 16x16 in the banner.
    shield: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
            'fill="currentColor" aria-hidden="true">' +
            '<path d="M8 1L2 3v5c0 3.5 2.5 6.5 6 7 3.5-.5 6-3.5 6-7V3L8 1zm0 1.2l4.8 1.5V8c0 2.8-2 5.2-4.8 5.7C5.2 13.2 3.2 10.8 3.2 8V3.7L8 2.2z"/>' +
            '<path d="M7 6V4.5C7 3.7 7.4 3 8 3s1 .7 1 1.5V6h.5v4.5h-3V6H7zm.5-1.5V6h1V4.5C8.5 4 8.3 3.5 8 3.5s-.5.5-.5 1z"/>' +
            '</svg>',

    // Close X
    close: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
           'fill="currentColor" aria-hidden="true">' +
           '<path d="M3.7 3L3 3.7 7.3 8 3 12.3 3.7 13 8 8.7 12.3 13 13 12.3 8.7 8 13 3.7 12.3 3 8 7.3 3.7 3z"/>' +
           '</svg>',

    // Help ?
    help: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
          'fill="currentColor" aria-hidden="true">' +
          '<path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 13a6 6 0 110-12 6 6 0 010 12z"/>' +
          '<path d="M7.3 5.5C7.3 4.7 7.9 4 8.8 4c.9 0 1.5.7 1.5 1.5 0 .5-.2.9-.6 1.2L8.5 7.5c-.3.2-.5.5-.5 1v.5h1V8.5c0-.2.1-.3.3-.4L10.6 7c.6-.4.9-1 .9-1.6C11.5 4 10.2 3 8.8 3 7.3 3 6.2 4.1 6.2 5.5h1.1zm.2 4.5v1.1h1.1V10H7.5z"/>' +
          '</svg>',

    // Down chevron (for the "Tell us why" expand)
    chevronDown: '<svg viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" ' +
                 'fill="currentColor" aria-hidden="true">' +
                 '<path d="M3 5.5L3.7 4.8 8 9.1l4.3-4.3.7.7L8 10.5 3 5.5z"/>' +
                 '</svg>'
  };

  var module = { ICONS: ICONS };

  if (typeof self !== 'undefined') self.__lensBannerIcons = module;
  if (typeof window !== 'undefined') window.__lensBannerIcons = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensBannerIcons = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
