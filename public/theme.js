/*
 * Theme resolution. Loaded synchronously in <head> so the correct palette is applied
 * before first paint (no flash of the wrong theme).
 *
 * Three states:
 *   no stored value -> follow the operating system, live
 *   "light"/"dark"  -> explicit override
 * Choosing the theme the system is already using clears the override, so the page
 * goes back to following the system instead of freezing on a stale choice.
 */
(function () {
  var KEY = "secureshare-theme";
  var mq = window.matchMedia("(prefers-color-scheme: dark)");

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : null;
    } catch (e) {
      return null; // private window, blocked storage
    }
  }

  function save(value) {
    try {
      if (value) localStorage.setItem(KEY, value);
      else localStorage.removeItem(KEY);
    } catch (e) {
      /* preference just will not persist */
    }
  }

  function systemTheme() {
    return mq.matches ? "dark" : "light";
  }

  function effective() {
    return stored() || systemTheme();
  }

  function apply(theme) {
    document.documentElement.setAttribute("data-theme", theme);
  }

  apply(effective());

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    var sw = document.getElementById("theme-switch");
    if (!sw) return; // status pages have no switch, they just follow the resolved theme

    function sync() {
      var dark = effective() === "dark";
      sw.setAttribute("aria-checked", String(dark));
      sw.title = dark ? "Switch to light theme" : "Switch to dark theme";
    }

    sw.addEventListener("click", function () {
      var next = effective() === "dark" ? "light" : "dark";
      save(next === systemTheme() ? null : next);
      apply(next);
      sync();
    });

    sync();
  });

  // Follow the system while no explicit choice is stored
  var onSystemChange = function () {
    if (stored()) return;
    apply(systemTheme());
    var sw = document.getElementById("theme-switch");
    if (sw) {
      sw.setAttribute("aria-checked", String(mq.matches));
      sw.title = mq.matches ? "Switch to light theme" : "Switch to dark theme";
    }
  };
  if (mq.addEventListener) mq.addEventListener("change", onSystemChange);
  else if (mq.addListener) mq.addListener(onSystemChange); // older Safari
})();
