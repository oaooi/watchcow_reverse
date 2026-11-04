(() => {
    "use strict";
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const parents = [];
    // Native fnOS apps run inside a same-origin iframe. Observe the desktop,
    // whose missing body theme-mode attribute means light, even on a dark OS.
    try {
        let current = window;
        while (current.parent !== current) {
            current = current.parent;
            const doc = current.document;
            parents.push(doc);
        }
    } catch (_) { /* Cross-origin launch: fall back to saved mode and the OS. */ }
    function storedTheme() {
        try {
            const mode = Number(localStorage.getItem("os-theme-mode") || localStorage.getItem("fnos-theme-mode"));
            if (mode === 10) return "light";
            if (mode === 20) return "dark";
        } catch (_) { /* Storage can be blocked by browser settings. */ }
        return media.matches ? "dark" : "light";
    }
    function update() {
        let theme = storedTheme();
        const desktop = parents[parents.length - 1];
        if (desktop && desktop.body) {
            const html = desktop.documentElement;
            const explicit = desktop.body.getAttribute("theme-mode") || html.getAttribute("data-theme");
            theme = explicit === "dark" || (!explicit && (html.classList.contains("dark") || html.classList.contains("body--biz-dark"))) ? "dark" : "light";
        }
        if (root.dataset.theme !== theme) root.dataset.theme = theme;
    }
    update();
    parents.forEach(doc => {
        const observer = new MutationObserver(update);
        observer.observe(doc.documentElement, {attributes: true, attributeFilter: ["theme-mode", "data-theme", "class"]});
        if (doc.body) observer.observe(doc.body, {attributes: true, attributeFilter: ["theme-mode", "data-theme", "class"]});
        else doc.addEventListener("DOMContentLoaded", () => {
            observer.observe(doc.body, {attributes: true, attributeFilter: ["theme-mode", "data-theme", "class"]});
            update();
        }, {once: true});
    });
    window.addEventListener("storage", event => {
        if (event.key === null || event.key === "os-theme-mode" || event.key === "fnos-theme-mode") update();
    });
    media.addEventListener("change", update);
    window.addEventListener("pageshow", update);
    document.addEventListener("visibilitychange", update);
})();
