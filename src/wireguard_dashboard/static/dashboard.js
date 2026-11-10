/**
 * Client-side interactive controller for WireGuard Companion Dashboard.
 * Enforces strict security:
 * - Real-time client-side search without network requests.
 * - On-demand configuration retrieval triggered exclusively by explicit user action.
 * - Inert text rendering (textContent) preventing XSS.
 * - Class-based visibility changes complying strictly with Content Security Policy (no inline styles).
 * - No local/sessionStorage caching of cryptographic secrets.
 */
(() => {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    initSearchFilter();
    initConfigActions();
  });

  function initSearchFilter() {
    const searchInput = document.getElementById("peer-search");
    const clearBtn = document.getElementById("clear-search-btn");
    const noResults = document.getElementById("no-search-results");
    const cards = Array.from(document.querySelectorAll(".peer-card"));

    if (!searchInput || cards.length === 0) {
      return;
    }

    function applyFilter() {
      const rawQuery = searchInput.value || "";
      const query = rawQuery.trim().toLowerCase();

      if (clearBtn) {
        clearBtn.classList.toggle("hidden", query.length === 0);
      }

      let visibleCount = 0;

      for (const card of cards) {
        const name = (card.getAttribute("data-peer-name") || "").toLowerCase();
        const ip = (card.getAttribute("data-peer-ip") || "").toLowerCase();

        const matches = !query || name.includes(query) || ip.includes(query);
        card.classList.toggle("card-hidden", !matches);
        if (matches) {
          visibleCount++;
        }
      }

      if (noResults) {
        noResults.classList.toggle("hidden", visibleCount > 0);
      }
    }

    searchInput.addEventListener("input", applyFilter);

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        searchInput.value = "";
        applyFilter();
        searchInput.focus();
      });
    }
  }

  function initConfigActions() {
    // In-memory runtime cache for the active session view only
    // Never persisted to localStorage or sessionStorage
    const confCache = new Map();

    const cards = document.querySelectorAll(".peer-card");

    cards.forEach((card) => {
      const peerId = card.getAttribute("data-peer-id");
      if (!peerId) return;

      const revealBtn = card.querySelector(".btn-reveal");
      const copyBtn = card.querySelector(".btn-copy");
      const previewWrapper = document.getElementById(`conf-wrapper-${peerId}`);
      const codeElem = document.getElementById(`conf-code-${peerId}`);

      if (!revealBtn || !previewWrapper || !codeElem) {
        return;
      }

      async function fetchConfiguration() {
        if (confCache.has(peerId)) {
          return confCache.get(peerId);
        }

        revealBtn.disabled = true;
        revealBtn.textContent = "Loading...";

        try {
          const resp = await fetch(`/peers/${encodeURIComponent(peerId)}/conf`, {
            headers: { Accept: "text/plain" },
            cache: "no-store",
          });

          if (!resp.ok) {
            if (resp.status === 401) {
              throw new Error("Authentication required. Please refresh and log in.");
            }
            throw new Error(`Failed to load configuration (HTTP ${resp.status}).`);
          }

          const text = await resp.text();
          confCache.set(peerId, text);
          return text;
        } finally {
          revealBtn.disabled = false;
        }
      }

      revealBtn.addEventListener("click", async () => {
        const isExpanded = revealBtn.getAttribute("aria-expanded") === "true";

        if (isExpanded) {
          // Hide configuration
          previewWrapper.classList.add("hidden");
          revealBtn.setAttribute("aria-expanded", "false");
          revealBtn.textContent = "Reveal Configuration";
        } else {
          // Show configuration
          try {
            const confText = await fetchConfiguration();
            codeElem.textContent = confText;
            previewWrapper.classList.remove("hidden");
            revealBtn.setAttribute("aria-expanded", "true");
            revealBtn.textContent = "Hide Configuration";

            if (copyBtn) {
              copyBtn.disabled = false;
              copyBtn.title = "Copy configuration to clipboard";
            }
          } catch (err) {
            codeElem.textContent = err instanceof Error ? err.message : "Error retrieving configuration.";
            previewWrapper.classList.remove("hidden");
            revealBtn.setAttribute("aria-expanded", "true");
            revealBtn.textContent = "Hide Error";
          }
        }
      });

      if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
          let textToCopy = confCache.get(peerId);

          if (!textToCopy) {
            try {
              textToCopy = await fetchConfiguration();
              codeElem.textContent = textToCopy;
              previewWrapper.classList.remove("hidden");
              revealBtn.setAttribute("aria-expanded", "true");
              revealBtn.textContent = "Hide Configuration";
              copyBtn.disabled = false;
            } catch (err) {
              return;
            }
          }

          try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              await navigator.clipboard.writeText(textToCopy);
            } else {
              // CSP-compliant fallback
              const textArea = document.createElement("textarea");
              textArea.value = textToCopy;
              textArea.className = "clipboard-hidden";
              document.body.appendChild(textArea);
              textArea.focus();
              textArea.select();
              const successful = document.execCommand("copy");
              document.body.removeChild(textArea);
              if (!successful) throw new Error("Fallback copy command unsuccessful");
            }

            const originalText = copyBtn.textContent;
            copyBtn.textContent = "✓ Copied!";
            copyBtn.classList.add("btn-copied");
            setTimeout(() => {
              copyBtn.textContent = originalText;
              copyBtn.classList.remove("btn-copied");
            }, 2000);
          } catch {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = "Copy Failed";
            setTimeout(() => {
              copyBtn.textContent = originalText;
            }, 2000);
          }
        });
      }
    });
  }
})();
