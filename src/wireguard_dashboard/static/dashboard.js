/**
 * Client-side interactive controller for WireGuard Companion Dashboard.
 * Enforces strict security:
 * - Real-time client-side search without network requests.
 * - On-demand configuration retrieval triggered exclusively by explicit user action.
 * - Strict content validation before clipboard operations.
 * - Inert text rendering (textContent) preventing XSS.
 * - Zero client-side caching of secrets in memory, localStorage, or sessionStorage.
 * - Full compliance with Content Security Policy (no inline styles or scripts).
 */
(() => {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    initSearchFilter();
    initConfigActions();
  });

  function validateWireguardConf(text) {
    if (typeof text !== "string" || !text.trim()) {
      return false;
    }
    // Strict WireGuard client configuration validation: must contain [Interface]
    return /(^|\n)\s*\[Interface\]/i.test(text);
  }

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
    const cards = document.querySelectorAll(".peer-card");

    cards.forEach((card) => {
      const peerId = card.getAttribute("data-peer-id");
      if (!peerId) return;

      const revealBtn = card.querySelector(".btn-reveal");
      const copyBtn = card.querySelector(".btn-copy");
      const maskedElem = document.getElementById(`conf-masked-${peerId}`);
      const codeBlock = card.querySelector(".conf-code-block");
      const codeElem = document.getElementById(`conf-code-${peerId}`);

      if (!revealBtn || !codeBlock || !codeElem) {
        return;
      }

      async function fetchConfiguration() {
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
        if (!validateWireguardConf(text)) {
          throw new Error("Configuration failed validation: missing [Interface].");
        }
        return text;
      }

      revealBtn.addEventListener("click", async () => {
        const isExpanded = revealBtn.getAttribute("aria-expanded") === "true";

        if (isExpanded) {
          // Revert to masked preview placeholder and purge secret from DOM
          codeElem.textContent = "";
          codeBlock.classList.add("hidden");
          if (maskedElem) maskedElem.classList.remove("hidden");
          revealBtn.setAttribute("aria-expanded", "false");
          revealBtn.textContent = "Reveal Configuration";
        } else {
          // Fetch strictly on-demand, validate, and reveal
          revealBtn.disabled = true;
          revealBtn.textContent = "Loading...";

          try {
            const confText = await fetchConfiguration();
            codeElem.textContent = confText;
            if (maskedElem) maskedElem.classList.add("hidden");
            codeBlock.classList.remove("hidden");
            revealBtn.setAttribute("aria-expanded", "true");
            revealBtn.textContent = "Hide Configuration";
          } catch (err) {
            codeElem.textContent = err instanceof Error ? err.message : "Error retrieving configuration.";
            if (maskedElem) maskedElem.classList.add("hidden");
            codeBlock.classList.remove("hidden");
            revealBtn.setAttribute("aria-expanded", "true");
            revealBtn.textContent = "Hide Error";
          } finally {
            revealBtn.disabled = false;
          }
        }
      });

      if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
          let textToCopy = codeElem.textContent;

          if (!textToCopy || !validateWireguardConf(textToCopy)) {
            // One-click copy on-demand fetch
            const origCopyText = copyBtn.textContent;
            copyBtn.disabled = true;
            copyBtn.textContent = "Loading...";
            try {
              textToCopy = await fetchConfiguration();
            } catch {
              copyBtn.textContent = "Copy Failed";
              setTimeout(() => {
                copyBtn.textContent = origCopyText;
                copyBtn.disabled = false;
              }, 2000);
              return;
            } finally {
              copyBtn.disabled = false;
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
