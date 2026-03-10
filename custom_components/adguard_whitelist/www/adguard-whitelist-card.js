const CARD_VERSION = "1.0.0";

class AdGuardWhitelistCard extends HTMLElement {
  static get properties() {
    return { hass: {}, config: {} };
  }

  static getConfigElement() {
    return document.createElement("adguard-whitelist-card-editor");
  }

  static getStubConfig() {
    return { client_ip: "192.168.8.50" };
  }

  setConfig(config) {
    if (!config.client_ip) {
      throw new Error("Veuillez définir client_ip");
    }
    this.config = config;
    this._newDomain = "";
    this._render();
  }

  set hass(hass) {
    this._hass = hass;
    this._render();
  }

  _findSensorEntity() {
    if (!this._hass) return null;
    for (const eid of Object.keys(this._hass.states)) {
      if (eid.startsWith("sensor.") && eid.includes("sites_autoris")) {
        const state = this._hass.states[eid];
        if (state.attributes && state.attributes.domains) {
          return state;
        }
      }
    }
    return null;
  }

  _findSwitchEntities() {
    if (!this._hass) return [];
    const switches = [];
    for (const eid of Object.keys(this._hass.states)) {
      if (eid.startsWith("switch.") && eid.includes("filtrage_dns")) {
        switches.push(this._hass.states[eid]);
      }
    }
    return switches;
  }

  _addSite() {
    if (!this._hass || !this._newDomain) return;
    const domain = this._newDomain.trim().toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");
    if (!domain) return;
    this._hass.callService("adguard_whitelist", "add_site", { domain });
    this._newDomain = "";
    // Re-render after a short delay to clear the input
    setTimeout(() => this._render(), 300);
  }

  _removeSite(domain) {
    if (!this._hass) return;
    this._hass.callService("adguard_whitelist", "remove_site", { domain });
  }

  _toggleSwitch(entityId) {
    if (!this._hass) return;
    const state = this._hass.states[entityId];
    if (!state) return;
    this._hass.callService("switch", state.state === "on" ? "turn_off" : "turn_on", {
      entity_id: entityId,
    });
  }

  _fireEvent(entityId) {
    const event = new Event("hass-more-info", { bubbles: true, composed: true });
    event.detail = { entityId };
    this.dispatchEvent(event);
  }

  _render() {
    if (!this.config || !this._hass) return;

    const sensor = this._findSensorEntity();
    const domains = sensor ? (sensor.attributes.domains || []) : [];
    const count = sensor ? sensor.state : "?";
    const pendingSsh = sensor ? (sensor.attributes.pending_ssh || 0) : 0;
    const totalRules = sensor ? (sensor.attributes.total_rules || 0) : 0;

    // Categorize domains
    const categories = {};
    const catEducation = sensor ? (sensor.attributes.category_éducation || sensor.attributes["category_\u00e9ducation"] || []) : [];
    const catProg = sensor ? (sensor.attributes.category_programmation || []) : [];
    const catCdn = sensor ? (sensor.attributes.category_cdn_technique || []) : [];
    const catAutre = sensor ? (sensor.attributes.category_autre || []) : [];

    if (catEducation.length) categories["Éducation"] = catEducation;
    if (catProg.length) categories["Programmation"] = catProg;
    if (catCdn.length) categories["CDN / Technique"] = catCdn;
    if (catAutre.length) categories["Autre"] = catAutre;

    const title = this.config.title || "Sites Autorisés";
    const showCdn = this.config.show_cdn !== false;

    // Category icons
    const catIcons = {
      "Éducation": "mdi:school",
      "Programmation": "mdi:code-braces",
      "CDN / Technique": "mdi:server-network",
      "Autre": "mdi:web",
    };

    // Category colors
    const catColors = {
      "Éducation": "var(--info-color, #2196f3)",
      "Programmation": "var(--success-color, #4caf50)",
      "CDN / Technique": "var(--secondary-text-color)",
      "Autre": "var(--warning-color, #ff9800)",
    };

    // Build site list HTML
    let sitesHtml = "";
    for (const [catName, catDomains] of Object.entries(categories)) {
      if (!showCdn && catName === "CDN / Technique") continue;

      const icon = catIcons[catName] || "mdi:web";
      const color = catColors[catName] || "var(--primary-text-color)";

      sitesHtml += `
        <div class="aw-category">
          <div class="aw-category-header">
            <ha-icon icon="${icon}" style="--mdc-icon-size:14px; color:${color}"></ha-icon>
            <span style="color:${color}">${catName}</span>
            <span class="aw-category-count">${catDomains.length}</span>
          </div>
          <div class="aw-site-list">
      `;

      for (const domain of catDomains) {
        sitesHtml += `
          <div class="aw-site-item">
            <span class="aw-site-domain">${domain}</span>
            <div class="aw-site-remove" data-remove="${domain}" title="Supprimer">
              <ha-icon icon="mdi:close-circle-outline" style="--mdc-icon-size:18px"></ha-icon>
            </div>
          </div>
        `;
      }

      sitesHtml += `</div></div>`;
    }

    this.innerHTML = `
      <ha-card>
        <style>
          .aw-card { padding: 16px; }
          .aw-header {
            display: flex; align-items: center; gap: 12px;
            margin-bottom: 16px; padding-bottom: 12px;
            border-bottom: 1px solid var(--divider-color);
          }
          .aw-header-icon {
            width: 40px; height: 40px; border-radius: 50%;
            background: var(--primary-color);
            display: flex; align-items: center; justify-content: center;
            color: white; font-size: 20px;
          }
          .aw-header-info { flex: 1; }
          .aw-header-title { font-size: 16px; font-weight: 500; }
          .aw-header-status {
            font-size: 12px; color: var(--secondary-text-color);
          }
          .aw-pending-badge {
            background: var(--warning-color, #ff9800); color: white;
            border-radius: 10px; padding: 2px 8px; font-size: 11px;
            margin-left: 4px;
          }
          .aw-stats {
            display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
            margin-bottom: 16px;
          }
          .aw-stat {
            background: var(--card-background-color, var(--ha-card-background));
            border: 1px solid var(--divider-color);
            border-radius: 12px; padding: 12px; text-align: center;
          }
          .aw-stat-value { font-size: 20px; font-weight: 600; }
          .aw-stat-label { font-size: 11px; color: var(--secondary-text-color); }

          /* Add site form */
          .aw-add-form {
            display: flex; gap: 8px; margin-bottom: 16px;
          }
          .aw-add-input {
            flex: 1; padding: 8px 12px;
            border: 1px solid var(--divider-color);
            border-radius: 8px;
            background: var(--card-background-color, var(--ha-card-background));
            color: var(--primary-text-color);
            font-size: 14px;
            outline: none;
          }
          .aw-add-input:focus {
            border-color: var(--primary-color);
          }
          .aw-add-input::placeholder {
            color: var(--secondary-text-color);
          }
          .aw-add-btn {
            padding: 8px 16px; border: none; border-radius: 8px;
            background: var(--primary-color); color: white;
            font-size: 14px; font-weight: 500; cursor: pointer;
            display: flex; align-items: center; gap: 4px;
          }
          .aw-add-btn:hover { opacity: 0.9; }
          .aw-add-btn:active { opacity: 0.7; }

          /* Categories and sites */
          .aw-category { margin-bottom: 12px; }
          .aw-category-header {
            display: flex; align-items: center; gap: 6px;
            font-size: 12px; font-weight: 600; text-transform: uppercase;
            margin-bottom: 6px;
          }
          .aw-category-count {
            background: var(--divider-color); border-radius: 10px;
            padding: 1px 6px; font-size: 10px;
          }
          .aw-site-list { }
          .aw-site-item {
            display: flex; align-items: center; justify-content: space-between;
            padding: 6px 8px; border-radius: 8px;
            transition: background 0.15s;
          }
          .aw-site-item:hover {
            background: var(--secondary-background-color, rgba(0,0,0,0.04));
          }
          .aw-site-domain {
            font-size: 13px; color: var(--primary-text-color);
          }
          .aw-site-remove {
            cursor: pointer; color: var(--error-color, #f44336);
            opacity: 0.4; transition: opacity 0.15s;
            display: flex; align-items: center;
          }
          .aw-site-item:hover .aw-site-remove { opacity: 1; }
        </style>

        <div class="aw-card">
          <!-- Header -->
          <div class="aw-header">
            <div class="aw-header-icon">
              <ha-icon icon="mdi:shield-check"></ha-icon>
            </div>
            <div class="aw-header-info">
              <div class="aw-header-title">${title}</div>
              <div class="aw-header-status">
                AdGuard Home &middot; ${this.config.client_ip}
                ${pendingSsh > 0 ? `<span class="aw-pending-badge">${pendingSsh} synchro en attente</span>` : ""}
              </div>
            </div>
          </div>

          <!-- Stats -->
          <div class="aw-stats">
            <div class="aw-stat">
              <div class="aw-stat-value">${count}</div>
              <div class="aw-stat-label">Sites autorisés</div>
            </div>
            <div class="aw-stat">
              <div class="aw-stat-value">${totalRules}</div>
              <div class="aw-stat-label">Règles totales</div>
            </div>
          </div>

          <!-- Add site -->
          <div class="aw-add-form">
            <input type="text" class="aw-add-input" id="aw-new-domain"
              placeholder="domaine.fr" value="${this._newDomain || ""}">
            <button class="aw-add-btn" id="aw-add-btn">
              <ha-icon icon="mdi:plus" style="--mdc-icon-size:16px"></ha-icon>
              Ajouter
            </button>
          </div>

          <!-- Sites by category -->
          ${sitesHtml || '<div style="text-align:center;color:var(--secondary-text-color);padding:16px;">Aucun site autorisé</div>'}
        </div>
      </ha-card>
    `;

    // Bind events
    const input = this.querySelector("#aw-new-domain");
    if (input) {
      input.addEventListener("input", (e) => {
        this._newDomain = e.target.value;
      });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          this._addSite();
        }
      });
    }

    const addBtn = this.querySelector("#aw-add-btn");
    if (addBtn) {
      addBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this._addSite();
      });
    }

    this.querySelectorAll("[data-remove]").forEach((el) => {
      el.addEventListener("click", (e) => {
        e.stopPropagation();
        const domain = el.dataset.remove;
        if (confirm(`Supprimer ${domain} de la liste blanche ?`)) {
          this._removeSite(domain);
        }
      });
    });
  }

  getCardSize() {
    return 6;
  }
}

// ── Config editor ──────────────────────────────────────────

class AdGuardWhitelistCardEditor extends HTMLElement {
  setConfig(config) {
    this._config = { ...config };
    this._render();
  }

  set hass(hass) {
    this._hass = hass;
  }

  _render() {
    this.innerHTML = `
      <div style="padding: 16px;">
        <div style="margin-bottom: 12px;">
          <label style="display: block; margin-bottom: 4px; font-weight: 500;">
            IP du client
          </label>
          <input type="text" id="client_ip"
            value="${this._config.client_ip || ""}"
            style="width: 100%; padding: 8px; border: 1px solid var(--divider-color); border-radius: 4px; box-sizing: border-box;"
            placeholder="192.168.8.50">
        </div>
        <div style="margin-bottom: 12px;">
          <label style="display: block; margin-bottom: 4px; font-weight: 500;">
            Titre (optionnel)
          </label>
          <input type="text" id="title"
            value="${this._config.title || ""}"
            style="width: 100%; padding: 8px; border: 1px solid var(--divider-color); border-radius: 4px; box-sizing: border-box;"
            placeholder="Sites Autorisés">
        </div>
        <div>
          <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
            <input type="checkbox" id="show_cdn" ${this._config.show_cdn !== false ? "checked" : ""}>
            Afficher les CDN / domaines techniques
          </label>
        </div>
      </div>
    `;

    this.querySelector("#client_ip").addEventListener("input", (e) => {
      this._config = { ...this._config, client_ip: e.target.value };
      this._dispatch();
    });

    this.querySelector("#title").addEventListener("input", (e) => {
      this._config = { ...this._config, title: e.target.value };
      this._dispatch();
    });

    this.querySelector("#show_cdn").addEventListener("change", (e) => {
      this._config = { ...this._config, show_cdn: e.target.checked };
      this._dispatch();
    });
  }

  _dispatch() {
    this.dispatchEvent(
      new CustomEvent("config-changed", { detail: { config: this._config } })
    );
  }
}

customElements.define("adguard-whitelist-card", AdGuardWhitelistCard);
customElements.define("adguard-whitelist-card-editor", AdGuardWhitelistCardEditor);

window.customCards = window.customCards || [];
window.customCards.push({
  type: "adguard-whitelist-card",
  name: "AdGuard Whitelist - Sites Autorisés",
  description: "Gérer les sites autorisés dans AdGuard Home",
  preview: true,
});

console.info(
  `%c ADGUARD-WHITELIST-CARD %c v${CARD_VERSION} `,
  "color: white; background: #4caf50; font-weight: bold; padding: 2px 4px; border-radius: 4px 0 0 4px;",
  "color: #4caf50; background: white; font-weight: bold; padding: 2px 4px; border-radius: 0 4px 4px 0; border: 1px solid #4caf50;"
);
