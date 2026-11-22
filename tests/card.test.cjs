const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { test } = require("node:test");
const vm = require("node:vm");

const definitions = new Map();
const source = readFileSync("custom_components/adguard_whitelist/www/adguard-whitelist-card.js", "utf8");
vm.runInNewContext(source, {
  console: { info() {} },
  customElements: {
    get: (name) => definitions.get(name),
    define: (name, type) => definitions.set(name, type),
  },
  HTMLElement: class { attachShadow() {} },
  window: {},
});

function createCard() {
  const Card = definitions.get("adguard-whitelist-card");
  const card = new Card();
  const calls = [];
  card._showError = () => {};

  const states = {
    "sensor.adguard": {
      entity_id: "sensor.adguard",
      attributes: { client: "192.0.2.1", config_entry_id: "adguard" },
    },
    "sensor.dnsmasq": {
      entity_id: "sensor.dnsmasq",
      attributes: { client: "192.0.2.2", config_entry_id: "dnsmasq" },
    },
  };
  card._hass = { states, callService: async (...args) => calls.push(args) };
  return { card, calls, states };
}

test("selects the configured client even when another sensor comes first", async () => {
  const { card, calls, states } = createCard();
  card.setConfig({ client_ip: "192.0.2.2" });
  assert.equal(card._findSensor(), states["sensor.dnsmasq"]);
  await card._callService("remove_site", { domain: "example.fr" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "adguard_whitelist");
  assert.equal(calls[0][1], "remove_site");
  assert.equal(calls[0][2].config_entry_id, "dnsmasq");
});

test("refuses a missing client and permits an explicit sensor", async () => {
  const { card, calls, states } = createCard();
  card.setConfig({ client_ip: "192.0.2.99" });
  assert.equal(card._findSensor(), null);
  await assert.rejects(card._callService("add_site", { domain: "example.fr" }));
  assert.equal(calls.length, 0);

  card.setConfig({ entity: "sensor.adguard" });
  assert.equal(card._findSensor(), states["sensor.adguard"]);
});
