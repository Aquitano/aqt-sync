// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const assets = new URL("../internal/server/webassets/", import.meta.url);
const html = readFileSync(new URL("share.html", assets), "utf8");
const script = readFileSync(new URL("share.js", assets), "utf8");
const globals = { TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, WebAssembly, atob, btoa };

// Load the exact browser builds served by the Go server, with no npm dependencies.
const runtime = vm.createContext({ ...globals, crypto: webcrypto, fetch, setTimeout, clearTimeout });
runtime.window = runtime;
runtime.self = runtime;
for (const name of ["libsodium-0.7.10.js", "libsodium-wrappers-0.7.10.js", "hash-wasm-argon2-4.9.0.js", "fzstd-0.1.1.js"]) {
  vm.runInContext(readFileSync(new URL(name, assets), "utf8"), runtime, { filename: name });
}
await runtime.sodium.ready;

export const resourceID = "test-resource";
export const key = new Uint8Array(32).fill(7);
export const publicHash = "#k." + Buffer.from(key).toString("base64url");
const nonce = new Uint8Array(24);
const bytes = (value) => ArrayBuffer.isView(value) ? value : new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value));

export function seal(value, role, contentKey = key) {
  const ciphertext = runtime.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    bytes(value), bytes(`aqt-${role}-v2:${resourceID}`), null, nonce, contentKey,
  );
  return { nonce: Buffer.from(nonce).toString("base64"), ciphertext: Buffer.from(ciphertext).toString("base64") };
}

export function object(value, role = "aqt-treenode-v1") {
  const plaintext = bytes(value);
  const ciphertext = runtime.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, bytes(role), null, nonce, key);
  return {
    chunk: { id: createHash("sha256").update(ciphertext).digest("hex"), key: Buffer.from(key).toString("base64"), len: plaintext.length },
    ciphertext,
  };
}

export function frames(...objects) {
  return Buffer.concat(objects.map((data) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    return Buffer.concat([length, data]);
  }));
}

export async function passwordHash(password) {
  const salt = new Uint8Array(16).fill(3);
  const passwordKey = await runtime.hashwasm.argon2id({
    password, salt, iterations: 1, parallelism: 1, memorySize: 8, hashLength: 32, outputType: "binary",
  });
  const ciphertext = runtime.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(key, bytes("aqt-gated-v1"), null, nonce, passwordKey);
  const gated = {
    kdf: { algo: "argon2id", time: 1, memory: 8, threads: 1, salt: Buffer.from(salt).toString("base64") },
    wrapped: { nonce: Buffer.from(nonce).toString("base64"), ciphertext: Buffer.from(ciphertext).toString("base64") },
  };
  return "#p." + Buffer.from(JSON.stringify(gated)).toString("base64url");
}

// Only DOM operations used by the page are modeled. IDs come from share.html, so
// deleting or renaming a required element fails startup instead of creating a stub.
class Element {
  children = [];
  attributes = new Map();
  listeners = new Map();
  hidden = false;
  disabled = false;
  value = "";
  classList = { toggle() {} };
  constructor(tagName = "div") { this.tagName = tagName; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text ?? "") + this.children.map((child) => child.textContent).join(""); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  remove() { this.parentNode.children = this.parentNode.children.filter((child) => child !== this); }
  focus() {}
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  dispatch(type) { this.listeners.get(type)?.({ preventDefault() {} }); }
  click() { if (!this.disabled) { this.onclick?.(); this.dispatch("click"); } }
}

export function browser({ hash = publicHash, respond } = {}) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => [match[1], new Element()]));
  const body = new Element("body");
  body.setAttribute("data-resource", resourceID);
  const requests = [];
  const timers = [];
  const blobs = [];
  let now = Date.UTC(2026, 0, 1);
  class Clock extends Date { static now() { return now; } }
  const context = vm.createContext({
    ...globals,
    Date: Clock,
    Math: Object.assign(Object.create(Math), { random: () => 0 }),
    Blob,
    URL: { createObjectURL(blob) { blobs.push(blob); return `blob:test-${blobs.length}`; }, revokeObjectURL() {} },
    navigator: {},
    location: { hash, href: `https://example.test/x/${resourceID}${hash}` },
    document: { body, getElementById: (id) => elements.get(id) ?? null, createElement: (tag) => new Element(tag), querySelectorAll: () => [] },
    sodium: runtime.sodium,
    hashwasm: runtime.hashwasm,
    fzstd: runtime.fzstd,
    setTimeout(callback, delay) { timers.push({ at: now + delay, callback }); },
    async fetch(url, options = {}) {
      requests.push({ url, options, at: now });
      assert.ok(respond, `unexpected request: ${url}`);
      return respond(url, options, requests.length);
    },
  });
  context.window = context;
  vm.runInContext(script, context, { filename: "share.js" });

  return {
    elements, requests, blobs,
    state(name) { return elements.get(name).hidden === false; },
    async until(predicate) {
      for (let i = 0; i < 100; i++) {
        // Flush promise chains before advancing simulated time.
        await new Promise(setImmediate);
        if (predicate()) return;
        timers.sort((a, b) => a.at - b.at);
        const timer = timers.shift();
        if (timer) { now = timer.at; timer.callback(); }
      }
      assert.fail(`page did not settle: ${elements.get("error-title").textContent} ${elements.get("error-body").textContent}`);
    },
  };
}
