// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";
import { browser, frames, object, passwordHash, resourceID, seal } from "./share-page-harness.mjs";

const meta = { kind: "file", name: "note.txt", size: 5 };
const preflight = { encryptedMeta: seal(meta, "meta"), minClient: 4, maxReads: 1, reads: 0 };
const resource = { encryptedMeta: preflight.encryptedMeta, blob: seal("hello", "blob") };

function fileResponse(url) {
  assert.ok(url.endsWith("/preflight") || url === `/v1/resources/${resourceID}`, `unexpected URL: ${url}`);
  return Response.json(url.endsWith("/preflight") ? preflight : resource);
}

async function decrypt(page) {
  await page.until(() => page.state("state-locked"));
  page.elements.get("decrypt-btn").click();
}

function buttons(element) {
  return element.children.flatMap((child) => [...(child.tagName === "button" ? [child] : []), ...buttons(child)]);
}

test("missing and malformed keys do not fetch a resource", () => {
  assert.ok(browser({ hash: "" }).state("state-cli"));
  const page = browser({ hash: "#k.bad" });
  assert.ok(page.state("state-error"));
  assert.match(page.elements.get("error-title").textContent, /malformed/);
  assert.equal(page.requests.length, 0);
});

test("preflight authenticates metadata; consent spends one read and decrypts the file", async () => {
  const page = browser({ respond: fileResponse });
  await page.until(() => page.state("state-locked"));
  assert.equal(page.requests.length, 1);
  assert.ok(page.requests[0].url.endsWith("/preflight"));
  assert.equal(page.requests[0].options.headers["X-Aqt-Capability"], "4");
  assert.match(page.elements.get("policy-note").textContent, /1 read\(s\) remain/);
  page.elements.get("decrypt-btn").click();
  await page.until(() => page.state("state-file"));
  assert.equal(page.requests.length, 2);
  assert.equal(await page.blobs[0].text(), "hello");
  assert.equal(page.elements.get("file-name").textContent, "note.txt");
  assert.equal(page.elements.get("act-download").getAttribute("download"), "note.txt");
});

test("a tampered metadata envelope is rejected before a counted read", async () => {
  const corrupt = structuredClone(preflight);
  const ciphertext = Buffer.from(corrupt.encryptedMeta.ciphertext, "base64");
  ciphertext[0] ^= 1;
  corrupt.encryptedMeta.ciphertext = ciphertext.toString("base64");
  const page = browser({ respond: () => Response.json(corrupt) });
  await page.until(() => page.state("state-error"));
  assert.match(page.elements.get("error-title").textContent, /key does not fit/);
  assert.equal(page.requests.length, 1);
});

test("a password share retries a wrong password without consuming a read", async () => {
  const page = browser({ hash: await passwordHash("secret"), respond: fileResponse });
  assert.ok(page.state("state-password"));
  page.elements.get("password-input").value = "wrong";
  page.elements.get("password-form").dispatch("submit");
  await page.until(() => page.state("state-password"));
  assert.match(page.elements.get("password-error").textContent, /Wrong password/);
  assert.equal(page.requests.length, 0);
  page.elements.get("password-input").value = "secret";
  page.elements.get("password-form").dispatch("submit");
  await decrypt(page);
  await page.until(() => page.state("state-file"));
  assert.equal(await page.blobs[0].text(), "hello");
});

for (const status of [404, 410, 426]) {
  test(`preflight ${status} produces an actionable error without consuming a read`, async () => {
    const page = browser({ respond: () => Response.json({ minClient: 99 }, { status }) });
    await page.until(() => page.state("state-error"));
    const title = page.elements.get("error-title").textContent;
    assert.match(title, status === 404 ? /not public/ : status === 410 ? /closed/ : /newer aqt/);
    if (status === 426) assert.match(page.elements.get("error-body").textContent, /99/);
    assert.equal(page.requests.length, 1);
  });
}

for (const [header, seconds] of [["2", 2], ["-1", 9], ["Thu, 01 Jan 2026 00:00:03 GMT", 3]]) {
  test(`rate limiting with Retry-After ${JSON.stringify(header)} waits ${seconds} seconds`, async () => {
    const page = browser({ respond: (url, options, count) => count === 1
      ? Response.json({ retryAfterSeconds: 9 }, { status: 429, headers: { "Retry-After": header } })
      : fileResponse(url) });
    await page.until(() => page.state("state-locked"));
    assert.equal(page.requests.length, 2);
    const deadline = header.includes("GMT") ? Date.parse(header) : page.requests[0].at + seconds * 1000;
    assert.equal(page.requests[1].at, deadline);
  });
}

test("persistent rate limiting stops retrying", async () => {
  const page = browser({ respond: () => new Response("", { status: 429, headers: { "Retry-After": "1" } }) });
  await page.until(() => page.state("state-error"));
  assert.equal(page.requests.length, 4);
  assert.match(page.elements.get("error-title").textContent, /rate limiting/);
  assert.match(page.elements.get("error-body").textContent, /no read was consumed/);
});

function folderPage(children) {
  const node = object({ version: 2, children });
  const encryptedMeta = seal({ kind: "folder", tree: true, name: "docs" }, "meta");
  return browser({ respond: (url, options) => {
    if (url.endsWith("/preflight")) return Response.json({ encryptedMeta });
    if (url.endsWith("/objects")) {
      assert.deepEqual(JSON.parse(options.body).ids, [node.chunk.id]);
      return new Response(frames(node.ciphertext));
    }
    assert.equal(url, `/v1/resources/${resourceID}`);
    return Response.json({ encryptedMeta, blob: seal({ root: node.chunk }, "treeroot") });
  } });
}

test("folder listing decrypts a real directory node and downloads an inline member", async () => {
  const page = folderPage([{ name: "note.txt", type: "file", size: 5, inline: Buffer.from("hello").toString("base64") }]);
  await decrypt(page);
  await page.until(() => page.elements.get("folder-list").textContent.includes("note.txt"));
  buttons(page.elements.get("folder-list"))[0].click();
  await page.until(() => page.blobs.length === 1);
  assert.equal(await page.blobs[0].text(), "hello");
  assert.equal(page.requests.filter((r) => r.url === `/v1/resources/${resourceID}`).length, 1);
});

test("a malformed inline member reports failure and re-enables its download button", async () => {
  const page = folderPage([{ name: "bad.txt", type: "file", size: 5, inline: "%%%" }]);
  await decrypt(page);
  await page.until(() => page.elements.get("folder-list").textContent.includes("bad.txt"));
  const button = buttons(page.elements.get("folder-list"))[0];
  button.click();
  await page.until(() => page.elements.get("folder-status").textContent.includes("bad.txt:"));
  assert.equal(button.disabled, false);
  assert.equal(page.blobs.length, 0);
});

for (const [name, payload, size] of [
  ["raw", Buffer.from("hello"), 5],
  // Single-segment zstd frame containing one final raw block.
  ["zstd", Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 41, 0, 0, ...Buffer.from("hello")]), 5],
]) {
  test(`a streamed file downloads and decrypts ${name} chunks`, async () => {
    const data = object(payload, "aqt-chunk-aad-v1");
    data.chunk.len = size;
    if (name === "zstd") data.chunk.alg = "zstd";
    const encryptedMeta = seal({ kind: "file", streamed: true, name: "large.txt", size }, "meta");
    const page = browser({ respond: (url, options) => {
      if (url.endsWith("/preflight")) return Response.json({ encryptedMeta });
      if (url.endsWith("/objects")) {
        assert.deepEqual(JSON.parse(options.body).ids, [data.chunk.id]);
        return new Response(frames(data.ciphertext));
      }
      return Response.json({ encryptedMeta, blob: seal({ size, chunks: [data.chunk] }, "blob") });
    } });
    await decrypt(page);
    await page.until(() => page.state("state-file"));
    buttons(page.elements.get("file-body"))[0].click();
    await page.until(() => page.blobs.length === 1);
    assert.equal(await page.blobs[0].text(), "hello");
    assert.equal(page.requests.length, 3);
  });
}
