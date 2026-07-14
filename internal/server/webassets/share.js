(function () {
  "use strict";

  /* Crypto boundary. libsodium supplies audited XChaCha20-Poly1305 and
   * hash-wasm supplies Argon2id with the same lane count as Go's argon2.IDKey.
   * Both builds are pinned, vendored, and loaded from this origin. */
  var AqtCrypto = {
    ready: window.sodium && window.hashwasm ? window.sodium.ready : null,
    xchachaOpen: function (key, nonce, ciphertextAndTag, aad) {
      try {
        return window.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null, ciphertextAndTag, aad, nonce, key
        );
      } catch (e) {
        return null;
      }
    },
    argon2id: function (password, salt, time, memoryKiB, threads, keyLen) {
      return window.hashwasm.argon2id({
        password: password,
        salt: salt,
        iterations: time,
        parallelism: threads,
        memorySize: memoryKiB,
        hashLength: keyLen,
        outputType: "binary",
      });
    },
  };
  if (window.__aqtTestHooks && window.__aqtTestHooks.crypto) {
    AqtCrypto = window.__aqtTestHooks.crypto;
  }

  /* ---------------- fragment + base64 helpers (parsing, not crypto) -- */

  function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return b64Decode(s);
  }

  function b64Decode(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8(s) { return new TextEncoder().encode(s); }

  function validGated(gated) {
    if (!gated || !gated.kdf || !gated.wrapped) return false;
    var kdf = gated.kdf;
    if (kdf.algo !== "argon2id" || !Number.isInteger(kdf.time) ||
        !Number.isInteger(kdf.memory) || !Number.isInteger(kdf.threads)) return false;
    // Match the limits enforced by crypto.KdfParams.validate. A share fragment
    // is attacker-controlled and must not be allowed to force unbounded WASM work.
    if (kdf.time < 1 || kdf.time > 16 || kdf.memory < 1 || kdf.memory > 1048576 ||
        kdf.threads < 1 || kdf.threads > 16) return false;
    try {
      var salt = b64Decode(kdf.salt);
      var nonce = b64Decode(gated.wrapped.nonce);
      var wrapped = b64Decode(gated.wrapped.ciphertext);
      return salt.length > 0 && salt.length <= 1024 && nonce.length === 24 && wrapped.length === 48;
    } catch (e) { return false; }
  }

  // "#k.<b64url key>" | "#p.<b64url json>" -> {kind, key | gated} | null
  function parseFragment(hash) {
    if (hash.indexOf("#k.") === 0) {
      try {
        var raw = b64urlDecode(hash.slice(3));
        if (raw.length !== 32) return null;
        return { kind: "public", key: raw };
      } catch (e) { return null; }
    }
    if (hash.indexOf("#p.") === 0) {
      try {
        var gated = JSON.parse(new TextDecoder().decode(b64urlDecode(hash.slice(3))));
        if (!validGated(gated)) return null;
        return { kind: "gated", gated: gated };
      } catch (e) { return null; }
    }
    return null;
  }

  // Open a {nonce, ciphertext} blob, trying the id-bound v2 AAD first
  // (rotated resources), then the unbound v1 tag (one-shot pushes).
  function openBound(sealed, key, role, id) {
    var nonce = b64Decode(sealed.nonce);
    var ct = b64Decode(sealed.ciphertext);
    var plain = AqtCrypto.xchachaOpen(key, nonce, ct, utf8("aqt-" + role + "-v2:" + id));
    if (plain === null) plain = AqtCrypto.xchachaOpen(key, nonce, ct, utf8("aqt-" + role + "-v1"));
    return plain;
  }

  /* ---------------- page state machine ------------------------------ */

  var RES_ID = document.body.getAttribute("data-resource");
  var $ = function (id) { return document.getElementById(id); };
  var states = ["state-cli", "state-locked", "state-password", "state-busy", "state-file", "state-error"];
  var stateLabels = {
    "state-cli": "NO KEY", "state-locked": "LOCKED", "state-password": "GATED",
    "state-busy": "WORKING", "state-file": "DECRYPTED", "state-error": "FAILED",
  };

  function show(state) {
    document.body.classList.toggle("is-decrypted", state === "state-file");
    states.forEach(function (s) { $(s).hidden = s !== state; });
    $("card-state").textContent = stateLabels[state];
  }

  function setHeadline(text) { $("headline").textContent = text; }

  function fail(title, body) {
    $("error-title").textContent = title;
    $("error-body").textContent = body + " You can always decrypt with the CLI:";
    show("state-error");
  }

  var pullCmd = "aqt pull '" + window.location.href + "'";

  function wireCopy(btnId, text) {
    var btn = $(btnId);
    if (!navigator.clipboard) { btn.hidden = true; return; }
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(typeof text === "function" ? text() : text).then(function () {
        var old = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = old; }, 1400);
      });
    });
  }

  /* ---------------- fetch + decrypt flow ----------------------------- */

  var fetchImpl = (window.__aqtTestHooks && window.__aqtTestHooks.fetch) || window.fetch.bind(window);

  function fetchResource() {
    return fetchImpl("/v1/resources/" + encodeURIComponent(RES_ID), {
      headers: { Accept: "application/json" },
    }).then(function (res) {
      if (res.status === 410) throw new Error("This link has expired or reached its read limit.");
      if (res.status === 404) throw new Error("This resource is no longer public.");
      if (!res.ok) throw new Error("The server answered " + res.status + ".");
      return res.json();
    });
  }

  function decryptFlow(keyPromise) {
    if (!AqtCrypto.ready) {
      fail("Browser decryption is unavailable.", "This browser could not load the local crypto runtime.");
      return;
    }
    show("state-busy");
    $("busy-step").textContent = "PREPARING KEY";
    var resource;
    var key;
    Promise.resolve(AqtCrypto.ready)
      // Yield once so the busy state paints before Argon2id starts its CPU work.
      .then(function () { return new Promise(function (r) { setTimeout(r, 30); }); })
      .then(keyPromise)
      .then(function (derivedKey) {
        key = derivedKey;
        $("busy-step").textContent = "FETCHING CIPHERTEXT";
        return fetchResource();
      })
      .then(function (json) {
        resource = json;
        $("busy-step").textContent = "DECRYPTING";
        return new Promise(function (r) { setTimeout(r, 30); });
      })
      .then(function () {
        var metaPlain = openBound(resource.EncryptedMeta, key, "meta", RES_ID);
        if (metaPlain === null) throw new Error("wrong-key");
        var meta = JSON.parse(new TextDecoder().decode(metaPlain));
        if (meta.streamed || meta.packed || meta.tree || meta.kind === "folder") {
          throw new Error("unsupported:" + (meta.kind === "folder" ? "folder" : "streamed"));
        }
        var plain = openBound(resource.Blob, key, "blob", RES_ID);
        if (plain === null) throw new Error("wrong-key");
        renderFile(meta, plain);
      })
      .catch(function (err) {
        var msg = String(err && err.message || err);
        if (msg === "wrong-password") {
          show("state-password");
          $("password-error").textContent = "Wrong password: the key failed to unwrap.";
          $("password-error").hidden = false;
        } else if (msg === "wrong-key") {
          fail("The key does not fit.", "The fragment in this link cannot authenticate this ciphertext. The link may be truncated or altered.");
        } else if (msg.indexOf("unsupported:") === 0) {
          var what = msg.split(":")[1] === "folder" ? "a folder" : "a large streamed file";
          fail("This is " + what + ".", "In-browser decryption currently covers single inline files only.");
        } else if (msg.indexOf("WebAssembly") !== -1 || msg.indexOf("crypto runtime") !== -1) {
          fail("Browser decryption is unavailable.", "This browser could not start the local crypto runtime.");
        } else {
          fail("Could not decrypt.", msg);
        }
      });
  }

  /* ---------------- decrypted file rendering ------------------------- */

  var MIME = {
    txt: "text/plain", md: "text/plain", json: "application/json", csv: "text/csv",
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
    webp: "image/webp", svg: "image/svg+xml", pdf: "application/pdf",
  };

  function formatSize(n) {
    if (n < 1024) return n + " B";
    var units = ["KB", "MB", "GB"];
    var v = n;
    for (var i = 0; i < units.length; i++) {
      v /= 1024;
      if (v < 1024 || i === units.length - 1) return (v < 10 ? v.toFixed(1) : Math.round(v)) + " " + units[i];
    }
  }

  // Keep the gutter lightweight for hostile or unusually newline-heavy files.
  // The text remains fully readable when the line-count ceiling is exceeded.
  var MAX_NUMBERED_LINES = 10000;

  function lineNumberText(text) {
    var count = 1;
    for (var i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10 && ++count > MAX_NUMBERED_LINES) return null;
    }
    var numbers = new Array(count);
    for (var line = 0; line < count; line++) numbers[line] = String(line + 1);
    return numbers.join("\n");
  }

  function renderTextFile(body, text) {
    var view = document.createElement("div");
    view.className = "code-view";

    var numbers = lineNumberText(text);
    if (numbers !== null) {
      var gutter = document.createElement("pre");
      gutter.className = "line-numbers";
      gutter.setAttribute("aria-hidden", "true");
      gutter.textContent = numbers;
      view.appendChild(gutter);
    }

    var pre = document.createElement("pre");
    pre.className = "code-content";
    pre.textContent = text;
    view.appendChild(pre);
    body.appendChild(view);
  }

  function renderFile(meta, plain) {
    var name = meta.name || RES_ID;
    var ext = name.indexOf(".") > 0 ? name.split(".").pop().toLowerCase() : "";
    var mime = MIME[ext] || "application/octet-stream";
    var blobURL = URL.createObjectURL(new Blob([plain], { type: mime }));

    setHeadline(name);
    $("meta-size").textContent = formatSize(plain.length);
    $("meta-size").hidden = false;
    $("file-name").textContent = name;
    $("file-size").textContent = formatSize(plain.length);

    $("act-raw").href = blobURL;
    $("act-download").href = blobURL;
    $("act-download").setAttribute("download", name);

    var body = $("file-body");
    body.textContent = "";
    var text = null;
    if (plain.length <= 2 * 1024 * 1024) {
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(plain); } catch (e) { /* binary */ }
    }
    if (text !== null && mime.indexOf("image/") !== 0) {
      renderTextFile(body, text);
      wireCopy("act-copy", function () { return text; });
    } else if (mime.indexOf("image/") === 0) {
      var img = document.createElement("img");
      img.src = blobURL;
      img.alt = name;
      body.appendChild(img);
      $("act-copy").disabled = true;
    } else {
      var note = document.createElement("p");
      note.className = "file-note";
      note.textContent = "No preview for this file type. Use Raw or Download.";
      body.appendChild(note);
      $("act-copy").disabled = true;
    }
    show("state-file");
  }

  /* ---------------- boot --------------------------------------------- */

  $("cli-cmd").textContent = pullCmd;
  $("error-cmd").textContent = pullCmd;
  $("nojs-hint").hidden = true;
  wireCopy("cli-copy", pullCmd);
  wireCopy("error-copy", pullCmd);

  var frag = parseFragment(window.location.hash);

  if (!window.location.hash) {
    show("state-cli");
  } else if (frag === null) {
    fail("The key fragment is malformed.", "The part after # is not a valid aqt key.");
  } else if (frag.kind === "public") {
    show("state-locked");
    $("decrypt-btn").addEventListener("click", function () {
      decryptFlow(function () { return Promise.resolve(frag.key); });
    });
    $("show-cli-btn").addEventListener("click", function () { show("state-cli"); });
  } else {
    show("state-password");
    $("password-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pw = $("password-input").value;
      if (!pw) return;
      $("password-error").hidden = true;
      decryptFlow(function () {
        var kdf = frag.gated.kdf;
        $("busy-step").textContent = "DERIVING PASSWORD KEY";
        return Promise.resolve(AqtCrypto.argon2id(
          utf8(pw), b64Decode(kdf.salt), kdf.time, kdf.memory, kdf.threads, 32
        )).then(function (pwKey) {
          var ck = AqtCrypto.xchachaOpen(
            pwKey, b64Decode(frag.gated.wrapped.nonce), b64Decode(frag.gated.wrapped.ciphertext),
            utf8("aqt-gated-v1")
          );
          if (ck === null || ck.length !== 32) throw new Error("wrong-password");
          return ck;
        });
      });
    });
  }

  /* pixel mark (same 6x6 glyph as the product site) */
  var MARK = [1,1,1,0,0,1, 1,0,1,1,0,1, 1,1,1,1,1,1, 0,1,0,1,0,0, 0,1,1,1,1,0, 0,0,1,1,1,1];
  document.querySelectorAll(".pixel-mark").forEach(function (el) {
    MARK.forEach(function (px) {
      var i = document.createElement("i");
      if (px) i.className = "on";
      el.appendChild(i);
    });
  });
}());
