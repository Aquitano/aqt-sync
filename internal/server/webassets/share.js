(function () {
  "use strict";

  /* Crypto boundary. libsodium supplies audited XChaCha20-Poly1305, hash-wasm
   * supplies Argon2id with the same lane count as Go's argon2.IDKey, and fzstd
   * supplies the zstd decoder for the one codec aqt seals chunks and directory
   * nodes with. All builds are pinned, vendored, and loaded from this origin. */
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
    zstd: function (payload) {
      return window.fzstd.decompress(payload);
    },
    // zstdSize reads the plaintext length a zstd frame declares in its header,
    // without decompressing. Callers bound it before handing the frame to fzstd,
    // which allocates that much up front. Returns Infinity when the frame does not
    // declare one, so an undeclared size is refused rather than waved through.
    zstdSize: function (payload) {
      // Frame header: 4-byte magic, then a descriptor byte whose top two bits select
      // the width of the frame content size field (0/1/2/4/8 bytes) and whose bit 5
      // (single-segment) shifts the field forward when no window descriptor follows.
      if (payload.length < 6 || payload[0] !== 0x28 || payload[1] !== 0xb5 ||
          payload[2] !== 0x2f || payload[3] !== 0xfd) {
        return Infinity;
      }
      var desc = payload[4];
      if ((desc >> 3) & 1) return Infinity; // reserved bit set: not a frame we read
      var singleSegment = (desc >> 5) & 1;
      var width = [singleSegment ? 1 : 0, 2, 4, 8][desc >> 6];
      if (width === 0) return Infinity;
      // Window_Descriptor (absent when single-segment), then Dictionary_ID, then the
      // frame content size.
      var off = 5 + (singleSegment ? 0 : 1) + [0, 1, 2, 4][desc & 3];
      if (off + width > payload.length) return Infinity;
      var size = 0;
      for (var i = width - 1; i >= 0; i--) size = size * 256 + payload[off + i];
      // The 2-byte form is stored biased by 256.
      return width === 2 ? size + 256 : size;
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

  /* ---------------- content-addressed object crypto ------------------ */
  /* Directory nodes, file chunks, and chunk-list segments are convergent
   * objects: each carries its own key in the sealed manifest, seals under a fixed
   * role AAD with a zero nonce, and is content-addressed by sha256(ciphertext).
   * This mirrors crypto.openConvergent, minus the explicit content-address recheck:
   * the per-object key comes from the authenticated node/root, so the Poly1305 tag
   * already rejects any substituted or truncated frame (libsodium's curated build
   * ships no SHA-256 to re-hash with, and the tag makes it redundant). */

  var ZERO_NONCE = new Uint8Array(24);
  var AAD_NODE = utf8("aqt-treenode-v1");
  var AAD_CHUNK = utf8("aqt-chunk-aad-v1");
  var AAD_CHUNKLIST = utf8("aqt-chunklist-v1");

  // decompress expands one frame. rawLen is the manifest's recorded plaintext
  // length, or -1 where the manifest carries none (an inline entry). The bound is
  // applied BEFORE fzstd runs: it allocates from the frame header's declared content
  // size, so checking the result afterwards is already too late — a hostile share
  // could declare gigabytes and kill the tab before any check ran.
  function decompress(payload, alg, rawLen, maxRawLen) {
    if (!Number.isSafeInteger(rawLen) || rawLen < -1 ||
        !Number.isSafeInteger(maxRawLen) || maxRawLen < 0 ||
        rawLen > maxRawLen) {
      throw new Error("object-corrupt");
    }
    var limit = rawLen >= 0 ? rawLen : maxRawLen;
    if (alg === "zstd") {
      if (!window.fzstd) throw new Error("no-decompressor");
      if (AqtCrypto.zstdSize(payload) > limit) throw new Error("object-corrupt");
      var raw = AqtCrypto.zstd(payload);
      if (rawLen >= 0 && raw.length !== rawLen) throw new Error("object-corrupt");
      return raw;
    }
    if (alg) throw new Error("object-corrupt");
    if (payload.length > limit) throw new Error("object-corrupt");
    if (rawLen >= 0 && payload.length !== rawLen) throw new Error("object-corrupt");
    return payload;
  }

  // openObject decrypts one content-addressed frame using the key/len/alg carried
  // in its manifest record (a crypto.Chunk). Throws "object-corrupt" if the frame
  // fails the AEAD tag or does not decompress to the recorded length.
  function objectLen(chunk, maxRawLen) {
    if (!chunk || !Number.isSafeInteger(chunk.len) || chunk.len < 0 ||
        chunk.len > maxRawLen) {
      throw new Error("object-corrupt");
    }
    return chunk.len;
  }

  function boundedObjectBytes(chunks, perObjectLimit, totalLimit) {
    if (!Array.isArray(chunks)) throw new Error("object-corrupt");
    var total = 0;
    for (var i = 0; i < chunks.length; i++) {
      var n = objectLen(chunks[i], perObjectLimit);
      if (n > totalLimit - total) throw new Error("object-corrupt");
      total += n;
    }
    return total;
  }

  function openObject(frame, chunk, aad, maxRawLen) {
    var key = b64Decode(chunk.key);
    if (key.length !== 32) throw new Error("object-corrupt");
    var rawLen = objectLen(chunk, maxRawLen);
    var payload = AqtCrypto.xchachaOpen(key, ZERO_NONCE, frame, aad);
    if (payload === null) throw new Error("object-corrupt");
    return decompress(payload, chunk.alg, rawLen, maxRawLen);
  }

  /* ---------------- page state machine ------------------------------ */

  var RES_ID = document.body.getAttribute("data-resource");
  var $ = function (id) { return document.getElementById(id); };
  var states = ["state-cli", "state-locked", "state-password", "state-busy", "state-file", "state-folder", "state-error"];
  var stateLabels = {
    "state-cli": "NO KEY", "state-locked": "LOCKED", "state-password": "GATED",
    "state-busy": "WORKING", "state-file": "DECRYPTED", "state-folder": "DECRYPTED", "state-error": "FAILED",
  };

  function show(state) {
    document.body.classList.toggle("is-decrypted", state === "state-file" || state === "state-folder");
    states.forEach(function (s) { $(s).hidden = s !== state; });
    $("card-state").textContent = stateLabels[state];
    var panel = $(state);
    panel.setAttribute("tabindex", "-1");
    panel.focus();
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
        btn.setAttribute("aria-label", "Copied successfully");
        setTimeout(function () { btn.textContent = old; btn.removeAttribute("aria-label"); }, 1400);
      }).catch(function () {
        btn.textContent = "Copy failed";
        btn.setAttribute("aria-label", "Copy failed; select the command manually");
      });
    });
  }

  /* ---------------- public object transport -------------------------- */

  var fetchImpl = (window.__aqtTestHooks && window.__aqtTestHooks.fetch) || window.fetch.bind(window);

  // publicBatchBytes windows one objects request by estimated ciphertext size, the
  // same 8 MiB bound the CLI uses, so a large file's download streams in windows
  // rather than buffering the whole response. frameOverhead over-estimates a
  // chunk's ciphertext from its plaintext len (AEAD tag plus slack).
  var publicBatchBytes = 8 * 1024 * 1024;
  var frameOverhead = 64;

  // maxDownloadBytes caps a single browser download. Assembling the plaintext plus
  // copying it into a Blob costs roughly twice the file size transiently, so very
  // large files are sent to the CLI instead of risking a killed tab.
  var maxDownloadBytes = 512 * 1024 * 1024;

  // These mirror the format bounds in syncengine: directory nodes are capped at
  // MaxNodeBytes and indirect chunk lists are split into chunkListSegmentBytes
  // pieces. Keep them explicit here because every manifest length is controlled by
  // the sender of a zero-knowledge share and must be validated before decompression.
  var maxTreeNodeBytes = 24 * 1024 * 1024;
  var maxChunkListSegmentBytes = 4 * 1024 * 1024;

  // maxChunkListBytes caps an indirect chunk list's decoded JSON. A list is metadata
  // about a file, not the file, so it is orders of magnitude smaller than the
  // download cap; bounding it separately keeps a hostile share from spending the
  // whole download budget on a manifest before any content is fetched.
  var maxChunkListBytes = 64 * 1024 * 1024;

  function fetchPreflight() {
    return fetchImpl("/v1/public/resources/" + encodeURIComponent(RES_ID) + "/preflight", {
      headers: { Accept: "application/json", "X-Aqt-Capability": "3" },
    }).then(function (res) {
      if (res.status === 410) throw new Error("gone");
      if (res.status === 404) throw new Error("not-public");
      if (!res.ok) throw new Error("The server answered " + res.status + ".");
      return res.json();
    });
  }

  function fetchResource() {
    return fetchImpl("/v1/resources/" + encodeURIComponent(RES_ID), {
      headers: { Accept: "application/json", "X-Aqt-Capability": "3" },
    }).then(function (res) {
      if (res.status === 410) throw new Error("gone");
      if (res.status === 404) throw new Error("not-public");
      if (!res.ok) throw new Error("The server answered " + res.status + ".");
      return res.json();
    });
  }

  // fetchObjects posts a positional id list to the public objects endpoint and
  // returns one ciphertext frame per id, in request order (duplicate ids yield
  // duplicate frames). These reads do not count against a link's --max-reads; only
  // the one resource fetch above does, so browsing a folder costs one read total.
  function fetchObjects(ids) {
    return fetchImpl("/v1/public/resources/" + encodeURIComponent(RES_ID) + "/objects", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/vnd.aqt.object-frames; version=1" },
      body: JSON.stringify({ ids: ids }),
    }).then(function (res) {
      if (res.status === 410) throw new Error("gone");
      if (res.status === 404) throw new Error("objects-unavailable");
      if (!res.ok) throw new Error("The server answered " + res.status + ".");
      return res.arrayBuffer();
    }).then(function (buf) {
      return parseFrames(new Uint8Array(buf), ids.length);
    });
  }

  // parseFrames splits the positional length-prefixed octet-stream (a 4-byte
  // big-endian length before each frame) into exactly want frames.
  function parseFrames(data, want) {
    var view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    var out = [];
    var off = 0;
    for (var i = 0; i < want; i++) {
      if (off + 4 > data.length) throw new Error("truncated");
      var n = view.getUint32(off, false);
      off += 4;
      if (n === 0 || off + n > data.length) throw new Error("truncated");
      out.push(data.subarray(off, off + n));
      off += n;
    }
    return out;
  }

  /* ---------------- folder tree walk --------------------------------- */

  var nodeCache = {}; // node id -> children array, so back-navigation refetches nothing

  // fetchNode fetches and opens one directory node, returning its children. The node
  // ciphertext is verified against its content address inside openObject.
  function fetchNode(node) {
    try {
      objectLen(node, maxTreeNodeBytes);
    } catch (err) {
      return Promise.reject(err);
    }
    if (nodeCache[node.id]) return Promise.resolve(nodeCache[node.id]);
    return fetchObjects([node.id]).then(function (frames) {
      var plain = openObject(frames[0], node, AAD_NODE, maxTreeNodeBytes);
      var parsed = JSON.parse(new TextDecoder().decode(plain));
      if (typeof parsed.version === "number" && parsed.version > 2) throw new Error("newer-format");
      var children = parsed.children || [];
      nodeCache[node.id] = children;
      return children;
    });
  }

  var folderStack = []; // breadcrumb: [{name, node}] from root to the open directory

  function startFolder(root, meta) {
    folderStack = [{ name: meta.name || RES_ID, node: root.root }];
    setHeadline(meta.name || RES_ID);
    $("meta-size").hidden = true;
    $("folder-cmd-code").textContent = pullCmd;
    showFolderLevel();
  }

  function showFolderLevel() {
    var top = folderStack[folderStack.length - 1];
    show("state-folder");
    renderCrumbs();
    setFolderStatus("");
    var list = $("folder-list");
    list.textContent = "";
    list.appendChild(noteEl("Decrypting listing…"));
    fetchNode(top.node).then(function (children) {
      renderListing(children);
    }).catch(function (err) {
      list.textContent = "";
      list.appendChild(noteEl(browseErrorText(err)));
    });
  }

  function renderCrumbs() {
    var crumbs = $("folder-crumbs");
    crumbs.textContent = "";
    folderStack.forEach(function (level, i) {
      if (i > 0) {
        var sep = document.createElement("span");
        sep.className = "sep";
        sep.textContent = "/";
        crumbs.appendChild(sep);
      }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = level.name;
      if (i < folderStack.length - 1) {
        btn.addEventListener("click", function () {
          folderStack = folderStack.slice(0, i + 1);
          showFolderLevel();
        });
      } else {
        btn.disabled = true;
      }
      crumbs.appendChild(btn);
    });
  }

  function renderListing(children) {
    var list = $("folder-list");
    list.textContent = "";
    var dirs = [];
    var files = [];
    children.forEach(function (c) { (c.type === "dir" ? dirs : files).push(c); });
    if (!dirs.length && !files.length) {
      list.appendChild(noteEl("This folder is empty."));
      return;
    }
    dirs.forEach(function (c) { list.appendChild(dirRow(c)); });
    files.forEach(function (c) { list.appendChild(fileRow(c)); });
  }

  function dirRow(child) {
    var row = document.createElement("div");
    row.className = "frow";
    var open = document.createElement("button");
    open.type = "button";
    open.className = "frow-open is-dir";
    open.appendChild(tagEl("DIR"));
    open.appendChild(nameEl(child.name));
    open.appendChild(sizeEl("—"));
    open.addEventListener("click", function () {
      if (!child.node) { setFolderStatus("This directory has no node reference."); return; }
      folderStack.push({ name: child.name, node: child.node });
      showFolderLevel();
    });
    row.appendChild(open);
    return row;
  }

  function fileRow(child) {
    var row = document.createElement("div");
    row.className = "frow";
    var main = document.createElement("div");
    main.className = "frow-open";
    if (child.type === "symlink") {
      main.appendChild(tagEl("LINK"));
      main.appendChild(nameEl(child.name + " → " + (child.link || "")));
      main.appendChild(sizeEl(""));
      row.appendChild(main);
      return row;
    }
    main.appendChild(tagEl("FILE"));
    main.appendChild(nameEl(child.name));
    main.appendChild(sizeEl(formatSize(child.size || 0)));
    row.appendChild(main);

    var actions = document.createElement("div");
    actions.className = "frow-dl";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Download";
    btn.addEventListener("click", function () { downloadEntry(child, btn); });
    actions.appendChild(btn);
    row.appendChild(actions);
    return row;
  }

  function tagEl(text) { var s = document.createElement("span"); s.className = "frow-tag"; s.textContent = text; return s; }
  function nameEl(text) { var s = document.createElement("span"); s.className = "frow-name"; s.textContent = text; return s; }
  function sizeEl(text) { var s = document.createElement("span"); s.className = "frow-size"; s.textContent = text; return s; }
  function noteEl(text) { var p = document.createElement("p"); p.className = "file-note"; p.textContent = text; return p; }
  function setFolderStatus(text) { $("folder-status").textContent = text; $("folder-status").hidden = !text; }

  function browseErrorText(err) {
    var msg = String(err && err.message || err);
    if (msg === "gone") return "This link has expired or reached its read limit.";
    if (msg === "objects-unavailable") return "The server is no longer serving this folder's contents.";
    if (msg === "object-corrupt") return "A folder node failed its integrity check. The link may be altered.";
    if (msg === "newer-format") return "This folder was written by a newer aqt. Use the CLI.";
    if (msg === "no-decompressor") return "This browser could not load the decompressor.";
    if (msg === "truncated") return "The server returned an incomplete response. Try again.";
    return "Could not read this folder: " + msg;
  }

  /* ---------------- file assembly + download ------------------------- */

  // collectChunks fetches a file's content objects in size-bounded windows and
  // returns their decrypted plaintext parts in order, reporting progress by
  // decrypted bytes. Per-chunk content-addressing plus the authenticated chunk
  // list make a whole-file hash check redundant, so parts are never concatenated
  // into one contiguous buffer here.
  function collectChunks(chunks, onProgress) {
    var totalLen;
    try {
      // The caller gated on the entry's declared size; this gates on what the chunk
      // list actually references, which a hostile share can make far larger. It also
      // validates every declared length before any frame is fetched or decompressed.
      totalLen = boundedObjectBytes(chunks, maxDownloadBytes, maxDownloadBytes);
    } catch (err) {
      return Promise.reject(err);
    }
    var parts = new Array(chunks.length);
    var done = 0;
    var i = 0;

    function nextBatch() {
      if (i >= chunks.length) return Promise.resolve(parts);
      var start = i;
      var est = 0;
      var ids = [];
      while (i < chunks.length) {
        var next = est + (chunks[i].len || 0) + frameOverhead;
        if (ids.length && next > publicBatchBytes) break;
        est = next;
        ids.push(chunks[i].id);
        i++;
      }
      return fetchObjects(ids).then(function (frames) {
        for (var j = 0; j < frames.length; j++) {
          var ch = chunks[start + j];
          parts[start + j] = openObject(frames[j], ch, AAD_CHUNK, maxDownloadBytes);
          done += parts[start + j].length;
          if (onProgress) onProgress(done, totalLen);
        }
        return nextBatch();
      });
    }
    return nextBatch();
  }

  // resolveChunkList opens a file's indirect chunk-list segments and returns the
  // recovered chunk records.
  function resolveChunkList(segs) {
    var total;
    try {
      // Enforce both Go-side format limits before fzstd sees a frame. Checking the
      // decoded total afterwards is too late: fzstd allocates the declared output
      // size while each segment is opened.
      total = boundedObjectBytes(segs, maxChunkListSegmentBytes, maxChunkListBytes);
    } catch (err) {
      return Promise.reject(err);
    }
    return fetchObjects(segs.map(function (s) { return s.id; })).then(function (frames) {
      var plains = frames.map(function (frame, i) {
        return openObject(frame, segs[i], AAD_CHUNKLIST, maxChunkListSegmentBytes);
      });
      var joined = new Uint8Array(total);
      var off = 0;
      plains.forEach(function (p) { joined.set(p, off); off += p.length; });
      return JSON.parse(new TextDecoder().decode(joined));
    });
  }

  function saveParts(name, parts) {
    var url = URL.createObjectURL(new Blob(parts, { type: mimeFor(name) }));
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
  }

  // resolveEntryChunks yields a file entry's plaintext parts: inline bytes decode
  // in place; inline or indirect chunk lists fetch their content objects.
  function resolveEntryChunks(child, onProgress) {
    if (child.inline != null) {
      var rawLen = typeof child.size === "number" ? child.size : -1;
      return Promise.resolve([decompress(
        b64Decode(child.inline), child.inlineAlg || "", rawLen, maxDownloadBytes
      )]);
    }
    var listP = (child.chunksRef && child.chunksRef.length)
      ? resolveChunkList(child.chunksRef)
      : Promise.resolve(child.chunks || []);
    return listP.then(function (chunks) {
      if (!chunks.length) return [new Uint8Array(0)];
      return collectChunks(chunks, onProgress);
    });
  }

  function downloadEntry(child, btn) {
    if ((child.size || 0) > maxDownloadBytes) {
      setFolderStatus(child.name + " is " + formatSize(child.size) +
        " — too large to assemble in a browser tab. Pull it with the CLI: " + pullCmd);
      return;
    }
    setFolderStatus("");
    var label = btn.textContent;
    btn.disabled = true;
    btn.textContent = "0%";
    resolveEntryChunks(child, function (done, total) {
      btn.textContent = total ? Math.floor((done / total) * 100) + "%" : "…";
    }).then(function (parts) {
      saveParts(child.name, parts);
      btn.textContent = "Saved";
      setTimeout(function () { btn.textContent = label; btn.disabled = false; }, 1600);
    }).catch(function (err) {
      btn.textContent = "Failed";
      btn.disabled = false;
      setFolderStatus(child.name + ": " + browseErrorText(err));
      setTimeout(function () { btn.textContent = label; }, 2000);
    });
  }

  /* ---------------- streamed single file ----------------------------- */

  function startStreamedFile(root, meta) {
    var name = meta.name || RES_ID;
    var size = typeof root.size === "number" ? root.size : (meta.size || 0);
    setHeadline(name);
    $("meta-size").textContent = formatSize(size);
    $("meta-size").hidden = false;
    $("file-name").textContent = name;
    $("file-size").textContent = formatSize(size);
    ["act-raw", "act-copy", "act-download"].forEach(function (id) { $(id).hidden = true; });

    var body = $("file-body");
    body.textContent = "";
    if (size > maxDownloadBytes) {
      fail("This file is " + formatSize(size) + ".",
        "It is too large to assemble safely in a browser tab.");
      return;
    }
    var wrap = document.createElement("div");
    wrap.className = "download-prompt";
    wrap.appendChild(noteEl("A large streamed file. Decrypt and download it in your browser:"));
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn";
    btn.textContent = "Download";
    btn.addEventListener("click", function () { downloadStreamed(name, root, btn); });
    wrap.appendChild(btn);
    body.appendChild(wrap);
    show("state-file");
  }

  function downloadStreamed(name, root, btn) {
    var label = btn.textContent;
    btn.disabled = true;
    btn.textContent = "0%";
    var listP = (root.chunkList && root.chunkList.length)
      ? resolveChunkList(root.chunkList)
      : Promise.resolve(root.chunks || []);
    listP.then(function (chunks) {
      if (!chunks.length) return [new Uint8Array(0)];
      return collectChunks(chunks, function (done, total) {
        btn.textContent = total ? Math.floor((done / total) * 100) + "%" : "…";
      });
    }).then(function (parts) {
      saveParts(name, parts);
      btn.textContent = "Saved";
      setTimeout(function () { btn.textContent = label; btn.disabled = false; }, 1600);
    }).catch(function (err) {
      btn.textContent = "Download";
      btn.disabled = false;
      var note = noteEl(browseErrorText(err));
      note.className = "file-note dl-error";
      btn.parentNode.appendChild(note);
    });
  }

  /* ---------------- fetch + decrypt flow ----------------------------- */

  function preflightPolicyText(preflight) {
    var notes = [];
    if (preflight.expiresAt) {
      notes.push("expires " + new Date(preflight.expiresAt * 1000).toLocaleString());
    }
    if (preflight.maxReads) {
      notes.push((preflight.maxReads - (preflight.reads || 0)) + " read(s) remain; decrypting consumes one");
    }
    return notes.length ? notes.join(" · ") : "This link has no server-enforced expiry or read limit.";
  }

  function prepareFlow(keyPromise) {
    if (!AqtCrypto.ready) {
      fail("Browser decryption is unavailable.", "This browser could not load the local crypto runtime.");
      return;
    }
    show("state-busy");
    $("busy-step").textContent = "INSPECTING ENCRYPTED METADATA";
    var key;
    Promise.resolve(AqtCrypto.ready)
      .then(function () { return new Promise(function (r) { setTimeout(r, 30); }); })
      .then(keyPromise)
      .then(function (derivedKey) { key = derivedKey; return fetchPreflight(); })
      .then(function (preflight) {
        var metaPlain = openBound(preflight.encryptedMeta, key, "meta", RES_ID);
        if (metaPlain === null) throw new Error("wrong-key");
        var meta = JSON.parse(new TextDecoder().decode(metaPlain));
        if (meta.kind === "folder" && (meta.packed || !meta.tree)) throw new Error("unsupported:packed");
        if ((meta.size || 0) > maxDownloadBytes) throw new Error("unsupported:large");
        $("policy-note").textContent = preflightPolicyText(preflight);
        $("decrypt-btn").onclick = function () { decryptFlow(function () { return Promise.resolve(key); }, meta); };
        show("state-locked");
        $("decrypt-btn").focus();
      })
      .catch(function (err) {
        var msg = String(err && err.message || err);
        if (msg === "wrong-password") {
          show("state-password");
          $("password-error").textContent = "Wrong password: the key failed to unwrap.";
          $("password-error").hidden = false;
          $("password-input").focus();
        } else if (msg === "wrong-key") {
          fail("The key does not fit.", "The fragment cannot authenticate the encrypted metadata.");
        } else if (msg === "gone") {
          fail("This link is closed.", "It has expired or reached its read limit.");
        } else if (msg === "not-public") {
          fail("This resource is not public.", "It may be private, deleted, or the link may be incomplete.");
        } else if (msg === "unsupported:packed") {
          fail("This folder needs the CLI.", "Packed or legacy folders are inspected without consuming a read.");
        } else if (msg === "unsupported:large") {
          fail("This resource needs the CLI.", "It is too large to assemble safely in a browser tab; no read was consumed.");
        } else {
          fail("Could not inspect this share.", msg);
        }
      });
  }

  function decryptFlow(keyPromise, knownMeta) {
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
        var meta = knownMeta;
        if (!meta) {
          var metaPlain = openBound(resource.encryptedMeta, key, "meta", RES_ID);
          if (metaPlain === null) throw new Error("wrong-key");
          meta = JSON.parse(new TextDecoder().decode(metaPlain));
        }

        if (meta.kind === "folder") {
          if (meta.packed || !meta.tree) throw new Error("unsupported:packed");
          var rootPlain = openBound(resource.blob, key, "treeroot", RES_ID);
          if (rootPlain === null) throw new Error("wrong-key");
          startFolder(JSON.parse(new TextDecoder().decode(rootPlain)), meta);
          return;
        }
        if (meta.streamed) {
          var frPlain = openBound(resource.blob, key, "blob", RES_ID);
          if (frPlain === null) throw new Error("wrong-key");
          startStreamedFile(JSON.parse(new TextDecoder().decode(frPlain)), meta);
          return;
        }
        var plain = openBound(resource.blob, key, "blob", RES_ID);
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
        } else if (msg === "gone") {
          fail("This link is closed.", "It has expired or reached its read limit.");
        } else if (msg === "not-public") {
          fail("This resource is not public.", "It may be private, deleted, or the link may be incomplete.");
        } else if (msg.indexOf("unsupported:") === 0) {
          fail("This is a packed folder.", "In-browser decryption covers chunked folders, single files, and streamed files.");
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

  function mimeFor(name) {
    var ext = name.indexOf(".") > 0 ? name.split(".").pop().toLowerCase() : "";
    return MIME[ext] || "application/octet-stream";
  }

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
    var mime = mimeFor(name);
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
  wireCopy("folder-copy", function () { return pullCmd; });
  $("show-cli-btn").addEventListener("click", function () { show("state-cli"); });

  var frag = parseFragment(window.location.hash);

  if (!window.location.hash) {
    show("state-cli");
  } else if (frag === null) {
    fail("The key fragment is malformed.", "The part after # is not a valid aqt key.");
  } else if (frag.kind === "public") {
    prepareFlow(function () { return Promise.resolve(frag.key); });
  } else {
    show("state-password");
    $("password-form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pw = $("password-input").value;
      if (!pw) {
        $("password-error").textContent = "Enter the share password.";
        $("password-error").hidden = false;
        $("password-input").focus();
        return;
      }
      $("password-input").value = "";
      $("password-error").hidden = true;
      prepareFlow(function () {
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
