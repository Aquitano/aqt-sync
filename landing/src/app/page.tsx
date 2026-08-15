// SPDX-License-Identifier: AGPL-3.0-or-later

import Image from "next/image";
import { InstallPicker } from "@/components/install-picker";
import { MotionLayer } from "@/components/motion-layer";

const markPixels = [
  1, 1, 1, 0, 0, 1,
  1, 0, 1, 1, 0, 1,
  1, 1, 1, 1, 1, 1,
  0, 1, 0, 1, 0, 0,
  0, 1, 1, 1, 1, 0,
  0, 0, 1, 1, 1, 1,
];

function PixelMark({ compact = false }: { compact?: boolean }) {
  return (
    <span className={compact ? "pixel-mark pixel-mark-small" : "pixel-mark"} aria-hidden="true">
      {markPixels.map((pixel, index) => (
        <span key={index} data-pixel={pixel ? "" : undefined} className={pixel ? "pixel-on" : "pixel-off"} />
      ))}
    </span>
  );
}

function CornerMarks() {
  return (
    <span className="corner-marks" aria-hidden="true">
      <i />
      <i />
      <i />
      <i />
    </span>
  );
}

function HatchLine({ label }: { label?: string }) {
  return (
    <div className="hatch-line" aria-hidden="true">
      {label ? <span className="hatch-label">{label}</span> : null}
      <span className="hatch" />
    </div>
  );
}

const dagNodes = [
  { cx: 100, cy: 15 },
  { cx: 52, cy: 59 },
  { cx: 148, cy: 59 },
  { cx: 22, cy: 103 },
  { cx: 178, cy: 103 },
];

const dagEdges = [
  "M100 15L52 59",
  "M100 15L148 59",
  "M52 59L22 103",
  "M52 59L100 103",
  "M148 59L178 103",
  "M148 59L100 103",
].join("");

// The hollow chunk hangs from both parents that reference it: one copy stored, two
// places in the tree pointing at it. That shared node is what dedup looks like.
function DagDiagram() {
  return (
    <svg className="dag-diagram" viewBox="0 0 200 114" aria-hidden="true">
      <path d={dagEdges} fill="none" stroke="currentColor" strokeOpacity="0.5" strokeWidth="1.5" />
      {dagNodes.map((node) => (
        <rect key={`${node.cx}-${node.cy}`} x={node.cx - 7} y={node.cy - 7} width="14" height="14" fill="currentColor" />
      ))}
      <rect x="93" y="96" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" />
    </svg>
  );
}

const triptychPanels = [
  { src: "/halftone-blocks.webp", caption: "Blocks", alt: "Halftone artwork of stacked encrypted data blocks" },
  { src: "/halftone-object.webp", caption: "Sealed object", alt: "Halftone artwork of pixels converging into a sealed case" },
  { src: "/halftone-network.webp", caption: "Network", alt: "Halftone artwork of a radio tower carrying beams of data" },
];

const workflow = [
  {
    verb: "Push",
    title: "Seal a file in one line.",
    body: "Private is the default. Add --public only when you intend to share.",
    command: "aqt push secret.env",
    output: "aqt://7yQ2pe",
    meta: "encrypted / private / copied",
  },
  {
    verb: "Sync",
    title: "Track folders like git.",
    body: "Two-way sync that merges non-overlapping text edits and keeps a conflict copy when they collide. Preview any of it with aqt diff, or let aqt watch run it for you.",
    command: "aqt sync ~/vault --conflicts=merge",
    output: "~ merged notes/plan.md",
    meta: "content addressed / deduplicated",
  },
  {
    verb: "Recover",
    title: "Prove the restore works.",
    body: "Clone on a clean machine or roll a tracked folder back to an anchored checkpoint.",
    command: "aqt restore pre-release",
    output: "restored ~/vault",
    meta: "verified / byte exact",
  },
];

const tuiKeys = [
  { key: "s", action: "sync" },
  { key: "c", action: "checkpoint" },
  { key: "d", action: "diff" },
  { key: "R", action: "restore" },
];

const specRows = [
  { term: "Cipher", detail: "XChaCha20-Poly1305, role-separated AADs" },
  { term: "KDF", detail: "Argon2id, calibrated on your device" },
  { term: "Keys", detail: "Derived locally, never transmitted" },
  { term: "Server stores", detail: "Ciphertext and opaque IDs" },
  { term: "Transport", detail: "HTTPS enforced off loopback" },
  { term: "Updates", detail: "Ed25519-signed manifest, verified before install" },
];

export default function Home() {
  return (
    <div className="min-h-[100dvh] overflow-x-clip bg-[var(--paper)] text-[var(--ink)]">
      <header className="site-nav">
        <a className="brand" href="#top" aria-label="aqt home">
          <PixelMark compact />
          <span>aqt</span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#features">Features</a>
          <a href="#workflow">Workflow</a>
          <a href="#security">Security</a>
        </nav>
        <a className="nav-cta" href="#install">Install aqt</a>
      </header>

      <main id="top">
        <section className="hero poster-section min-h-[calc(100dvh-72px)]" aria-labelledby="hero-title">
          <CornerMarks />
          <div className="hero-copy">
            <p data-hero-kicker className="eyebrow">Zero-knowledge sync for developers</p>
            <h1 id="hero-title">
              <span className="hero-line"><span data-hero-line>Every file.</span></span>
              <span className="hero-line"><span data-hero-line>Only yours.</span></span>
            </h1>
            <p data-hero-copy className="hero-lede">
              Encrypted file and folder sync that keeps filenames, contents, and keys invisible to the server.
            </p>
            <div data-hero-actions className="hero-actions">
              <a className="button button-dark" href="#install">Install aqt</a>
              <a className="text-link" href="#features">Explore features <span aria-hidden="true">&#8600;</span></a>
            </div>
          </div>

          <div data-hero-visual className="hero-poster frame">
            <CornerMarks />
            <div className="poster-topline">
              <span>AQT / SYNC</span>
              <span>LOCAL FIRST</span>
            </div>
            <div className="poster-center">
              <span className="poster-rules" aria-hidden="true"><i /><i /><i /><i /></span>
              <PixelMark />
              <div className="poster-word" aria-hidden="true">aqt</div>
            </div>
            <HatchLine label="XCHACHA20 / ARGON2ID / CIPHERTEXT" />
            <div className="poster-command">
              <span className="prompt">$</span>
              <code>aqt sync ~/vault</code>
              <span className="command-result">ciphertext pushed</span>
            </div>
          </div>
        </section>

        <section className="manifesto poster-section section-pad" aria-labelledby="manifesto-title">
          <CornerMarks />
          <div data-reveal className="manifesto-type" aria-hidden="true">
            <span>PRIVATE</span>
            <span>BY DEFAULT</span>
          </div>
          <div className="manifesto-copy">
            <h2 id="manifesto-title" data-reveal>The storage provider is no longer a trusted party.</h2>
            <p data-reveal>
              aqt encrypts locally with XChaCha20-Poly1305. Your root key never leaves your device, and your server only coordinates opaque objects.
            </p>
            <div className="knowledge-grid" data-reveal>
              <div><span>Server sees</span><strong>Opaque IDs</strong></div>
              <div><span>Server stores</span><strong>Ciphertext</strong></div>
              <div><span>Server cannot read</span><strong>Names or files</strong></div>
              <div><span>You control</span><strong>Every key</strong></div>
            </div>
          </div>
        </section>

        <section id="features" className="features poster-section section-pad" aria-labelledby="features-title">
          <CornerMarks />
          <div className="section-heading" data-reveal>
            <h2 id="features-title">Built for the whole life of a file.</h2>
            <p>Push it once, keep a folder in sync, back a repository up, share it safely, or recover it years later.</p>
            <HatchLine label="PUSH / SYNC / SHARE / GIT / SNAPSHOT / RESTORE" />
          </div>
          <div className="feature-grid" data-feature-grid>
            <article data-feature className="feature-cell feature-zero">
              <CornerMarks />
              <p className="feature-label">Zero knowledge</p>
              <div className="feature-visual" aria-hidden="true">
                <div className="dissolve-caption"><span>PLAINTEXT</span><span>CIPHERTEXT</span></div>
                <div className="dissolve-band" />
              </div>
              <h3>Nothing readable reaches the server.</h3>
              <p>Filenames, file contents, metadata, and keys are encrypted on your machine before upload.</p>
            </article>

            <article data-feature className="feature-cell feature-dag">
              <CornerMarks />
              <p className="feature-label">Content addressed</p>
              <div className="feature-visual" aria-hidden="true">
                <DagDiagram />
                <p className="visual-caption">ROOT / CHUNKS / DEDUP</p>
              </div>
              <h3>Sync less. Restore faster.</h3>
              <p>Folders become a Merkle DAG of encrypted chunks with per-account deduplication.</p>
            </article>

            <article data-feature className="feature-cell feature-links">
              <CornerMarks />
              <p className="feature-label">Private sharing</p>
              <div className="feature-visual" aria-hidden="true">
                <p className="link-anatomy">
                  <span>aqt.sh/x/9fK2qd</span>
                  <span className="link-fragment">#k.Hs7nT4</span>
                </p>
                <p className="visual-caption">EXPIRY / BURN / ACCOUNT GRANTS</p>
              </div>
              <h3>The key stays after the #.</h3>
              <p>Public links keep their key after the #. For private account grants, aqt share --with gives read-only access, aqt shares lists incoming grants, and aqt contacts pins recipient keys.</p>
            </article>

            <article data-feature className="feature-cell feature-git">
              <CornerMarks />
              <p className="feature-label">Encrypted Git remotes</p>
              <div className="feature-visual" aria-hidden="true">
                <div className="snap-rows">
                  <code><span>$</span> aqt repo create notes</code>
                  <code><span>$</span> git remote add origin aqt::notes</code>
                  <code><span>$</span> git push -u origin main</code>
                </div>
                <p className="visual-caption">BUNDLES / REFS / CIPHERTEXT</p>
              </div>
              <h3>Push history, not a .git folder.</h3>
              <p>Git owns commits, refs, and merges; aqt stores the bundles as ciphertext. Clone, fetch, push, tags, and ref deletion all work through the same binary, and the server never sees a path, a ref, or an object.</p>
            </article>

            <article data-feature className="feature-cell feature-history">
              <CornerMarks />
              <p className="feature-label">Snapshots</p>
              <div className="feature-visual" aria-hidden="true">
                <div className="snap-rows">
                  <code><span>$</span> aqt checkpoint pre-release</code>
                  <code><span>$</span> aqt snapshot diff &lt;id&gt;</code>
                  <code><span>$</span> aqt restore pre-release</code>
                </div>
              </div>
              <h3>Checkpoint what matters.</h3>
              <p>Anchor named snapshots, compare them with the live tree, and restore in place or beside it.</p>
            </article>

            <article data-feature className="feature-cell feature-tui">
              <CornerMarks />
              <p className="feature-label">Terminal UI</p>
              <div className="feature-visual" aria-hidden="true">
                <div className="tui-mock">
                  <div className="tui-pane">
                    <p><span>changes</span></p>
                    <p><span><b>M</b>notes/plan.md</span></p>
                    <p><span><b>+</b>assets/logo.png</span></p>
                  </div>
                  <div className="tui-pane">
                    <p><span>snapshots</span></p>
                    <p><span>pre-release</span><span className="tui-meta">anchored</span></p>
                    <p><span>auto</span><span className="tui-meta">today 21:04</span></p>
                  </div>
                </div>
                <p className="tui-keys">
                  {tuiKeys.map((key) => (
                    <span key={key.key}><b>{key.key}</b>{key.action}</span>
                  ))}
                </p>
              </div>
              <h3>The whole vault on one screen.</h3>
              <p>aqt tui is a lazygit-style dashboard. Live changes, snapshots, and shares, driven by single-key actions that run real aqt commands.</p>
            </article>
          </div>
        </section>

        <section data-triptych className="triptych-section poster-section section-pad" aria-labelledby="triptych-title">
          <CornerMarks />
          <div className="triptych-head" data-reveal>
            <h2 id="triptych-title">From plaintext to sealed matter.</h2>
            <p>Blocks converge, encrypt, and move. The network only carries what it cannot understand.</p>
          </div>
          <div className="triptych-frames">
            {triptychPanels.map((panel) => (
              <figure key={panel.caption} className="triptych-panel frame" data-triptych-panel>
                <CornerMarks />
                <div className="triptych-media">
                  <Image
                    data-triptych-image
                    src={panel.src}
                    alt={panel.alt}
                    width={880}
                    height={880}
                    sizes="(max-width: 767px) 90vw, 30vw"
                  />
                </div>
                <figcaption>{panel.caption}</figcaption>
              </figure>
            ))}
          </div>
        </section>

        <section id="workflow" data-horizontal className="workflow" aria-labelledby="workflow-title">
          <div data-horizontal-track className="workflow-track">
            {workflow.map((step, index) => (
              <article className={`workflow-panel workflow-panel-${index + 1}`} key={step.verb}>
                <div className="workflow-copy">
                  {index === 0 ? <h2 id="workflow-title">One binary. Three essential moves.</h2> : null}
                  <p className="workflow-verb" aria-hidden="true">{step.verb}</p>
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                </div>
                <div className="terminal-card">
                  <div className="terminal-title"><span>AQT SHELL</span><span>LOCAL</span></div>
                  <code><span>$</span> {step.command}</code>
                  <code className="terminal-output">{step.output}</code>
                  <p>{step.meta}</p>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section id="security" className="security poster-section section-pad" aria-labelledby="security-title">
          <CornerMarks />
          <div className="security-heading" data-reveal>
            <p className="eyebrow">A key hierarchy you can reason about</p>
            <h2 id="security-title">The secret stops at your machine.</h2>
          </div>
          <div className="crypto-flow" data-reveal>
            <div className="crypto-node"><span>Your input</span><strong>Passphrase</strong></div>
            <span className="flow-arrow" aria-hidden="true">&#8594;</span>
            <div className="crypto-node"><span>Memory-hard KDF</span><strong>Argon2id</strong></div>
            <span className="flow-arrow" aria-hidden="true">&#8594;</span>
            <div className="crypto-node"><span>Unlocks locally</span><strong>Root key</strong></div>
            <span className="flow-arrow" aria-hidden="true">&#8594;</span>
            <div className="crypto-node"><span>Seals every resource</span><strong>XChaCha20</strong></div>
          </div>
          <div className="security-grid">
            <div className="spec-card frame" data-reveal>
              <CornerMarks />
              <div className="spec-glyph" aria-hidden="true"><i /><i /><i /><i /><i /></div>
              <dl className="spec-rows">
                {specRows.map((row) => (
                  <div key={row.term}>
                    <dt>{row.term}</dt>
                    <dd>{row.detail}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="security-proof" data-reveal>
              <p>Share links place the content key in the browser fragment.</p>
              <code>https://aqt.sh/x/9fK2qd<span>#k.Hs7nT4...</span></code>
              <p>The fragment never appears in the HTTP request.</p>
            </div>
          </div>
        </section>

        <section className="self-host poster-section section-pad" aria-labelledby="host-title">
          <CornerMarks />
          <div className="host-copy" data-reveal>
            <h2 id="host-title">Own the machine. Or rent one.</h2>
            <p>
              aqt-server is a static Go binary backed by SQLite and a ciphertext data directory. Put it behind Caddy, systemd, or Docker.
            </p>
            <p>
              Accounts are managed from the data directory, not a privileged HTTP surface: inspect one, cap its storage, suspend it, or erase it and sweep its ciphertext, with any file left behind named in the receipt.
            </p>
            <a className="text-link text-link-light" href="https://github.com/aquitano/aqt-sync/blob/main/docs/deploy.md">Read the deploy guide <span aria-hidden="true">&#8599;</span></a>
          </div>
          <div className="host-ticket frame" data-reveal>
            <div className="ticket-head">
              <span>AQT-SERVER</span>
              <span>SELF-HOSTED</span>
            </div>
            <code>
              <span>$</span> AQT_DATA_DIR=./aqt-data ./bin/aqt-server{"\n"}
              <span>$</span> aqt-server admin accounts quota you@example.com 20GB
            </code>
            <HatchLine />
            <div className="host-specs">
              <span>SQLite</span><span>Prometheus</span><span>Native TLS</span><span>Pure Go</span>
            </div>
          </div>
        </section>

        <section id="install" className="install poster-section" aria-labelledby="install-title">
          <CornerMarks />
          <div data-reveal>
            <PixelMark compact />
            <h2 id="install-title">Your files are ready to disappear.</h2>
            <p>From everyone except you.</p>
          </div>
          <InstallPicker />
          <a className="button button-dark" href="https://github.com/aquitano/aqt-sync">View on GitHub</a>
        </section>
      </main>

      <footer className="site-footer">
        <div className="lockup" aria-hidden="true">
          <span className="lockup-rules"><i /><i /><i /><i /></span>
          <PixelMark />
          <span className="lockup-word">aqt</span>
        </div>
        <div className="footer-meta">
          <div className="footer-tag">
            <p>Every file. Only yours.</p>
            <HatchLine />
          </div>
          <div className="footer-links">
            <a href="https://github.com/aquitano/aqt-sync">GitHub</a>
            <a href="https://github.com/aquitano/aqt-sync/blob/main/docs/architecture.md">Protocol</a>
            <a href="https://github.com/aquitano/aqt-sync/blob/main/docs/git-repositories.md">Git remotes</a>
            <a href="https://github.com/aquitano/aqt-sync/blob/main/docs/deploy.md">Deploy</a>
            <a href="https://github.com/aquitano/aqt-sync/blob/main/LICENSE">AGPL-3.0</a>
          </div>
        </div>
      </footer>

      <MotionLayer />
    </div>
  );
}
