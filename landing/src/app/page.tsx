// SPDX-License-Identifier: AGPL-3.0-or-later

import Image from "next/image";
import { InstallPicker } from "@/components/install-picker";
import { MotionLayer } from "@/components/motion-layer";
import { markPixels } from "./mark";

function PixelMark({ className = "pixel-mark" }: { className?: string }) {
  return (
    <span className={className} aria-hidden="true">
      {markPixels.map((pixel, index) => (
        <span key={index} data-pixel={pixel ? "" : undefined} className={pixel ? "pixel-on" : "pixel-off"} />
      ))}
    </span>
  );
}

// One span per glyph so the decrypt animation can lock each cell to its final width;
// scrambling a proportional face without that reflows the line on every frame.
function HeroLine({ text }: { text: string }) {
  return (
    <span className="hero-line">
      {text.split(" ").map((word, wordIndex) => (
        <span key={wordIndex} className="hero-word">
          {wordIndex > 0 ? " " : null}
          {[...word].map((glyph, glyphIndex) => (
            <span key={glyphIndex} data-hero-char>{glyph}</span>
          ))}
        </span>
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

const dagEdges = [
  "M100 15L52 59",
  "M100 15L148 59",
  "M52 59L22 103",
  "M52 59L100 103",
  "M148 59L178 103",
  "M148 59L100 103",
].join("");

const dagNodes = [
  { cx: 100, cy: 15 },
  { cx: 52, cy: 59 },
  { cx: 148, cy: 59 },
  { cx: 22, cy: 103 },
  { cx: 178, cy: 103 },
];

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
  },
  {
    verb: "Sync",
    title: "Track folders like git.",
    body: "Two-way sync that merges non-overlapping text edits and keeps a conflict copy when they collide. Preview any of it with aqt diff, or let aqt watch run it for you.",
    command: "aqt sync ~/vault --conflicts=merge",
    output: "~ merged notes/plan.md",
  },
  {
    verb: "Recover",
    title: "Prove the restore works.",
    body: "Clone on a clean machine or roll a tracked folder back to an anchored checkpoint.",
    command: "aqt restore pre-release",
    output: "restored ~/vault",
  },
];

const keyChain = [
  { term: "Passphrase", detail: "Your input." },
  { term: "Argon2id", detail: "Memory-hard KDF, calibrated on your device." },
  { term: "Root key", detail: "Unlocked locally, never transmitted." },
  { term: "XChaCha20-Poly1305", detail: "Seals every resource with role-separated AADs." },
];

const specGroups = [
  {
    name: "Cryptography",
    rows: [
      { term: "Cipher", detail: "XChaCha20-Poly1305" },
      { term: "KDF", detail: "Argon2id" },
      { term: "Keys", detail: "Derived locally" },
    ],
  },
  {
    name: "Server and transport",
    rows: [
      { term: "Server stores", detail: "Ciphertext, opaque IDs" },
      { term: "Transport", detail: "HTTPS off loopback" },
      { term: "Updates", detail: "Ed25519-signed manifest" },
    ],
  },
];

const serverTags = ["SQLite", "Prometheus", "Native TLS", "Pure Go"];

export default function Home() {
  return (
    <div className="site">
      <header className="site-nav">
        <a className="brand" href="#top" aria-label="aqt home">
          <PixelMark className="pixel-mark pixel-mark-small" />
          <span>aqt</span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#features">Features</a>
          <a href="#workflow">Workflow</a>
          <a href="#security">Security</a>
        </nav>
        <a className="button button-dark button-small" href="#install">Install aqt</a>
      </header>

      <main id="top">
        <section className="poster-section hero" aria-labelledby="hero-title">
          <CornerMarks />
          <div className="hero-copy">
            <p data-hero-kicker className="kicker">Zero-knowledge sync for developers</p>
            <h1 id="hero-title">
              <HeroLine text="Every file." />
              <HeroLine text="Only yours." />
            </h1>
            <p data-hero-copy className="hero-lede">
              Encrypted file and folder sync that keeps filenames, contents, and keys invisible to the server.
            </p>
            <div data-hero-actions className="hero-actions">
              <a className="button button-dark" href="#install">Install aqt</a>
              <a className="text-link" href="#features">Explore features</a>
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
              <PixelMark className="pixel-mark pixel-mark-poster" />
              <div className="poster-word" aria-hidden="true">aqt</div>
            </div>
            <span className="hatch" aria-hidden="true" />
            <div className="poster-command">
              <span className="prompt">$</span>
              <code>aqt sync ~/vault</code>
            </div>
          </div>
        </section>

        <section className="poster-section manifesto section-pad" aria-labelledby="manifesto-title">
          <CornerMarks />
          <div className="manifesto-copy" data-reveal>
            <h2 id="manifesto-title">The storage provider is no longer a trusted party.</h2>
            <p>
              aqt encrypts locally with XChaCha20-Poly1305. Your root key never leaves your device, and your server only coordinates opaque objects.
            </p>
          </div>
          <div className="knowledge-grid" data-reveal>
            <div><span>Server sees</span><strong>Opaque IDs</strong></div>
            <div><span>Server stores</span><strong>Ciphertext</strong></div>
            <div><span>Server cannot read</span><strong>Names or files</strong></div>
            <div><span>You control</span><strong>Every key</strong></div>
          </div>
        </section>

        <section id="features" className="poster-section features section-pad" aria-labelledby="features-title">
          <CornerMarks />
          <div className="section-heading" data-reveal>
            <h2 id="features-title">Built for the whole life of a file.</h2>
            <p>Push it once, keep a folder in sync, back a repository up, share it safely, or recover it years later.</p>
          </div>
          <div className="feature-grid" data-feature-grid>
            <article data-feature className="feature-cell">
              <p className="feature-label">aqt push</p>
              <div className="feature-screen" aria-hidden="true">
                <div className="ledger-wrap">
                  <pre className="ledger">
                    <span>notes/plan.md</span><b>7yQ2peKd9m3f…</b>{"\n"}
                    <span>assets/logo.png</span><b>3fHq0ZsBt2Lq…</b>{"\n"}
                    <span>secret.env</span><b>xL8wR1vQe4Nn…</b>
                  </pre>
                  <span className="dissolve-band" />
                </div>
              </div>
              <h3>Nothing readable reaches the server.</h3>
              <p>Filenames, file contents, metadata, and keys are encrypted on your machine before upload.</p>
            </article>

            <article data-feature className="feature-cell">
              <p className="feature-label">aqt sync</p>
              <div className="feature-screen" aria-hidden="true">
                <DagDiagram />
              </div>
              <h3>Sync less. Restore faster.</h3>
              <p>Folders become a Merkle DAG of encrypted chunks with per-account deduplication.</p>
            </article>

            <article data-feature className="feature-cell">
              <p className="feature-label">aqt share</p>
              <div className="feature-screen" aria-hidden="true">
                <p className="link-anatomy">
                  <span>aqt.sh/x/9fK2qd</span>
                  <span className="link-fragment">#k.Hs7nT4</span>
                  <span className="screen-caption">expiry / burn / account grants</span>
                </p>
              </div>
              <h3>The key stays after the #.</h3>
              <p>Public links carry their key in the fragment. For private grants, aqt share --with gives read-only access and aqt contacts pins recipient keys.</p>
            </article>

            <article data-feature className="feature-cell">
              <p className="feature-label">git push</p>
              <div className="feature-screen" aria-hidden="true">
                <pre className="snap-rows">
                  <span>$</span> aqt repo create notes{"\n"}
                  <span>$</span> git remote add origin aqt::notes{"\n"}
                  <span>$</span> git push -u origin main
                </pre>
              </div>
              <h3>Push history, not a .git folder.</h3>
              <p>Git owns commits, refs, and merges; aqt stores the bundles as ciphertext. The server never sees a path, a ref, or an object.</p>
            </article>

            <article data-feature className="feature-cell">
              <p className="feature-label">aqt checkpoint</p>
              <div className="feature-screen" aria-hidden="true">
                <pre className="snap-rows">
                  <span>$</span> aqt checkpoint pre-release{"\n"}
                  <span>$</span> aqt snapshot diff &lt;id&gt;{"\n"}
                  <span>$</span> aqt restore pre-release
                </pre>
              </div>
              <h3>Checkpoint what matters.</h3>
              <p>Anchor named snapshots, compare them with the live tree, and restore in place or beside it.</p>
            </article>

            <article data-feature className="feature-cell">
              <p className="feature-label">aqt tui</p>
              <div className="feature-screen tui-mock" aria-hidden="true">
                <pre className="tui-pane">
                  <span>changes</span>{"\n"}
                  M  notes/plan.md{"\n"}
                  +  assets/logo.png
                </pre>
                <pre className="tui-pane">
                  <span>snapshots</span>{"\n"}
                  pre-release  <span>anchored</span>{"\n"}
                  auto         <span>21:04</span>
                </pre>
              </div>
              <h3>The whole vault on one screen.</h3>
              <p>A lazygit-style dashboard. Live changes, snapshots, and shares, driven by single-key actions that run real aqt commands.</p>
            </article>
          </div>
        </section>

        <section className="poster-section triptych section-pad" aria-labelledby="triptych-title">
          <CornerMarks />
          <div className="section-heading" data-reveal>
            <h2 id="triptych-title">From plaintext to sealed matter.</h2>
            <p>Blocks converge, encrypt, and move. The network only carries what it cannot understand.</p>
          </div>
          <div className="triptych-frames">
            {triptychPanels.map((panel) => (
              <figure key={panel.caption} className="triptych-panel">
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

        <section id="workflow" className="poster-section workflow section-pad" aria-labelledby="workflow-title">
          <CornerMarks />
          <h2 id="workflow-title" data-reveal>One binary. Three essential moves.</h2>
          <div className="workflow-grid" data-workflow-grid>
            {workflow.map((step, index) => (
              <article data-workflow className="workflow-card" key={step.verb}>
                <div className="workflow-copy">
                  <span className="workflow-index">{index + 1}</span>
                  <p className="workflow-verb" aria-hidden="true">{step.verb}</p>
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                </div>
                <pre className="terminal">
                  <span className="prompt">$</span> {step.command}{"\n"}
                  <span className="terminal-output">{step.output}</span>
                </pre>
              </article>
            ))}
          </div>
        </section>

        <section id="security" className="poster-section security section-pad" aria-labelledby="security-title">
          <CornerMarks />
          <div className="section-heading" data-reveal>
            <h2 id="security-title">The secret stops at your machine.</h2>
            <p>A key hierarchy you can reason about, from the passphrase you type to the ciphertext the server keeps.</p>
          </div>
          <div className="security-grid">
            <ol className="key-chain" data-reveal>
              {keyChain.map((link) => (
                <li key={link.term}>
                  <strong>{link.term}</strong>
                  <span>{link.detail}</span>
                </li>
              ))}
            </ol>
            <div className="security-detail" data-reveal>
              <div className="spec-groups">
                {specGroups.map((group) => (
                  <dl key={group.name} className="spec-group">
                    <p>{group.name}</p>
                    {group.rows.map((row) => (
                      <div key={row.term}>
                        <dt>{row.term}</dt>
                        <dd>{row.detail}</dd>
                      </div>
                    ))}
                  </dl>
                ))}
              </div>
              <div className="security-proof">
                <p>Share links place the content key in the browser fragment. It never appears in the HTTP request.</p>
                <code>https://aqt.sh/x/9fK2qd<span>#k.Hs7nT4…</span></code>
              </div>
            </div>
          </div>
        </section>

        <section className="poster-section self-host section-pad" aria-labelledby="host-title">
          <CornerMarks />
          <div className="host-copy" data-reveal>
            <h2 id="host-title">Own the machine. Or rent one.</h2>
            <p>
              aqt-server is a static Go binary backed by SQLite and a ciphertext data directory. Put it behind Caddy, systemd, or Docker.
            </p>
            <p>
              Accounts are managed from the data directory, not a privileged HTTP surface: inspect one, cap its storage, suspend it, or erase it and sweep its ciphertext, with any file left behind named in the receipt.
            </p>
            <a className="text-link" href="https://github.com/aquitano/aqt-sync/blob/main/docs/deploy.md">Read the deploy guide</a>
          </div>
          <div className="host-card frame" data-reveal>
            <CornerMarks />
            <div className="panel-topline">
              <span>aqt-server</span>
              <span>self-hosted</span>
            </div>
            <pre className="terminal terminal-bare">
              <span className="prompt">$</span> AQT_DATA_DIR=./aqt-data ./bin/aqt-server{"\n"}
              <span className="prompt">$</span> aqt-server admin accounts quota you@example.com 20GB
            </pre>
            <ul className="host-tags">
              {serverTags.map((tag) => (
                <li key={tag}>{tag}</li>
              ))}
            </ul>
          </div>
        </section>

        <section id="install" className="poster-section install section-pad" aria-labelledby="install-title">
          <CornerMarks />
          <div className="install-copy" data-reveal>
            <h2 id="install-title">Your files are ready to disappear.</h2>
            <p>From everyone except you.</p>
          </div>
          <div className="install-panel">
            <InstallPicker />
            <a className="button button-dark" href="https://github.com/aquitano/aqt-sync">View on GitHub</a>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div className="lockup" aria-hidden="true">
          <PixelMark className="pixel-mark pixel-mark-footer" />
          <span className="lockup-word">aqt</span>
        </div>
        <div className="footer-meta">
          <p>Every file. Only yours.</p>
          <span className="hatch" aria-hidden="true" />
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
