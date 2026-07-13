import Image from "next/image";
import { CopyCommand } from "@/components/copy-command";
import { MotionLayer } from "@/components/motion-layer";

const installCommand = "go install github.com/aquitano/aqt-sync/cmd/aqt@latest";

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

function TechMarks({ label }: { label: string }) {
  return (
    <div className="tech-marks" aria-hidden="true">
      <span className="micro-bars" />
      <span>{label}</span>
      <span className="micro-grid" />
    </div>
  );
}

const features = [
  {
    className: "feature-zero",
    label: "Zero knowledge",
    title: "Nothing readable reaches the server.",
    body: "Filenames, file contents, metadata, and keys are encrypted on your machine before upload.",
    visual: "CIPHERTEXT ONLY",
  },
  {
    className: "feature-dag",
    label: "Content addressed",
    title: "Sync less. Restore faster.",
    body: "Folders become a Merkle DAG of encrypted chunks with per-account deduplication.",
    visual: "ROOT / CHUNK / PACK",
  },
  {
    className: "feature-links",
    label: "Private sharing",
    title: "The key stays after the #.",
    body: "Public links keep their content key in the URL fragment, which browsers never send to the server.",
    visual: "aqt.sh/x/id#k.key",
  },
  {
    className: "feature-history",
    label: "Snapshots",
    title: "Checkpoint what matters.",
    body: "Anchor named snapshots, compare them with the live tree, and restore in place or beside it.",
    visual: "SAVE / DIFF / RESTORE",
  },
  {
    className: "feature-host",
    label: "Self-hosted",
    title: "One binary. One data directory.",
    body: "Run aqt-server with SQLite and ciphertext blobs. Back it up anywhere without exposing plaintext.",
    visual: "GO + SQLITE",
  },
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
    body: "Two-way sync, conflict copies, ignore rules, and a watcher that waits when git is busy.",
    command: "aqt init ~/vault && aqt sync ~/vault",
    output: "3 pushed / 0 pulled / 0 conflicts",
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
              <a className="text-link" href="#features">Explore features <span aria-hidden="true">↘</span></a>
            </div>
          </div>

          <div data-hero-visual className="hero-poster frame">
            <CornerMarks />
            <div className="poster-ghost" aria-hidden="true">AQT</div>
            <div className="poster-topline">
              <span>AQT / SYNC</span>
              <span>LOCAL FIRST</span>
            </div>
            <div className="poster-center">
              <PixelMark />
              <div className="poster-word" aria-hidden="true">aqt</div>
            </div>
            <TechMarks label="XCHACHA20 / ARGON2ID / CIPHERTEXT" />
            <div className="poster-command">
              <span className="prompt">$</span>
              <code>aqt sync ~/vault</code>
              <span className="command-result">ciphertext pushed</span>
            </div>
          </div>
        </section>

        <section className="manifesto poster-section section-pad" aria-labelledby="manifesto-title">
          <CornerMarks />
          <div data-reveal className="manifesto-type">
            <span>PRIVATE</span>
            <span>BY DEFAULT</span>
          </div>
          <div className="manifesto-copy">
            <h2 id="manifesto-title" data-reveal>The storage provider is no longer a trusted party.</h2>
            <p data-reveal>
              aqt encrypts locally with XChaCha20-Poly1305. Your root key never leaves your device, and your server only coordinates opaque objects.
            </p>
          </div>
          <div className="knowledge-grid" data-reveal>
            <div><span>Server sees</span><strong>Opaque IDs</strong></div>
            <div><span>Server stores</span><strong>Ciphertext</strong></div>
            <div><span>Server cannot read</span><strong>Names or files</strong></div>
            <div><span>You control</span><strong>Every key</strong></div>
          </div>
          <TechMarks label="PRIVATE BY DEFAULT / PUBLIC BY INTENT" />
        </section>

        <section id="features" className="features poster-section section-pad" aria-labelledby="features-title">
          <CornerMarks />
          <div className="section-heading" data-reveal>
            <h2 id="features-title">Built for the whole life of a file.</h2>
            <p>Push it once, keep a folder in sync, share it safely, or recover it years later.</p>
            <TechMarks label="PUSH / SYNC / SHARE / SNAPSHOT / RESTORE" />
          </div>
          <div className="feature-grid" data-feature-grid>
            {features.map((feature) => (
              <article key={feature.label} data-feature className={`feature-cell ${feature.className}`}>
                <CornerMarks />
                <p className="feature-label">{feature.label}</p>
                <div className="feature-visual" aria-hidden="true">{feature.visual}</div>
                <h3>{feature.title}</h3>
                <p>{feature.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section data-triptych className="triptych-section poster-section" aria-labelledby="triptych-title">
          <CornerMarks />
          <div className="triptych-head" data-reveal>
            <h2 id="triptych-title">From plaintext to sealed matter.</h2>
            <p>Blocks converge, encrypt, and move. The network only carries what it cannot understand.</p>
          </div>
          <div className="triptych-frame frame">
            <CornerMarks />
            <TechMarks label="BLOCKS / OBJECTS / NETWORK" />
            <Image
              data-triptych-image
              src="/encrypted-network-halftone.png"
              alt="Duotone halftone artwork of encrypted blocks, a sealed object, and network infrastructure"
              width={2172}
              height={724}
              sizes="100vw"
            />
          </div>
        </section>

        <section id="workflow" data-horizontal className="workflow" aria-labelledby="workflow-title">
          <div data-horizontal-track className="workflow-track">
            {workflow.map((step, index) => (
              <article className={`workflow-panel workflow-panel-${index + 1}`} key={step.verb}>
                <div className="workflow-index" aria-hidden="true">0{index + 1}</div>
                <div className="workflow-copy">
                  {index === 0 ? <h2 id="workflow-title">One binary. Three essential moves.</h2> : null}
                  <p className="workflow-verb">{step.verb}</p>
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
            <span className="flow-arrow" aria-hidden="true">→</span>
            <div className="crypto-node crypto-node-accent"><span>Memory-hard KDF</span><strong>Argon2id</strong></div>
            <span className="flow-arrow" aria-hidden="true">→</span>
            <div className="crypto-node"><span>Unlocks locally</span><strong>Root key</strong></div>
            <span className="flow-arrow" aria-hidden="true">→</span>
            <div className="crypto-node"><span>Seals every resource</span><strong>XChaCha20</strong></div>
          </div>
          <div className="security-proof" data-reveal>
            <p>Share links place the content key in the browser fragment.</p>
            <code>https://aqt.sh/x/9fK2qd<span>#k.Hs7nT4...</span></code>
            <p>The fragment never appears in the HTTP request.</p>
          </div>
        </section>

        <section className="self-host poster-section section-pad" aria-labelledby="host-title">
          <CornerMarks />
          <div className="host-mark" aria-hidden="true"><PixelMark /></div>
          <div className="host-copy" data-reveal>
            <h2 id="host-title">Own the machine. Or rent one.</h2>
            <p>
              aqt-server is a static Go binary backed by SQLite and a ciphertext data directory. Put it behind Caddy, systemd, or Docker.
            </p>
            <a className="text-link text-link-light" href="https://github.com/aquitano/aqt-sync/blob/main/docs/deploy.md">Read the deploy guide <span aria-hidden="true">↗</span></a>
          </div>
          <div className="host-terminal" data-reveal>
            <p>START A LOCAL SERVER</p>
            <code><span>$</span> AQT_DATA_DIR=./aqt-data ./bin/aqt-server</code>
            <div className="host-specs">
              <span>SQLite</span><span>Prometheus</span><span>Native TLS</span><span>Pure Go</span>
            </div>
          </div>
        </section>

        <section id="install" className="install poster-section section-pad" aria-labelledby="install-title">
          <CornerMarks />
          <div data-reveal>
            <PixelMark compact />
            <h2 id="install-title">Your files are ready to disappear.</h2>
            <p>From everyone except you.</p>
          </div>
          <div className="install-command" data-reveal>
            <code>{installCommand}</code>
            <CopyCommand command={installCommand} />
          </div>
          <a className="button button-dark" href="https://github.com/aquitano/aqt-sync">View on GitHub</a>
        </section>
      </main>

      <footer>
        <a className="brand" href="#top"><PixelMark compact /><span>aqt</span></a>
        <p>Zero-knowledge encrypted sync.</p>
        <div><a href="https://github.com/aquitano/aqt-sync">GitHub</a><a href="https://github.com/aquitano/aqt-sync/blob/main/DESIGN.md">Protocol</a><a href="https://github.com/aquitano/aqt-sync/blob/main/docs/deploy.md">Deploy</a></div>
      </footer>

      <MotionLayer />
    </div>
  );
}
