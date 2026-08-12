"use client";

import { useState, useSyncExternalStore } from "react";
import { CopyCommand } from "@/components/copy-command";

const shellCommand = "curl -fsSL https://web.sync.aquitano.me/install.sh | sh";

const shellNote = "Installs to ~/.local/bin. Append -s -- --server for the server binary.";

const targets = {
  macos: { label: "macOS", prompt: "$", command: shellCommand, note: shellNote },
  linux: { label: "Linux", prompt: "$", command: shellCommand, note: shellNote },
  windows: {
    label: "Windows",
    prompt: ">",
    command: "iwr -useb https://web.sync.aquitano.me/install.ps1 | iex",
    note: "PowerShell. Installs to %LOCALAPPDATA%\\Programs\\aqt.",
  },
} satisfies Record<string, { label: string; prompt: string; command: string; note: string }>;

type OsKey = keyof typeof targets;

const order = ["macos", "linux", "windows"] as const satisfies readonly OsKey[];

// Every distinct command is rendered into the same grid cell, so the box is always as
// wide as the longest one and switching tabs moves nothing.
const commands = [...new Map(order.map((key) => [targets[key].command, targets[key]])).values()];

// Even a reduced user-agent string still carries its platform token, so it is the
// one signal every browser agrees on.
function detectOs(): OsKey | null {
  const ua = navigator.userAgent;

  // Neither installer runs on a phone, and both handheld families claim a desktop
  // token anyway: iOS says "like Mac OS X", Android says "Linux; Android". They have
  // to be answered first, and the answer is no detection rather than a wrong one.
  if (/iphone|ipad|ipod|android/i.test(ua)) return null;

  if (/windows|win64|win32/i.test(ua)) return "windows";
  if (/macintosh|mac os x/i.test(ua)) return "macos";
  if (/linux|cros|x11/i.test(ua)) return "linux";
  return null;
}

/** The user agent is only readable on the client, so the server renders no detection. */
const noSubscribe = () => () => {};
const noServerSnapshot = () => null;

export function InstallPicker() {
  const detected = useSyncExternalStore(noSubscribe, detectOs, noServerSnapshot);
  const [picked, setPicked] = useState<OsKey | null>(null);

  const active = picked ?? detected ?? "macos";
  const target = targets[active];

  return (
    <div className="install-picker" data-reveal>
      <div className="os-tabs" role="group" aria-label="Choose your platform">
        {order.map((key) => (
          <button
            key={key}
            type="button"
            className="os-tab"
            aria-pressed={key === active}
            onClick={() => setPicked(key)}
          >
            {targets[key].label}
            {key === detected ? <span className="os-detected">detected</span> : null}
          </button>
        ))}
      </div>

      <div className="install-command">
        <div className="command-stack">
          {commands.map((entry) => (
            <code key={entry.command} data-active={entry.command === target.command ? "" : undefined}>
              <span className="prompt" aria-hidden="true">
                {entry.prompt}
              </span>
              {entry.command}
            </code>
          ))}
        </div>
        {/* Remount on switch so a stale "Copied" badge never sits beside a new command */}
        <CopyCommand key={active} command={target.command} />
      </div>

      <p className="install-note">{target.note}</p>
    </div>
  );
}
