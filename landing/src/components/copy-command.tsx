"use client";

import { useEffect, useRef, useState } from "react";

type CopyCommandProps = {
  command: string;
  label?: string;
};

function CopyIcon() {
  return (
    <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <path d="M5.7 5.7V2.7h7.6v7.6h-3" />
      <rect x="2.7" y="5.7" width="7.6" height="7.6" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M2.8 8.4 6.4 12 13.2 4.4" />
    </svg>
  );
}

export function CopyCommand({ command, label = "Copy" }: CopyCommandProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button className="copy-button" type="button" onClick={copy} data-copied={copied ? "" : undefined}>
      {copied ? <CheckIcon /> : <CopyIcon />}
      <span>{copied ? "Copied" : label}</span>
      <span className="sr-only" aria-live="polite">
        {copied ? "Command copied to clipboard" : ""}
      </span>
    </button>
  );
}
