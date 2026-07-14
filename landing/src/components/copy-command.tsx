"use client";

import { useEffect, useRef, useState } from "react";

type CopyCommandProps = {
  command: string;
  label?: string;
};

export function CopyCommand({ command, label = "Copy command" }: CopyCommandProps) {
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
    <button className="copy-button" type="button" onClick={copy}>
      <span>{copied ? "Copied" : label}</span>
      <span aria-hidden="true">{copied ? "OK" : "+"}</span>
      <span className="sr-only" aria-live="polite">
        {copied ? "Command copied to clipboard" : ""}
      </span>
    </button>
  );
}
