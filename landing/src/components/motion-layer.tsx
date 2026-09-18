// SPDX-License-Identifier: AGPL-3.0-or-later

"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";

gsap.registerPlugin(useGSAP, ScrollTrigger, ScrambleTextPlugin);

const cipherChars = "abcdefghijklmnopqrstuvwxyz0123456789#/*.:|";

// Renders every cipher character once in the headline's own face and returns them
// narrowest first, so each glyph cell can be given the set that fits inside it.
function measureCipherWidths(sample: HTMLElement) {
  const probe = document.createElement("span");
  probe.style.visibility = "hidden";
  probe.style.position = "absolute";
  sample.parentElement?.append(probe);
  const measured = [...cipherChars].map((char) => {
    probe.textContent = char;
    return { char, width: probe.getBoundingClientRect().width };
  });
  probe.remove();
  return measured.sort((a, b) => a.width - b.width);
}

export function MotionLayer() {
  useGSAP(() => {
    const media = gsap.matchMedia();

    media.add("(prefers-reduced-motion: no-preference)", () => {
      // One orchestrated load, in stages rather than all at once: the headline
      // decrypts, the copy settles under it, the poster unrolls, the mark assembles
      // pixel by pixel. Everything after that is driven by the reader's scroll.
      // The headline is shown as ciphertext first, flickering for a beat, and then
      // decrypts glyph by glyph. Each glyph runs inside a cell locked to its final
      // width and only draws cipher characters that fit that cell, so nothing is
      // clipped and the line never reflows. The cells are released once the sequence
      // ends so the headline can wrap normally on resize.
      const chars = gsap.utils.toArray<HTMLElement>("[data-hero-char]");
      const glyphs = chars.map((char) => char.textContent ?? "");
      const widths = chars.map((char) => char.getBoundingClientRect().width);
      const cipherWidths = measureCipherWidths(chars[0]);
      const fitting = widths.map((width) => {
        const fits = cipherWidths.filter((entry) => entry.width <= width + 0.5).map((entry) => entry.char);
        return fits.length > 0 ? fits.join("") : cipherWidths[0].char;
      });
      const randomFrom = (pool: string) => pool[Math.floor(Math.random() * pool.length)];
      chars.forEach((char, index) => {
        char.style.width = `${widths[index]}px`;
        char.style.display = "inline-block";
        char.textContent = randomFrom(fitting[index]);
      });
      const hero = gsap.timeline({
        defaults: { ease: "power3.out" },
        onComplete: () => gsap.set(chars, { clearProps: "width,display" }),
      });
      hero.from("[data-hero-kicker]", { opacity: 0, duration: 0.4 }, 0);
      chars.forEach((char, index) => {
        hero
          .to(
            char,
            { duration: 0.45, ease: "none", scrambleText: { text: randomFrom(fitting[index]), chars: fitting[index], speed: 1 } },
            0.05,
          )
          .to(
            char,
            { duration: 0.5, ease: "none", scrambleText: { text: glyphs[index], chars: fitting[index], speed: 1 } },
            0.5 + index * 0.035,
          );
      });
      hero
        .from("[data-hero-copy]", { opacity: 0, duration: 0.5 }, 1.7)
        .from("[data-hero-actions] > *", { opacity: 0, duration: 0.45, stagger: 0.1, clearProps: "opacity" }, 1.85)
        .from("[data-hero-visual]", { clipPath: "inset(0 0 100% 0)", duration: 0.9, ease: "power4.out" }, 2)
        .from(
          "[data-hero-visual] [data-pixel]",
          { opacity: 0, scale: 0.82, duration: 0.45, stagger: 0.03 },
          2.6,
        );

      gsap.utils.toArray<HTMLElement>("[data-reveal]").forEach((element) => {
        gsap.from(element, {
          opacity: 0,
          y: 28,
          duration: 0.7,
          ease: "power3.out",
          scrollTrigger: { trigger: element, start: "top 86%", once: true },
        });
      });

      for (const [grid, cell] of [
        ["[data-feature-grid]", "[data-feature]"],
        ["[data-workflow-grid]", "[data-workflow]"],
      ]) {
        gsap.from(cell, {
          opacity: 0,
          y: 32,
          duration: 0.7,
          stagger: 0.07,
          ease: "power3.out",
          scrollTrigger: { trigger: grid, start: "top 78%", once: true },
        });
      }

      gsap.utils.toArray<HTMLElement>("[data-triptych-image]").forEach((image) => {
        gsap.fromTo(
          image,
          { scale: 1.12 },
          {
            scale: 1,
            ease: "none",
            scrollTrigger: { trigger: image, start: "top bottom", end: "bottom top", scrub: 0.8 },
          },
        );
      });

      let cancelled = false;
      document.fonts.ready.then(() => {
        if (!cancelled) ScrollTrigger.refresh();
      });

      return () => {
        cancelled = true;
      };
    });

    return () => media.revert();
  }, []);

  return null;
}
