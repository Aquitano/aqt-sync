"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";

gsap.registerPlugin(useGSAP, ScrollTrigger, ScrambleTextPlugin);

// Restricted to glyphs Pixelify Sans covers, so scrambled frames never fall back to another font.
const cipherChars = "ABCDEFGHJKMNPQRSTUVWXYZ0123456789#/*";

export function MotionLayer() {
  useGSAP(() => {
    const media = gsap.matchMedia();

    media.add(
      {
        reduce: "(prefers-reduced-motion: reduce)",
        allow: "(prefers-reduced-motion: no-preference)",
        desktop: "(min-width: 768px)",
      },
      (context) => {
        const { reduce, allow, desktop } = context.conditions as {
          reduce: boolean;
          allow: boolean;
          desktop: boolean;
        };

        if (reduce || !allow) return;

        const hero = gsap.timeline({ defaults: { ease: "power4.out" } });
        hero
          .to(
            "[data-hero-kicker]",
            {
              duration: 0.6,
              ease: "none",
              scrambleText: {
                text: "{original}",
                chars: cipherChars,
                speed: 0.6,
                tweenLength: false,
              },
            },
            0,
          )
          .to(
            "[data-hero-line]",
            {
              duration: 1.05,
              stagger: 0.22,
              ease: "none",
              scrambleText: {
                text: "{original}",
                chars: cipherChars,
                speed: 0.55,
                tweenLength: false,
              },
            },
            0,
          )
          // Opacity only: everything else in the hero resolves in place, so a y-slide
          // reads as a different language — and a clipPath wipe slices the glyphs.
          .from("[data-hero-copy]", { opacity: 0, duration: 0.7 }, "-=0.55")
          .from(
            "[data-hero-actions] > *",
            { opacity: 0, duration: 0.55, stagger: 0.08 },
            "-=0.45",
          )
          .from(
            "[data-hero-visual]",
            { clipPath: "inset(0 0 100% 0)", duration: 1.05 },
            "-=0.9",
          )
          .from(
            "[data-hero-visual] [data-pixel]",
            { opacity: 0, scale: 0.82, duration: 0.35, stagger: 0.018 },
            "-=0.55",
          );

        gsap.utils.toArray<HTMLElement>("[data-reveal]").forEach((element) => {
          gsap.from(element, {
            opacity: 0,
            y: 44,
            duration: 0.8,
            ease: "power3.out",
            scrollTrigger: {
              trigger: element,
              start: "top 84%",
              once: true,
            },
          });
        });

        gsap.from("[data-feature]", {
          opacity: 0,
          y: 56,
          duration: 0.8,
          stagger: 0.09,
          ease: "power3.out",
          scrollTrigger: {
            trigger: "[data-feature-grid]",
            start: "top 72%",
            once: true,
          },
        });

        gsap.from("[data-triptych-panel]", {
          opacity: 0,
          y: 48,
          duration: 0.8,
          stagger: 0.12,
          ease: "power3.out",
          scrollTrigger: {
            trigger: "[data-triptych]",
            start: "top 74%",
            once: true,
          },
        });

        gsap.utils.toArray<HTMLElement>("[data-triptych-image]").forEach((image) => {
          gsap.fromTo(
            image,
            { scale: 1.12 },
            {
              scale: 1,
              ease: "none",
              scrollTrigger: {
                trigger: image,
                start: "top bottom",
                end: "bottom top",
                scrub: 0.8,
              },
            },
          );
        });

        if (desktop) {
          const wrapper = document.querySelector<HTMLElement>("[data-horizontal]");
          const track = document.querySelector<HTMLElement>("[data-horizontal-track]");

          if (wrapper && track) {
            const distance = () => Math.max(0, track.scrollWidth - window.innerWidth);

            gsap.to(track, {
              x: () => -distance(),
              ease: "none",
              scrollTrigger: {
                trigger: wrapper,
                start: "top top",
                end: () => `+=${distance()}`,
                pin: true,
                scrub: 0.8,
                invalidateOnRefresh: true,
                anticipatePin: 1,
              },
            });
          }
        }

        let cancelled = false;
        document.fonts.ready.then(() => {
          if (!cancelled) ScrollTrigger.refresh();
        });

        return () => {
          cancelled = true;
        };
      },
    );

    return () => media.revert();
  }, []);

  return null;
}
