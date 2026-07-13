"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(useGSAP, ScrollTrigger);

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
          .from("[data-hero-kicker]", { opacity: 0, y: 12, duration: 0.45 })
          .from(
            "[data-hero-line]",
            { yPercent: 115, duration: 0.9, stagger: 0.08 },
            "-=0.2",
          )
          .from(
            "[data-hero-copy], [data-hero-actions]",
            { opacity: 0, y: 22, duration: 0.65, stagger: 0.08 },
            "-=0.55",
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

        gsap.fromTo(
          "[data-triptych-image]",
          { scale: 1.12 },
          {
            scale: 1,
            ease: "none",
            scrollTrigger: {
              trigger: "[data-triptych]",
              start: "top bottom",
              end: "bottom top",
              scrub: 0.8,
            },
          },
        );

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
