"use client";

import { useEffect, useId, useRef } from "react";

/**
 * LogoReveal — M365 Assessment shield ident, adapted from indexlogo.html.
 * Badge / timecode / replay chrome intentionally omitted: this is the
 * compact header that sits directly above the sign-in card.
 *
 * Timeline (6s): 0–2.5s stroke draw · 2.5s whole-length flare ·
 * 2.5–3.4s cream flood fill · 2.8–4.0s wordmark letterspace-in ·
 * 3.6–4.3s rule expands · 4.5s+ ambient idle hold.
 */
export function LogoReveal() {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const clipId = `floodClip-${uid}`;
  const floodRectId = `floodRect-${uid}`;

  const shieldRef = useRef<SVGPathElement>(null);
  const checkRef = useRef<SVGPathElement>(null);
  const shieldFlareRef = useRef<SVGPathElement>(null);
  const checkFlareRef = useRef<SVGPathElement>(null);
  const shieldFillRef = useRef<SVGPathElement>(null);
  const checkCutRef = useRef<SVGPathElement>(null);
  const floodRectRef = useRef<SVGRectElement>(null);
  const wordmarkRef = useRef<HTMLDivElement>(null);
  const ruleRef = useRef<HTMLDivElement>(null);
  const floatRef = useRef<SVGGElement>(null);

  useEffect(() => {
    const shield = shieldRef.current;
    const check = checkRef.current;
    const shieldFlare = shieldFlareRef.current;
    const checkFlare = checkFlareRef.current;
    const shieldFill = shieldFillRef.current;
    const checkCut = checkCutRef.current;
    const floodRect = floodRectRef.current;
    const wordmark = wordmarkRef.current;
    const rule = ruleRef.current;
    const floatG = floatRef.current;
    if (
      !shield ||
      !check ||
      !shieldFlare ||
      !checkFlare ||
      !shieldFill ||
      !checkCut ||
      !floodRect ||
      !wordmark ||
      !rule ||
      !floatG
    ) {
      return;
    }

    const DUR = 6.0;
    const reduce = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;

    const shieldLen = shield.getTotalLength();
    const checkLen = check.getTotalLength();
    shield.style.strokeDasharray = `${shieldLen} ${shieldLen}`;
    check.style.strokeDasharray = `${checkLen} ${checkLen}`;

    const easeInOut = (x: number) =>
      x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2;
    const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

    const applyFinalState = () => {
      shield.style.strokeDashoffset = "0";
      check.style.strokeDashoffset = "0";
      shieldFlare.style.opacity = "0";
      checkFlare.style.opacity = "0";
      shieldFill.style.opacity = "1";
      checkCut.style.opacity = "1";
      floodRect.setAttribute("width", "160");
      wordmark.style.opacity = "1";
      wordmark.style.letterSpacing = "0.18em";
      wordmark.style.textIndent = "0.18em";
      wordmark.style.transform = "translateY(0px)";
      rule.style.transform = "scaleX(1)";
      rule.style.opacity = "1";
      floatG.style.transform = "none";
      floatG.style.filter = "none";
    };

    if (reduce) {
      applyFinalState();
      return;
    }

    const t0 = performance.now();
    let raf = 0;
    let idleRaf = 0;

    const frame = (now: number) => {
      const t = Math.min(DUR, (now - t0) / 1000);

      const sP = easeInOut(clamp01(t / 2.2));
      const cP = easeInOut(clamp01((t - 1.4) / 1.1));
      shield.style.strokeDashoffset = String(shieldLen * (1 - sP));
      check.style.strokeDashoffset = String(checkLen * (1 - cP));

      let flare = 0;
      if (t >= 2.5 && t < 2.9) {
        const f = (t - 2.5) / 0.4;
        flare = f < 0.45 ? f / 0.45 : 1 - (f - 0.45) / 0.55;
      }
      shieldFlare.style.opacity = flare.toFixed(3);
      checkFlare.style.opacity = flare.toFixed(3);
      shieldFlare.style.strokeWidth = String(6 + flare * 10);
      checkFlare.style.strokeWidth = String(6 + flare * 8);

      const fillP = easeInOut(clamp01((t - 2.55) / 0.85));
      shieldFill.style.opacity = fillP.toFixed(3);
      checkCut.style.opacity = fillP.toFixed(3);
      floodRect.setAttribute("width", (160 * fillP).toFixed(1));

      const wP = easeInOut(clamp01((t - 2.8) / 1.2));
      wordmark.style.opacity = wP.toFixed(3);
      const ls = 0.6 - (0.6 - 0.18) * wP;
      wordmark.style.letterSpacing = `${ls.toFixed(3)}em`;
      wordmark.style.textIndent = `${ls.toFixed(3)}em`;
      wordmark.style.transform = `translateY(${((1 - wP) * 14).toFixed(1)}px)`;

      const rP = easeInOut(clamp01((t - 3.6) / 0.7));
      rule.style.transform = `scaleX(${rP.toFixed(3)})`;
      rule.style.opacity = (0.25 + 0.75 * rP).toFixed(3);

      const idleP = clamp01((t - 4.5) / 1.5);
      const tt = now / 1000;
      const amp = idleP * (2.6 + Math.sin(tt * 1.4) * 0.8);
      floatG.style.transform = `translateY(${(-amp).toFixed(2)}px)`;
      floatG.style.filter =
        idleP > 0
          ? `drop-shadow(0 0 ${(6 + 4 * Math.sin(tt * 1.1)).toFixed(1)}px rgba(244,237,218,.18))`
          : "none";

      if (t < DUR) {
        raf = requestAnimationFrame(frame);
      } else {
        const idle = () => {
          const t2 = (performance.now() - t0) / 1000;
          const a = 2.6 + Math.sin(t2 * 1.4) * 0.8;
          floatG.style.transform = `translateY(${(-a).toFixed(2)}px)`;
          floatG.style.filter = `drop-shadow(0 0 ${(6 + 4 * Math.sin(t2 * 1.1)).toFixed(1)}px rgba(244,237,218,.18))`;
          idleRaf = requestAnimationFrame(idle);
        };
        idleRaf = requestAnimationFrame(idle);
      }
    };

    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      cancelAnimationFrame(idleRaf);
    };
  }, []);

  return (
    <div
      role="img"
      aria-label="M365 Assessment logo reveal: shield stroke draws, flares, fills cream, wordmark appears"
      className="relative w-full max-w-sm overflow-hidden rounded-lg"
      style={{
        background:
          "radial-gradient(120% 90% at 50% 12%, #0e3a2f 0%, #0a2b23 55%, #071e18 100%)",
        boxShadow:
          "0 30px 80px rgba(0,0,0,.5), 0 0 0 1px rgba(244,237,218,.08)",
      }}
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(60% 46% at 50% 44%, rgba(255,251,239,.06), transparent 70%)",
        }}
      />
      <div className="relative flex flex-col items-center justify-center px-6 py-8">
        <div className="h-28 w-28">
          <svg viewBox="0 0 200 200" className="block h-full w-full overflow-visible" aria-hidden="true">
            <defs>
              <clipPath id={clipId}>
                <rect
                  ref={floodRectRef}
                  id={floodRectId}
                  x="20"
                  y="10"
                  width="160"
                  height="180"
                  rx="4"
                />
              </clipPath>
            </defs>
            <g ref={floatRef}>
              <path
                ref={shieldRef}
                d="M100 18 L156 42 V102 C156 140 131 164 100 178 C69 164 44 140 44 102 V42 Z"
                fill="transparent"
                fillOpacity="0"
                stroke="#f4edda"
                strokeWidth="5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                ref={checkRef}
                d="M74 101 L92 119 L128 76"
                fill="transparent"
                fillOpacity="0"
                stroke="#f4edda"
                strokeWidth="5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <g clipPath={`url(#${clipId})`}>
                <path
                  ref={shieldFillRef}
                  d="M100 18 L156 42 V102 C156 140 131 164 100 178 C69 164 44 140 44 102 V42 Z"
                  fill="#f4edda"
                  opacity="1"
                />
                <path
                  ref={checkCutRef}
                  d="M74 101 L92 119 L128 76"
                  fill="none"
                  stroke="#0a2b23"
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  opacity="1"
                />
              </g>
              <path
                ref={shieldFlareRef}
                d="M100 18 L156 42 V102 C156 140 131 164 100 178 C69 164 44 140 44 102 V42 Z"
                fill="none"
                stroke="#fffbef"
                strokeWidth="9"
                strokeLinecap="round"
                strokeLinejoin="round"
                opacity="0"
                style={{ filter: "blur(3px)" }}
              />
              <path
                ref={checkFlareRef}
                d="M74 101 L92 119 L128 76"
                fill="none"
                stroke="#fffbef"
                strokeWidth="9"
                strokeLinecap="round"
                strokeLinejoin="round"
                opacity="0"
                style={{ filter: "blur(3px)" }}
              />
            </g>
          </svg>
        </div>
        <div
          ref={wordmarkRef}
          className="mt-5 text-center font-semibold whitespace-nowrap text-[#f4edda]"
          style={{ fontSize: "22px" }}
        >
          M365 Assessment
          <small
            className="mt-2 block font-medium opacity-85"
            style={{ fontSize: "7px", letterSpacing: "inherit" }}
          >
            SECURITY POSTURE · TENANT OVERVIEW
          </small>
        </div>
        <div
          ref={ruleRef}
          className="mt-4 h-px w-2/3 origin-center bg-[#f4edda]/60"
        />
      </div>
    </div>
  );
}
