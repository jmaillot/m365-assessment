"use client";

import { RotateCcw } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  type ReactNode,
} from "react";

import { Button } from "@/components/ui/button";

/**
 * LogoReveal — M365 Assessment shield ident, adapted from indexlogo.html.
 * Compact sign-in panel: animated shield + wordmark on the deep-green
 * stage, with caller-supplied sign-in CTA rendered inside (`children`)
 * and a subtle replay control. The ident chrome from the source file
 * (badge / timecode / progress bar) is intentionally omitted.
 *
 * Timeline (6s): 0–2.5s stroke draw · 2.5s whole-length flare ·
 * 2.5–3.4s cream flood fill · 2.8–4.0s wordmark letterspace-in ·
 * 3.6–4.3s rule expands · 4.5s+ ambient idle hold.
 */
const DUR = 6.0;

const easeInOut = (x: number) =>
  x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2;
const clamp01 = (x: number) => Math.max(0, Math.min(1, x));

export function LogoReveal({ children }: { children?: ReactNode }) {
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

  const rafRef = useRef(0);
  const idleRef = useRef(0);
  const lengthsRef = useRef<{ shield: number; check: number } | null>(null);

  const stop = useCallback(() => {
    cancelAnimationFrame(rafRef.current);
    cancelAnimationFrame(idleRef.current);
  }, []);

  const applyFinalState = useCallback(() => {
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
  }, []);

  const play = useCallback(() => {
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

    stop();
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      applyFinalState();
      return;
    }

    if (!lengthsRef.current) {
      lengthsRef.current = {
        shield: shield.getTotalLength(),
        check: check.getTotalLength(),
      };
    }
    const { shield: shieldLen, check: checkLen } = lengthsRef.current;
    shield.style.strokeDasharray = `${shieldLen} ${shieldLen}`;
    check.style.strokeDasharray = `${checkLen} ${checkLen}`;

    const t0 = performance.now();

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
        rafRef.current = requestAnimationFrame(frame);
      } else {
        const idle = () => {
          const t2 = (performance.now() - t0) / 1000;
          const a = 2.6 + Math.sin(t2 * 1.4) * 0.8;
          floatG.style.transform = `translateY(${(-a).toFixed(2)}px)`;
          floatG.style.filter = `drop-shadow(0 0 ${(6 + 4 * Math.sin(t2 * 1.1)).toFixed(1)}px rgba(244,237,218,.18))`;
          idleRef.current = requestAnimationFrame(idle);
        };
        idleRef.current = requestAnimationFrame(idle);
      }
    };

    rafRef.current = requestAnimationFrame(frame);
  }, [applyFinalState, stop]);

  useEffect(() => {
    play();
    return stop;
  }, [play, stop]);

  return (
    <div
      className="relative w-full max-w-[28rem] overflow-hidden rounded-lg"
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
      <div className="relative flex flex-col items-center px-8 py-10 text-center">
        <div
          role="img"
          aria-label="M365 Assessment logo reveal: shield stroke draws, flares, fills cream, wordmark appears"
          className="flex flex-col items-center"
        >
          <div className="h-36 w-36">
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
            className="mt-5 font-semibold whitespace-nowrap text-[#f4edda]"
            style={{ fontSize: "26px" }}
          >
            M365 Assessment
            <small
              className="mt-2 block font-medium opacity-85"
              style={{ fontSize: "8px", letterSpacing: "inherit" }}
            >
              SECURITY POSTURE · TENANT OVERVIEW
            </small>
          </div>
          <div
            ref={ruleRef}
            className="mt-4 h-px w-2/3 origin-center bg-[#f4edda]/60"
          />
        </div>

        {children ? (
          <div className="mt-6 flex w-full flex-col items-center">
            {children}
          </div>
        ) : null}

        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={(e) => {
            play();
            e.currentTarget.blur();
          }}
          className="mt-4 text-[#f4edda]/60 hover:text-[#f4edda]"
        >
          <RotateCcw />
          Replay
        </Button>
      </div>
    </div>
  );
}
