import { useEffect, useRef, useState } from "react";

import "./DomeGallery.css";

type DomeTile = {
  title: string;
  subtitle: string;
  detail: string;
  accent: "primary" | "safe" | "warning" | "danger";
};

const tiles: DomeTile[] = [
  {
    title: "DOM Monitor",
    subtitle: "Live mutation tracking",
    detail: "Observes DOM changes, overlays, hidden inputs, and delayed injections before action execution.",
    accent: "primary",
  },
  {
    title: "Policy Engine",
    subtitle: "Allow / Warn / Block",
    detail: "Converts model output and risk thresholds into enforceable mediation decisions.",
    accent: "danger",
  },
  {
    title: "Action Mediator",
    subtitle: "Human-in-the-loop controls",
    detail: "Validates click, type, and navigation proposals against page context and user intent.",
    accent: "warning",
  },
  {
    title: "Threat Intel",
    subtitle: "Known malicious signals",
    detail: "Combines reputation and indicator checks with local heuristics for early blocking.",
    accent: "danger",
  },
  {
    title: "ML Detector",
    subtitle: "Text and structure scoring",
    detail: "Runs lightweight classification over extracted content to detect malicious intent patterns.",
    accent: "primary",
  },
  {
    title: "UI Deception",
    subtitle: "Clickjacking detection",
    detail: "Flags hidden overlays, overlapping elements, fake buttons, and deceptive affordances.",
    accent: "warning",
  },
  {
    title: "Firebase Auth",
    subtitle: "Identity and session bridge",
    detail: "Handles sign-in and dashboard identity while the backend issues SecureAgent JWT sessions.",
    accent: "safe",
  },
  {
    title: "Firestore Logs",
    subtitle: "Audit and scan records",
    detail: "Stores recent scans, mediated actions, and historical evidence used by the dashboard.",
    accent: "safe",
  },
  {
    title: "FastAPI Backend",
    subtitle: "Runtime orchestration",
    detail: "Coordinates scanning, risk scoring, performance tracking, and action-plan validation.",
    accent: "primary",
  },
  {
    title: "Selenium Runtime",
    subtitle: "Browser automation",
    detail: "Loads target pages inside the controlled automation environment used by the system pipeline.",
    accent: "primary",
  },
];

const radius = 360;

const DomeGallery = () => {
  const [rotation, setRotation] = useState({ x: -10, y: -18 });
  const [activeIndex, setActiveIndex] = useState(0);
  const dragState = useRef<{ x: number; y: number; startX: number; startY: number } | null>(null);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      setRotation((current) => {
        if (dragState.current) return current;
        return { ...current, y: current.y + 8 };
      });
    }, 3500);

    return () => window.clearInterval(intervalId);
  }, []);

  const handlePointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    dragState.current = {
      x: event.clientX,
      y: event.clientY,
      startX: rotation.x,
      startY: rotation.y,
    };
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (!dragState.current) return;
    const deltaX = event.clientX - dragState.current.x;
    const deltaY = event.clientY - dragState.current.y;
    setRotation({
      x: Math.max(-24, Math.min(18, dragState.current.startX - deltaY * 0.06)),
      y: dragState.current.startY + deltaX * 0.16,
    });
  };

  const handlePointerUp = () => {
    dragState.current = null;
  };

  return (
    <section id="gallery" className="py-24">
      <div className="container mx-auto px-6">
        <div className="mb-12 text-center">
          <span className="mb-4 block font-mono text-sm uppercase tracking-[0.22em] text-primary/80">Service Dome</span>
          <h2 className="text-3xl font-bold md:text-4xl">System Surfaces In One View</h2>
          <p className="mx-auto mt-4 max-w-3xl text-muted-foreground">
            Drag the dome to inspect the services that make SecureAgent work: scanning, policy,
            mediation, telemetry, persistence, and identity.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-[1.35fr_0.8fr] lg:items-center">
          <div
            className="dome-gallery-shell"
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            onPointerLeave={handlePointerUp}
          >
            <div className="dome-gallery-stage">
              <div
                className="dome-gallery-sphere"
                style={{
                  transform: `translateZ(-${radius}px) rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)`,
                }}
              >
                {tiles.map((tile, index) => {
                  const angle = (360 / tiles.length) * index;
                  const vertical = index % 2 === 0 ? -16 : 8;
                  return (
                    <button
                      key={tile.title}
                      type="button"
                      className={`dome-gallery-tile dome-gallery-tile--${tile.accent} ${
                        activeIndex === index ? "is-active" : ""
                      }`}
                      style={{
                        transform: `rotateY(${angle}deg) rotateX(${vertical}deg) translateZ(${radius}px)`,
                      }}
                      onClick={() => setActiveIndex(index)}
                    >
                      <span className="dome-gallery-kicker">{tile.subtitle}</span>
                      <strong>{tile.title}</strong>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="dome-gallery-fade dome-gallery-fade--top" />
            <div className="dome-gallery-fade dome-gallery-fade--bottom" />
          </div>

          <div className="glass rounded-[28px] border border-border/80 p-6">
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-primary">
              Selected Service
            </p>
            <h3 className="mt-3 text-2xl font-semibold">{tiles[activeIndex].title}</h3>
            <p className="mt-2 text-sm font-mono text-muted-foreground">
              {tiles[activeIndex].subtitle}
            </p>
            <p className="mt-5 text-sm leading-7 text-foreground/85">{tiles[activeIndex].detail}</p>

            <div className="mt-6 grid gap-3">
              {tiles.slice(0, 4).map((tile) => (
                <div
                  key={tile.title}
                  className="rounded-2xl border border-border/70 bg-background/40 px-4 py-3"
                >
                  <p className="text-sm font-medium">{tile.title}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{tile.subtitle}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default DomeGallery;
