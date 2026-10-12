/* <LiquidMetalButton /> for PhishHawk: ThreeUI's "Sign up Pill" (variant
   "pill"), rebuilt so it works under the app's Content-Security-Policy.

   The ThreeUI package renders this button inside <iframe srcdoc> with an
   inline <script> and <style>, and loads Inter from Google Fonts. PhishHawk's
   CSP (script-src 'self'; style-src 'self') blocks all three, so the packaged
   component shows an empty frame there. Here the same renderer
   (mountLiquidMetal.ts, shaders.ts) draws into a canvas behind a real <button>:
   it can submit a form, take focus, be disabled, and be read by a screen
   reader like any other button.

   Budget: each lit button holds one WebGL2 context. At most MAX_LIVE render
   at once; others, and any button off screen or in a hidden tab, show the
   still CSS version. Use it for the one primary action on a screen. */

import {
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from 'react';
import { mountLiquidMetal } from './mountLiquidMetal';
import './liquid-metal.css';

const MAX_LIVE = 3;
let live = 0;

export type LiquidMetalButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> & {
  /** Plain text, at most 24 characters (as in the original). */
  children: string;
  /** Optional leading icon; rendered aria-hidden. Defaults to the original plus sign when omitted and showIcon is true. */
  icon?: ReactNode;
  showIcon?: boolean;
  /** Button height in px. The original's control height is 52. */
  height?: number;
};

/** The original wrapper sized the pill from its label: 1407 to 3000 units. */
function pillUnits(label: string) {
  return Math.min(3000, Math.max(1407, 820 + label.length * 94));
}

export function LiquidMetalButton({
  children,
  icon,
  showIcon = false,
  height = 52,
  className,
  type = 'button',
  disabled,
  style,
  ...rest
}: LiquidMetalButtonProps) {
  const label = String(children).slice(0, 24);
  const rootRef = useRef<HTMLDivElement>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const [visible, setVisible] = useState(false);
  const [render, setRender] = useState<'static' | 'gl'>('static');

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    let onScreen = false;
    const update = () => setVisible(onScreen && document.visibilityState !== 'hidden');
    const io = new IntersectionObserver(
      ([entry]) => {
        onScreen = entry.isIntersecting;
        update();
      },
      { rootMargin: '80px' },
    );
    io.observe(root);
    document.addEventListener('visibilitychange', update);
    return () => {
      io.disconnect();
      document.removeEventListener('visibilitychange', update);
    };
  }, []);

  useEffect(() => {
    const root = rootRef.current,
      stage = stageRef.current,
      button = buttonRef.current;
    if (!visible || !root || !stage || !button || live >= MAX_LIVE) return;
    const canvas = document.createElement('canvas');
    canvas.className = 'lm-fx';
    canvas.setAttribute('aria-hidden', 'true');
    stage.appendChild(canvas);
    let dispose: (() => void) | null = null;
    let lost = false;
    try {
      dispose = mountLiquidMetal({ root, stage, canvas, button }, () => {
        lost = true;
        setRender('static');
      });
    } catch {
      dispose = null;
    }
    if (!dispose) {
      canvas.remove();
      return;
    }
    live += 1;
    if (!lost) setRender('gl');
    return () => {
      live -= 1;
      dispose?.();
      canvas.remove();
      setRender('static');
    };
  }, [visible]);

  const vars = {
    ...style,
    '--h': `${height}px`,
    '--lm-units': String(pillUnits(label)),
  } as CSSProperties;

  return (
    <div
      ref={rootRef}
      className={['lm', className].filter(Boolean).join(' ')}
      style={vars}
      data-render={render}
      data-disabled={disabled ? 'true' : undefined}
    >
      <button ref={buttonRef} className="lm-btn" type={type} disabled={disabled} {...rest}>
        {icon ?? (showIcon ? <PlusIcon /> : null)}
        <span className="lm-lbl">{label}</span>
      </button>
      <div ref={stageRef} className="lm-stage" aria-hidden="true">
        <div className="lm-plate" />
      </div>
    </div>
  );
}

function PlusIcon() {
  return (
    <svg className="lm-ico" viewBox="0 0 115 115" aria-hidden="true">
      <g stroke="currentColor" strokeWidth="17" strokeLinecap="round">
        <path d="M57.5 8.5 V106.5" />
        <path d="M8.5 57.5 H106.5" />
      </g>
    </svg>
  );
}
