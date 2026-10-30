/* The product page: what PhishHawk is, how it works, what it checks, what it
   gives back, how well it does, and how to start. It is the first page a
   signed-out visitor sees at /app/, and stays at /app/about for everyone.
   Every claim here is what the code does: the engine's own findings, the
   server (docs/SERVER.md) and the README's evaluation. Change it only with the
   code. The example analysis and the example findings use made-up names and
   reserved addresses, defanged. */

import { Fragment, useEffect, useRef, useState, type CSSProperties, type ElementType, type ReactNode } from 'react';
import { AnimatePresence, animate, motion, useInView, useReducedMotion } from 'motion/react';
import {
  ArrowDown,
  ArrowRight,
  AtSign,
  Check,
  CircleCheck,
  Cookie,
  Crosshair,
  Download,
  EyeOff,
  FileText,
  Fingerprint,
  Gauge,
  Hash,
  Hourglass,
  Inbox,
  KeyRound,
  Layers,
  Link2,
  ListChecks,
  Lock,
  Mailbox,
  Megaphone,
  Network,
  Paperclip,
  QrCode,
  ScanSearch,
  ScrollText,
  Server,
  ShieldCheck,
  Terminal,
  Users,
  WifiOff,
  X,
} from 'lucide-react';
import { AnimatedBackground } from '@/components/core/animated-background';
import { AnimatedNumber } from '@/components/core/animated-number';
import { Cursor } from '@/components/core/cursor';
import { ImageComparison, ImageComparisonImage, ImageComparisonSlider } from '@/components/core/image-comparison';
import { ScrollProgress } from '@/components/core/scroll-progress';
import { Spotlight } from '@/components/core/spotlight';
import { TextShimmer } from '@/components/core/text-shimmer';
import { TransitionPanel } from '@/components/core/transition-panel';
import { LiquidMetalButton } from '@/components/threeui/liquid-metal/LiquidMetalButton';
import { Question } from '@/components/phishhawk/Question';
import { SectionLink } from '@/components/phishhawk/PublicChrome';
import { Card, Chip, CopyButton, Panel, SeverityBadge, VerdictBadge } from '@/components/ui/ui';
import { Link, asset, navigate } from '@/app/router';
import { VERDICT_MEANING } from '@/app/vocabulary';
import { usePicturesLoaded } from '@/hooks/usePicturesLoaded';
import { cn } from '@/lib/utils';
import type { Verdict } from '@/api/types';
import './landing.css';

const EASE = [0.32, 0.72, 0, 1] as const;
const WRAP = 'mx-auto w-full max-w-[1120px] px-4 md:px-8';
const HEADLINE = 'Every reported email, triaged and explained.';

type Severity = 'high' | 'medium' | 'low';
type Signal = { severity: Severity; text: string };

/* ---- small pieces ---- */

/** Fades and lifts its content in, once, as it scrolls into view. */
function Reveal({ children, className, delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  return (
    <motion.div
      className={cn('print:!transform-none print:!opacity-100', className)}
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.6, delay, ease: EASE }}
    >
      {children}
    </motion.div>
  );
}

function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-[10px] font-medium uppercase tracking-[0.2em] text-ink-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-accent" aria-hidden="true" />
      {children}
    </span>
  );
}

function SectionHead({ eyebrow, title, titleId, center = false, children }: { eyebrow: string; title: string; titleId?: string; center?: boolean; children?: ReactNode }) {
  return (
    <Reveal className={center ? 'mx-auto max-w-[760px] text-center' : 'max-w-[680px]'}>
      <Eyebrow>{eyebrow}</Eyebrow>
      <h2 id={titleId} className="mt-4 text-[30px] font-semibold leading-[1.08] tracking-[-0.03em] text-ink sm:text-[40px]">
        {title}
      </h2>
      {children && <p className="mt-4 text-[15px] leading-relaxed text-ink-dim sm:text-base">{children}</p>}
    </Reveal>
  );
}

function IconTile({ icon: Icon, className }: { icon: ElementType; className?: string }) {
  return (
    <span className={cn('grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-line bg-raised text-accent shadow-[var(--shell-highlight)]', className)}>
      <Icon className="h-[18px] w-[18px]" strokeWidth={1.5} aria-hidden="true" />
    </span>
  );
}

function SignalRow({ signal }: { signal: Signal }) {
  return (
    <>
      <SeverityBadge severity={signal.severity} />
      <span className="min-w-0 text-[13px] leading-snug text-ink-dim [overflow-wrap:anywhere]">{signal.text}</span>
    </>
  );
}

/** Counts up to a number once it scrolls into view; screen readers get the number at once. */
function CountUp({ to, decimals = 0 }: { to: number; decimals?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const reduce = useReducedMotion();
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setValue(to);
      return;
    }
    const controls = animate(0, to, { duration: 1.6, ease: EASE, onUpdate: setValue });
    return () => controls.stop();
  }, [inView, reduce, to]);
  return (
    <>
      <span ref={ref} aria-hidden="true" className="tabular-nums">
        {value.toFixed(decimals)}
      </span>
      <span className="sr-only">{to.toFixed(decimals)}</span>
    </>
  );
}

/** The way in: the liquid metal button, Sign in or Open console. */
function EnterButton({ signedIn }: { signedIn: boolean }) {
  return (
    <LiquidMetalButton height={52} onClick={() => navigate(signedIn ? '/app/' : '/app/login')}>
      {signedIn ? 'Open console' : 'Sign in'}
    </LiquidMetalButton>
  );
}

/* ---- the hero: the promise, and an analysis running on an example ---- */

const SAMPLE: Signal[] = [
  { severity: 'high', text: "From domain micros0ft-support.example spells 'microsoft' with look-alike characters" },
  { severity: 'high', text: 'URL points at a raw IP: hxxp://203.0.113[.]24/login' },
  { severity: 'medium', text: 'display name shows a different address (it-desk@company.example)' },
  { severity: 'low', text: 'greets the recipient by email address instead of by name' },
];
const WEIGHT: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

function SampleAnalysis() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-40px' });
  const reduce = useReducedMotion();
  const [shown, setShown] = useState(0);

  useEffect(() => {
    if (!inView) return;
    if (reduce) {
      setShown(SAMPLE.length + 1);
      return;
    }
    let step = 0;
    const timer = window.setInterval(() => {
      step += 1;
      setShown(step);
      if (step > SAMPLE.length) window.clearInterval(timer);
    }, 700);
    return () => window.clearInterval(timer);
  }, [inView, reduce]);

  const done = shown > SAMPLE.length;
  const score = SAMPLE.slice(0, shown).reduce((sum, s) => sum + WEIGHT[s.severity], 0);

  return (
    <motion.div
      ref={ref}
      className="relative w-full min-w-0 print:hidden"
      initial={{ opacity: 0, y: 28, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.9, delay: 0.35, ease: EASE }}
    >
      <div
        className="ph-breathe pointer-events-none absolute -inset-8 rounded-[56px] bg-[radial-gradient(55%_55%_at_70%_20%,color-mix(in_srgb,var(--brand)_24%,transparent),transparent_70%),radial-gradient(50%_50%_at_20%_90%,color-mix(in_srgb,var(--accent)_18%,transparent),transparent_70%)] blur-2xl"
        aria-hidden="true"
      />
      <figure className="ph-ring relative rounded-[28px]" aria-label="An example analysis, with made-up names and addresses">
        <Panel inner="relative overflow-hidden">
          <div className="ph-scan" aria-hidden="true" />
          <div className="relative p-5 sm:p-6">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2 text-xs text-ink-muted">
                <span className="rounded-full border border-line bg-raised px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.16em] text-ink-dim">Example</span>
                Analysis 1042
              </span>
              {done ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-ok">
                  <CircleCheck className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
                  Finished · 9 ms
                </span>
              ) : (
                <TextShimmer as="span" duration={1.4} className="text-xs [--base-color:var(--text-muted)] [--base-gradient-color:var(--accent)]">
                  Reading the message
                </TextShimmer>
              )}
            </div>

            <p className="mt-4 text-[15px] font-medium leading-snug text-ink">Your mailbox is 98% full: act within 24 hours</p>
            <p className="mt-1 font-mono text-xs text-ink-muted [overflow-wrap:anywhere]">IT Service Desk &lt;alerts@micros0ft-support.example&gt;</p>

            <div className="mt-5 flex min-h-[58px] flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-raised/70 px-4 py-3">
              <AnimatePresence mode="wait" initial={false}>
                {done ? (
                  <motion.span key="verdict" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: 'spring', bounce: 0.45, duration: 0.6 }}>
                    <VerdictBadge verdict="LIKELY PHISHING" />
                  </motion.span>
                ) : (
                  <motion.span key="pending" exit={{ opacity: 0 }} className="text-xs text-ink-muted">
                    Verdict pending
                  </motion.span>
                )}
              </AnimatePresence>
              <span className="flex items-baseline gap-2">
                <span className="text-xs text-ink-muted">Score</span>
                <AnimatedNumber value={score} className="text-2xl font-semibold text-ink" springOptions={{ stiffness: 120, damping: 20 }} />
              </span>
            </div>

            <ul className="mt-4 grid gap-2">
              {SAMPLE.map((signal, i) => (
                <motion.li
                  key={signal.text}
                  initial={false}
                  animate={{ opacity: i < shown ? 1 : 0.2, x: i < shown ? 0 : -6 }}
                  transition={{ duration: 0.45, ease: EASE }}
                  className="flex items-start gap-3 rounded-xl border border-line bg-surface px-3 py-2.5"
                >
                  <SignalRow signal={signal} />
                </motion.li>
              ))}
            </ul>

            <div className="mt-4 flex flex-wrap gap-2">
              <Chip className="font-mono text-[11px]">T1566.002 Spearphishing Link</Chip>
              <Chip className="font-mono text-[11px]">T1656 Impersonation</Chip>
            </div>
            <p className="mt-4 flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-line pt-4 text-xs text-ink-muted">
              <Download className="h-3.5 w-3.5" strokeWidth={1.75} aria-hidden="true" />
              HTML · JSON · STIX 2.1 · MISP · Markdown · CSV
            </p>
          </div>
        </Panel>
      </figure>
    </motion.div>
  );
}

function Hero({ signedIn }: { signedIn: boolean }) {
  const words = HEADLINE.split(' ');
  return (
    <section id="top" aria-labelledby="hero-title" className="relative scroll-mt-28 overflow-hidden">
      <div className="ph-glow-bg pointer-events-none absolute inset-x-0 -top-24 bottom-0" aria-hidden="true" />
      <Spotlight className="bg-accent/10 blur-3xl" size={420} />
      <div className={cn(WRAP, 'relative grid grid-cols-1 items-center gap-14 pb-20 pt-12 sm:pt-16 lg:grid-cols-[1.05fr_1fr] lg:gap-14 lg:pb-28 lg:pt-20')}>
        <div className="min-w-0">
          <motion.span
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: EASE }}
            className="inline-flex items-center gap-2.5 rounded-full border border-line-strong bg-surface/80 py-1 pl-1 pr-3.5 backdrop-blur"
          >
            <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-6 w-6 rounded-full" />
            <span className="relative flex h-2 w-2" aria-hidden="true">
              <span className="ph-ping absolute inline-flex h-full w-full rounded-full bg-ok/70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
            </span>
            <TextShimmer as="span" duration={2.4} className="text-[12px] font-medium [--base-color:var(--text-dim)] [--base-gradient-color:var(--text)]">
              Open-source phishing email triage
            </TextShimmer>
          </motion.span>

          <h1 id="hero-title" className="mt-7 text-[40px] font-semibold leading-[1.02] tracking-[-0.045em] text-ink sm:text-[56px] lg:text-[64px]">
            {words.map((word, i) => (
              <Fragment key={i}>
                <span className="inline-block overflow-hidden pb-[0.1em] align-top">
                  <motion.span
                    className={cn(
                      'inline-block',
                      i === words.length - 1 && 'bg-[linear-gradient(100deg,var(--accent),var(--brand))] bg-clip-text text-transparent print:bg-none print:text-ink',
                    )}
                    initial={{ y: '110%' }}
                    animate={{ y: 0 }}
                    transition={{ duration: 0.85, delay: 0.1 + i * 0.07, ease: EASE }}
                  >
                    {word}
                  </motion.span>
                </span>
                {i < words.length - 1 && ' '}
              </Fragment>
            ))}
          </h1>

          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.55, ease: EASE }}
            className="mt-6 max-w-[54ch] text-base leading-relaxed text-ink-dim sm:text-[17px]"
          >
            An analyst drops in a reported email. PhishHawk reads its headers, links, attachments and QR codes, and gives back a verdict with the evidence behind it, a full report
            and files for your other tools. Open source, so all of it can run on your own server.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.7, ease: EASE }}
            className="mt-9 flex flex-wrap items-center gap-3"
          >
            <EnterButton signedIn={signedIn} />
            <SectionLink
              id="how"
              onLanding
              className="group inline-flex h-[52px] items-center gap-2 rounded-full border border-line-strong bg-raised/70 px-6 text-sm font-medium text-ink backdrop-blur transition-colors duration-300 hover:bg-hover"
            >
              See how it works
              <ArrowDown className="h-4 w-4 transition-transform duration-300 group-hover:translate-y-0.5 motion-reduce:transition-none" strokeWidth={1.75} aria-hidden="true" />
            </SectionLink>
          </motion.div>

          <motion.ul
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.9 }}
            className="mt-9 flex flex-wrap gap-x-6 gap-y-3 text-[13px] text-ink-dim"
          >
            {['Self-hostable', 'Offline by default', 'Tamper-evident audit log'].map((fact) => (
              <li key={fact} className="flex items-center gap-2">
                <CircleCheck className="h-4 w-4 text-ok" strokeWidth={1.75} aria-hidden="true" />
                {fact}
              </li>
            ))}
          </motion.ul>
        </div>
        <SampleAnalysis />
      </div>
    </section>
  );
}

/* ---- the strip of formats, mailboxes and tools ---- */

const STRIP = [
  '.eml',
  '.msg',
  '.mbox',
  '.zip',
  'Pasted headers',
  'IMAP',
  'Microsoft Graph',
  'Gmail',
  'QR codes',
  'VirusTotal',
  'urlscan.io',
  'AbuseIPDB',
  'RDAP',
  'MITRE ATT&CK',
  'STIX 2.1',
  'MISP',
  'HTML report',
  'JSON',
  'Markdown',
  'CSV',
  'Docker Compose',
  'PostgreSQL',
  'SQLite',
];

function Strip() {
  return (
    <section aria-label="What PhishHawk reads, checks with and exports" className="border-y border-line bg-surface/60 py-6">
      <p className="mb-4 text-center text-[11px] font-medium uppercase tracking-[0.2em] text-ink-muted">Reads, checks with and exports to</p>
      <div className="ph-marquee overflow-hidden">
        <div className="ph-marquee__track">
          {[0, 1].map((copy) => (
            <ul key={copy} aria-hidden={copy === 1 || undefined} className={cn('ph-marquee__list flex shrink-0 items-center gap-3 pr-3', copy === 1 && 'ph-marquee__copy')}>
              {STRIP.map((item) => (
                <li key={item} className="whitespace-nowrap rounded-full border border-line bg-raised px-4 py-1.5 text-[13px] text-ink-dim">
                  {item}
                </li>
              ))}
            </ul>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---- why: the work a report takes, by hand and with PhishHawk ---- */

const BY_HAND = [
  'Read raw headers and the Received path line by line',
  'Copy every link into something safe before looking at it',
  'Unpack archives and open documents to see what they hide',
  'Scan QR codes with a phone',
  'Write the ticket and list the indicators by hand',
];
const WITH_PHISHHAWK = [
  'SPF, DKIM and DMARC checked, and whether they match the sender',
  'Every link pulled out, defanged and looked at',
  'Archives, disk images and documents opened in memory, nothing run',
  'QR codes decoded into links you can read',
  'A report for the ticket and six files for your tools',
];

function Why() {
  return (
    <section aria-labelledby="why-title" className={cn(WRAP, 'py-24 sm:py-28')}>
      <div className="grid grid-cols-1 gap-12 lg:grid-cols-[0.95fr_1.05fr] lg:items-center lg:gap-16">
        <SectionHead eyebrow="Why PhishHawk" title="A reported email is a question someone has to answer." titleId="why-title">
          Employees report what looks wrong. Every report means reading headers, following links without opening them, unpacking attachments and writing it all up. PhishHawk does
          the reading and shows its work, so your analysts spend their time deciding, not digging.
        </SectionHead>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Reveal>
            <Card className="ph-glow h-full p-6">
              <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-ink-muted">By hand</p>
              <ul className="mt-5 grid gap-3.5">
                {BY_HAND.map((item) => (
                  <li key={item} className="flex gap-3 text-sm leading-snug text-ink-muted">
                    <X className="mt-0.5 h-4 w-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
                    {item}
                  </li>
                ))}
              </ul>
            </Card>
          </Reveal>
          <Reveal delay={0.12}>
            <div className="ph-ring h-full rounded-[28px]">
              <Panel className="h-full" inner="p-6">
                <p className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.18em] text-accent">
                  <img src={asset('brand/phishhawk-mark.svg')} alt="" className="h-4 w-4 rounded" />
                  With PhishHawk
                </p>
                <ul className="mt-5 grid gap-3.5">
                  {WITH_PHISHHAWK.map((item) => (
                    <li key={item} className="flex gap-3 text-sm leading-snug text-ink">
                      <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" strokeWidth={2} aria-hidden="true" />
                      {item}
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* ---- how it works: four steps, and a light that runs from the first to the last ---- */

const STEPS = [
  {
    icon: Inbox,
    title: 'Submit',
    text: 'Upload .eml, .msg, .mbox or .zip files, paste the raw message, or let a connected report mailbox bring new messages in.',
    tags: ['.eml', '.msg', '.mbox', '.zip', 'Paste', 'Mailbox'],
  },
  {
    icon: ScanSearch,
    title: 'Read every part',
    text: 'PhishHawk parses the headers, the body, every link, every attachment, archives and disk images included, and any QR code. In memory; nothing is run.',
    tags: ['Headers', 'Links', 'Attachments', 'QR codes'],
  },
  {
    icon: Gauge,
    title: 'Score with reasons',
    text: 'Each finding has a severity and says why it matters. Together they make the score and one of four verdicts.',
    tags: ['High 3 pts', 'Medium 2 pts', 'Low 1 pt'],
  },
  {
    icon: FileText,
    title: 'Report and act',
    text: 'Read the verdict and the evidence, open the full report, download the exports, and see whether the message is part of a campaign.',
    tags: ['Verdict', 'HTML report', '6 exports', 'Campaign'],
  },
];
// the light reaches one step every STEP_SECONDS (landing.css times its run to match)
const STEP_SECONDS = 1.2;

function HowItWorks() {
  const flow = useRef<HTMLDivElement>(null);
  const live = useInView(flow, { once: true, margin: '-120px' });
  return (
    <section id="how" aria-labelledby="how-title" className="scroll-mt-28 border-t border-line bg-surface/40">
      <div className={cn(WRAP, 'py-24 sm:py-28')}>
        <SectionHead center eyebrow="How it works" title="From a reported email to a decision, in four steps." titleId="how-title">
          Nothing to install on the analyst&apos;s computer and nothing to learn first: a browser, a message, and a few seconds.
        </SectionHead>
        <div ref={flow} className={cn('relative mt-16', live && 'is-live')}>
          {/* across on desktops: the line draws itself, then a light runs along it */}
          <motion.div
            aria-hidden="true"
            className="ph-flow-line absolute left-[12.5%] right-[12.5%] top-8 hidden h-px origin-left lg:block"
            initial={{ scaleX: 0 }}
            animate={live ? { scaleX: 1 } : { scaleX: 0 }}
            transition={{ duration: 1.2, ease: EASE }}
          >
            <span className="ph-flow-spark" />
          </motion.div>
          <ol className="relative grid grid-cols-1 gap-10 lg:grid-cols-4 lg:gap-6">
            {STEPS.map(({ icon: Icon, title, text, tags }, i) => {
              const timing = {
                '--delay': `${i * STEP_SECONDS}s`,
                '--node': `color-mix(in srgb, var(--fx-a), var(--fx-b) ${Math.round((i / (STEPS.length - 1)) * 100)}%)`,
              } as CSSProperties;
              return (
                <motion.li
                  key={title}
                  initial={{ opacity: 0, y: 22 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: '-60px' }}
                  transition={{ duration: 0.6, delay: i * 0.14, ease: EASE }}
                  className="relative grid grid-cols-[64px_minmax(0,1fr)] content-start gap-x-5 lg:grid-cols-1 lg:justify-items-center lg:text-center print:!transform-none print:!opacity-100"
                >
                  {/* down the side on phones and tablets: a line to the next step, with its own run of light */}
                  {i < STEPS.length - 1 && (
                    <span aria-hidden="true" className="ph-flow-line ph-flow-line--down absolute -bottom-10 left-8 top-16 w-px lg:hidden" style={timing}>
                      <span className="ph-flow-spark" />
                    </span>
                  )}
                  <span
                    className="ph-edge ph-flow-node grid h-16 w-16 place-items-center rounded-2xl border border-line-strong bg-surface text-accent shadow-[var(--float-shadow)]"
                    style={timing}
                  >
                    <Icon className="h-7 w-7" strokeWidth={1.5} aria-hidden="true" />
                    <span className="absolute -right-2 -top-2 z-[2] grid h-6 w-6 place-items-center rounded-full font-mono text-[10px] font-semibold text-[var(--on-accent)] [background:linear-gradient(135deg,var(--fx-a),var(--fx-b))]">
                      {i + 1}
                    </span>
                  </span>
                  <div className="min-w-0 lg:mt-6">
                    <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-muted">Step {i + 1}</p>
                    <h3 className="mt-1.5 text-[17px] font-semibold text-ink">{title}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-ink-dim">{text}</p>
                    <ul className="mt-4 flex flex-wrap gap-1.5 lg:justify-center">
                      {tags.map((tag) => (
                        <li key={tag} className="rounded-full border border-line bg-raised px-2.5 py-0.5 text-[11px] text-ink-dim">
                          {tag}
                        </li>
                      ))}
                    </ul>
                  </div>
                </motion.li>
              );
            })}
          </ol>
        </div>
      </div>
    </section>
  );
}

/* ---- what it checks: one part of the message at a time ---- */

const CHECKS: { id: string; label: string; icon: ElementType; title: string; text: string; points: string[]; signals: Signal[] }[] = [
  {
    id: 'sender',
    label: 'Sender and headers',
    icon: AtSign,
    title: 'Who really sent it',
    text: 'Phishing borrows a name it does not own. PhishHawk compares the display name, the From address, Reply-To and the domains that signed the message, checks SPF, DKIM and DMARC, and follows the path the message took between mail servers.',
    points: [
      'SPF, DKIM and DMARC, and whether they match the From domain',
      'Look-alike domains and display names, mixed alphabets included',
      'Free-mail senders asking for money: the business email compromise pattern',
      'Authentication-Results headers forged by the sender',
    ],
    signals: [
      { severity: 'high', text: "display name claims 'PayPal' but the domain is pay-secure.example" },
      { severity: 'high', text: 'sender address uses bank.example, but the message is not authenticated for it' },
      { severity: 'medium', text: "display name 'Payroll Team' reads as an organisation but the address is free-mail (gmail.com)" },
      { severity: 'low', text: 'greets the recipient by email address instead of by name' },
    ],
  },
  {
    id: 'links',
    label: 'Links',
    icon: Link2,
    title: 'Where the links really go',
    text: 'Every link is pulled out of the text, the HTML, the attachments and the QR codes, and shown defanged, as hxxp and [.], so nobody opens it by mistake. PhishHawk looks at where each one really leads, not at the words it is dressed in.',
    points: [
      'Raw and disguised IP addresses, and hosts hidden behind @',
      'Punycode and look-alike host names',
      'Shortened links, and link text that shows a different site',
      'Pages built into the link itself, and links that run JavaScript',
    ],
    signals: [
      { severity: 'high', text: 'URL points at a raw IP: hxxp://203.0.113[.]24/login' },
      { severity: 'high', text: "URL hides its real host behind '@': hxxps://paypal.com@198.51.100[.]9/" },
      { severity: 'high', text: 'punycode URL host: xn--pypal-4ve[.]example' },
      { severity: 'medium', text: 'shortened link: hxxps://short[.]example/a1b2' },
    ],
  },
  {
    id: 'files',
    label: 'Attachments',
    icon: Paperclip,
    title: 'What the files would do',
    text: 'Attachments are read as data, in memory, and never run. PhishHawk records each file’s hashes, opens archives and disk images to look inside, and checks documents for the tricks that turn opening a file into running one.',
    points: [
      'ZIP, 7z, RAR, TAR, ISO and VHD contents; password-protected archives flagged',
      'Office macros, PDF launch actions and forms, RTF exploits, HTML smuggling',
      'Double extensions, right-to-left name tricks and shortcut files',
      'MD5, SHA-1 and SHA-256 for every file, ready to search for',
    ],
    signals: [
      { severity: 'high', text: 'macro-enabled document: invoice_0921.docm' },
      { severity: 'high', text: 'double extension: statement.pdf.exe' },
      { severity: 'high', text: 'PDF scan_0921.pdf has a launch action that starts a program' },
      { severity: 'high', text: 'password-protected archive: documents.zip' },
    ],
  },
  {
    id: 'qr',
    label: 'QR codes',
    icon: QrCode,
    title: 'The links you cannot see',
    text: 'Quishing hides the link in a picture, where filters do not look, and moves the click to a personal phone. PhishHawk decodes QR codes and checks what they hold like any other link.',
    points: [
      'Image attachments and inline images',
      'Images inside PDF attachments and in the HTML itself',
      'Codes drawn with HTML table cells or Unicode blocks',
      'Phone numbers to call or text, as well as links',
    ],
    signals: [
      { severity: 'high', text: 'URL points at a raw IP: hxxp://198.51.100[.]7/mfa, from a QR code' },
      { severity: 'medium', text: 'QR code in image001.png calls or texts +1 555 0100' },
      { severity: 'medium', text: 'shortened link: hxxps://short[.]example/q, from a QR code' },
    ],
  },
  {
    id: 'hidden',
    label: 'Hidden tricks',
    icon: EyeOff,
    title: 'What filters are not meant to see',
    text: 'To slip past filters, phishing hides its words: invisible characters, text nobody can see, letters borrowed from other alphabets, styled Unicode. PhishHawk reads the message the way a filter would and the way a person would, and reports the difference.',
    points: [
      'Zero-width and invisible characters in the subject and body',
      'Hidden text that breaks words apart',
      'Mixed alphabets and styled Unicode letters',
      'Links encoded in base64, and MIME parts nested too deep',
    ],
    signals: [
      { severity: 'high', text: 'hidden text breaks up words in 7 places, so filters read something else' },
      { severity: 'medium', text: '12 zero-width characters hidden in the body (filter evasion)' },
      { severity: 'medium', text: 'subject mixes alphabets inside a word (Pаypal): look-alike letters' },
      { severity: 'medium', text: 'MIME parts nested 9 levels deep; real mail stays under five (filter evasion)' },
    ],
  },
  {
    id: 'lures',
    label: 'Lures',
    icon: Megaphone,
    title: 'What it wants you to do',
    text: 'Phishing always asks for something: a password, a payment, a call. PhishHawk knows the wording of the common lures, in English and other languages, and the call-back scams that send a phone number instead of a link.',
    points: [
      'Sign-in and password requests',
      'Invoices, payment changes, parcels and prizes',
      'Crypto wallets, extortion and advance-fee scams',
      'Call-back phishing: a number to call, no link at all',
    ],
    signals: [
      { severity: 'high', text: 'asks for payment to a BTC wallet (extortion wording)' },
      { severity: 'medium', text: 'credential lure wording: verify your account, password expires' },
      { severity: 'medium', text: 'free-mail sender asks for money (wire transfer): business email compromise pattern' },
    ],
  },
];

function Checks() {
  const [active, setActive] = useState(0);
  return (
    <section id="checks" aria-labelledby="checks-title" className={cn(WRAP, 'scroll-mt-28 py-24 sm:py-28')}>
      <SectionHead eyebrow="What it checks" title="Every part of the message, read the way an analyst would." titleId="checks-title">
        Pick a part of the message to see what PhishHawk looks for there, and the kind of findings it reports.
      </SectionHead>

      <Reveal className="-mx-4 mt-10 overflow-x-auto px-4 pb-1 [scrollbar-width:none]">
        <div className="w-max rounded-full border border-line bg-sunken p-1" role="group" aria-label="Part of the message">
          <AnimatedBackground
            defaultValue="sender"
            onValueChange={(id) => id && setActive(CHECKS.findIndex((c) => c.id === id))}
            className="rounded-full [background:var(--pill-active-bg)]"
            transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
          >
            {CHECKS.map(({ id, label, icon: Icon }, i) => (
              <button
                key={id}
                data-id={id}
                type="button"
                aria-pressed={active === i}
                className={cn(
                  'h-9 items-center justify-center rounded-full px-4 text-sm font-medium transition-colors duration-300',
                  active === i ? 'text-[var(--pill-active-ink)]' : 'text-ink-dim hover:text-ink',
                )}
              >
                <span className="flex items-center gap-2">
                  <Icon className="h-4 w-4" strokeWidth={1.75} aria-hidden="true" />
                  {label}
                </span>
              </button>
            ))}
          </AnimatedBackground>
        </div>
      </Reveal>

      <Reveal className="mt-6">
        <Panel className="ph-edge ph-glow" inner="overflow-hidden">
          <TransitionPanel
            activeIndex={active}
            transition={{ duration: 0.3, ease: EASE }}
            variants={{
              enter: { opacity: 0, y: 10, filter: 'blur(4px)' },
              center: { opacity: 1, y: 0, filter: 'blur(0px)' },
              exit: { opacity: 0, y: -10, filter: 'blur(4px)' },
            }}
          >
            {CHECKS.map((check) => (
              <div key={check.id} className="grid grid-cols-1 gap-10 p-6 sm:p-8 lg:min-h-[400px] lg:grid-cols-[1fr_1.1fr] lg:gap-12">
                <div className="min-w-0">
                  <IconTile icon={check.icon} className="h-12 w-12 rounded-2xl" />
                  <h3 className="mt-5 text-2xl font-semibold tracking-[-0.02em] text-ink">{check.title}</h3>
                  <p className="mt-3 text-[15px] leading-relaxed text-ink-dim">{check.text}</p>
                  <ul className="mt-6 grid gap-2.5">
                    {check.points.map((point) => (
                      <li key={point} className="flex gap-2.5 text-sm text-ink-dim">
                        <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" strokeWidth={2} aria-hidden="true" />
                        {point}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="min-w-0">
                  <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-ink-muted">Findings it reports</p>
                  <ul className="mt-3 grid gap-2.5">
                    {check.signals.map((signal, i) => (
                      <motion.li
                        key={signal.text}
                        initial={{ opacity: 0, x: 12 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.4, delay: 0.08 + i * 0.07, ease: EASE }}
                        className="flex items-start gap-3 rounded-xl border border-line bg-raised/60 px-3.5 py-3"
                      >
                        <SignalRow signal={signal} />
                      </motion.li>
                    ))}
                  </ul>
                  <p className="mt-3 text-xs text-ink-muted">Examples in PhishHawk&apos;s own words, with made-up names and addresses.</p>
                </div>
              </div>
            ))}
          </TransitionPanel>
        </Panel>
      </Reveal>
    </section>
  );
}

/* ---- what every analysis gives back ---- */

const RESULTS = [
  { icon: Gauge, title: 'A verdict and a score you can trace', text: 'One of four verdicts, and a score that adds up from the findings: 3 for each high, 2 for each medium, and at most 3 for all the low ones together.' },
  { icon: ListChecks, title: 'Findings that explain themselves', text: 'Every finding has a severity, says why it matters and what to check before you act on it.' },
  { icon: Fingerprint, title: 'Indicators, defanged', text: 'Links, domains, IP addresses, email addresses and file hashes, ready to copy into a search or a block list.' },
  { icon: Crosshair, title: 'Mapped to MITRE ATT&CK', text: 'Findings carry their ATT&CK techniques, such as T1566.002 Spearphishing Link, each linked to its page.' },
  { icon: FileText, title: 'A full report for the ticket', text: 'A self-contained HTML report: the summary, the findings, the mail path, authentication, every link and every file. It opens in a sandbox.' },
  { icon: Download, title: 'Six files for your other tools', text: 'HTML, JSON, STIX 2.1, MISP, Markdown and CSV, for your SIEM, your threat-intelligence platform or a spreadsheet.' },
  { icon: Network, title: 'Campaigns, found for you', text: 'Messages that share an attachment, a phishing link, a QR payload, a sender, a wallet or a phone number are grouped, so twenty reports of one lure are one investigation.' },
  { icon: Hash, title: 'Evidence you can vouch for', text: 'Each message’s SHA-256 and size are recorded when it arrives, and every download is written to the audit log.' },
];

function Results() {
  return (
    <section id="results" aria-labelledby="results-title" className="scroll-mt-28 border-t border-line bg-surface/40">
      <div className={cn(WRAP, 'py-24 sm:py-28')}>
        <SectionHead center eyebrow="What you get" title="Every analysis comes back with the evidence." titleId="results-title">
          A verdict alone is a guess. PhishHawk shows how it got there, and hands you everything you need for the ticket and the tools that come after it.
        </SectionHead>
        <ul className="mt-14 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {RESULTS.map(({ icon, title, text }, i) => (
            <li key={title}>
              <Reveal delay={(i % 4) * 0.08} className="h-full">
                <div className="ph-edge ph-glow group h-full overflow-hidden rounded-[22px] border border-line bg-surface p-5 transition-colors duration-300 hover:border-line-strong">
                  <Spotlight className="bg-accent/10 blur-2xl" size={220} />
                  <IconTile icon={icon} className="relative transition-transform duration-300 group-hover:-translate-y-0.5 motion-reduce:transition-none" />
                  <h3 className="relative mt-5 text-[15px] font-semibold text-ink">{title}</h3>
                  <p className="relative mt-2 text-[13px] leading-relaxed text-ink-dim">{text}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/** The report itself, dark and light side by side; only when the pictures are in this build. */
function ReportPreview() {
  const dark = asset('brand/report-dark.webp');
  const light = asset('brand/report-light.webp');
  const loaded = usePicturesLoaded([dark, light]);
  if (!loaded) return null;
  return (
    <section aria-labelledby="report-title" className={cn(WRAP, 'py-24 sm:py-28')}>
      <div className="grid grid-cols-1 items-center gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
        <SectionHead eyebrow="The report" title="One page the whole team can read." titleId="report-title">
          The HTML report goes into the ticket as it is: the verdict and why, the findings with what to check, the mail path, authentication, every link and every file. Move across
          it to compare the dark and the light theme.
        </SectionHead>
        <Reveal>
          <Panel inner="overflow-hidden">
            <div className="relative aspect-[1180/1240] max-h-[72vh] w-full overflow-hidden rounded-[22px]">
              <ImageComparison className="h-full w-full" enableHover springOptions={{ bounce: 0.3 }}>
                <ImageComparisonImage src={dark} alt="The HTML report, dark theme" position="left" />
                <ImageComparisonImage src={light} alt="The HTML report, light theme" position="right" />
                <ImageComparisonSlider className="w-0.5 bg-white/50" />
              </ImageComparison>
              <Cursor attachToParent springConfig={{ bounce: 0.001 }}>
                <span className="rounded-full bg-black/80 px-2.5 py-1 text-xs text-white">Compare</span>
              </Cursor>
            </div>
          </Panel>
        </Reveal>
      </div>
    </section>
  );
}

/* ---- the numbers, measured ---- */

// the lines between the numbers: one column on phones, two by two, then one row
const NUMBER_LINES = ['border-b sm:border-r lg:border-b-0', 'border-b lg:border-b-0 lg:border-r', 'border-b sm:border-b-0 sm:border-r', ''];

const NUMBERS = [
  { value: 81.3, decimals: 1, unit: '%', label: 'of real phishing flagged', detail: '5,714 emails it had never seen. 46.9% of them were called likely phishing.' },
  { value: 0.8, decimals: 1, unit: '%', label: 'false positives', detail: '46 of 5,945 real legitimate emails were flagged by mistake.' },
  { value: 9, decimals: 0, unit: 'ms', label: 'median per message', detail: 'Measured on the same 5,714 emails, offline.' },
  { value: 0, decimals: 0, unit: '', label: 'indicators sent out by default', detail: 'Reputation providers stay off until an admin turns them on.' },
];

function Numbers() {
  return (
    <section id="numbers" aria-labelledby="numbers-title" className={cn(WRAP, 'scroll-mt-28 py-24 sm:py-28')}>
      <SectionHead center eyebrow="Measured" title="Tested on mail it had never seen." titleId="numbers-title">
        The engine was tuned on one set of real mail and scored once, at the end, on another it had never seen. These are the results.
      </SectionHead>
      <Reveal className="mt-14">
        <Panel className="ph-edge ph-glow">
          <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
            {NUMBERS.map(({ value, decimals, unit, label, detail }, i) => (
              <div key={label} className={cn('border-line px-6 py-7 sm:px-7', NUMBER_LINES[i])}>
                <dt className="text-sm font-medium text-ink">{label}</dt>
                <dd className="mt-3">
                  <span className="flex items-baseline gap-1 text-[44px] font-semibold leading-none tracking-[-0.04em] text-ink">
                    <CountUp to={value} decimals={decimals} />
                    {unit && <span className="text-xl font-medium tracking-normal text-ink-muted">{unit}</span>}
                  </span>
                  <span className="mt-3 block text-[13px] leading-relaxed text-ink-dim">{detail}</span>
                </dd>
              </div>
            ))}
          </dl>
        </Panel>
      </Reveal>
      <p className="mx-auto mt-6 max-w-[90ch] text-center text-xs leading-relaxed text-ink-muted">
        Measured with the PhishHawk 2.2 engine, offline and with no reputation lookups, on held-out real mail scored once after all tuning. The phishing comes from the phishing_pot
        honeypot, 2022 to 2026. A verdict can still be wrong in either direction, so check the findings before you act.
      </p>
    </section>
  );
}

/* ---- the four verdicts ---- */

const LEVEL: Record<Verdict, number> = { MALICIOUS: 4, 'LIKELY PHISHING': 3, SUSPICIOUS: 2, 'NO STRONG INDICATORS': 1 };
const FILL: Record<Verdict, string> = { MALICIOUS: 'bg-v-malicious', 'LIKELY PHISHING': 'bg-v-phishing', SUSPICIOUS: 'bg-v-suspicious', 'NO STRONG INDICATORS': 'bg-v-neutral' };

function Verdicts() {
  return (
    <section id="verdicts" aria-labelledby="verdicts-title" className="scroll-mt-28 border-t border-line bg-surface/40">
      <div className={cn(WRAP, 'grid grid-cols-1 gap-12 py-24 sm:py-28 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16')}>
        <SectionHead eyebrow="Verdicts" title="Four verdicts, from proof to nothing found." titleId="verdicts-title">
          A verdict sums up the findings; it never replaces them. Every analysis lists the signals behind its verdict, so you can see why, and disagree when you know better.
        </SectionHead>
        <Reveal>
          <Card className="ph-edge ph-glow overflow-hidden">
            <ul>
              {VERDICT_MEANING.map(([verdict, meaning]) => (
                <li key={verdict} className="flex items-center gap-6 border-b border-line px-5 py-5 last:border-b-0 sm:px-6">
                  <div className="grid min-w-0 flex-1 gap-2.5">
                    <span>
                      <VerdictBadge verdict={verdict} />
                    </span>
                    <p className="text-sm leading-relaxed text-ink-dim">{meaning}</p>
                  </div>
                  <span className="hidden gap-1 sm:flex" aria-hidden="true">
                    {[1, 2, 3, 4].map((n) => (
                      <motion.span
                        key={n}
                        className={cn('h-6 w-1.5 origin-bottom rounded-full', n <= LEVEL[verdict] ? FILL[verdict] : 'bg-line-strong')}
                        initial={{ scaleY: 0.2, opacity: 0 }}
                        whileInView={{ scaleY: 1, opacity: 1 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.5, delay: 0.15 + n * 0.07, ease: EASE }}
                      />
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      </div>
    </section>
  );
}

/* ---- ways to use it, for analysts and for admins ---- */

type Audience = 'Analysts' | 'Admins';
type Way = { icon: ElementType; audience: Audience; title: string; text: string; points: string[]; command?: string; cta?: string; href?: string };

const WAYS: Way[] = [
  {
    icon: Inbox,
    audience: 'Analysts',
    title: 'Web console',
    text: 'Upload or paste a reported message and read the verdict, the findings and the full report in your browser.',
    points: ['An Offline analysis switch for sensitive mail', 'One queue for the team: search a SHA-256, report ID or indicator', 'Re-analyse, delete, or download every file'],
    cta: 'Open Triage',
    href: '/app/',
  },
  {
    icon: Layers,
    audience: 'Analysts',
    title: 'Batches and campaigns',
    text: 'Upload an .mbox, a .zip or several files at once. Each message is analysed, and related ones are grouped into campaigns.',
    points: ['Up to 500 messages in one batch', 'Combined reports for the whole batch', 'Campaigns across the last 90 days of reports'],
    cta: 'Open Campaigns',
    href: '/app/campaigns',
  },
  {
    icon: Terminal,
    audience: 'Analysts',
    title: 'Command line',
    text: 'The same engine in a terminal, with no server and no account: for one-off checks, scripts and pipelines.',
    command: 'phishhawk scan suspicious.eml --offline --html report.html',
    points: ['--fail-on sets the exit code for a pipeline', 'Reads IMAP, Microsoft Graph and Gmail mailboxes too', 'HTML, JSON, STIX 2.1, MISP, Markdown and CSV out'],
  },
  {
    icon: Mailbox,
    audience: 'Admins',
    title: 'Report mailboxes',
    text: 'Connect the mailbox your employees forward suspicious mail to. PhishHawk picks up new messages and analyses each one on its own.',
    points: ['IMAP, Microsoft Graph or Gmail', 'Read-only: nothing is moved, marked as read or deleted', 'Its credentials are stored encrypted'],
    cta: 'Open Mailboxes',
    href: '/app/mailboxes',
  },
  {
    icon: KeyRound,
    audience: 'Admins',
    title: 'API tokens',
    text: 'Give a SOAR playbook or a script its own token, to submit messages and fetch results over the same API the web app uses.',
    points: ['Shown once, then kept only as a hash', 'Revoked in one click', 'One token per script, so each can be revoked alone'],
    cta: 'Open API tokens',
    href: '/app/tokens',
  },
  {
    icon: Server,
    audience: 'Admins',
    title: 'Run it yourself',
    text: 'One container with Docker Compose, on SQLite or PostgreSQL, behind your own TLS proxy. You hold the keys.',
    command: 'docker compose up -d',
    points: ['You create the session and the encryption key', '30-day retention by default, with Hold for what must stay', 'A Health page for the server and its worker'],
    cta: 'Open Health',
    href: '/app/health',
  },
];

function WayCard({ way, signedIn }: { way: Way; signedIn: boolean }) {
  const { icon, audience, title, text, points, command, cta, href } = way;
  // signed out, the start page is this page: the console starts at the sign-in form
  const target = !href ? null : signedIn || href !== '/app/' ? href : '/app/login';
  return (
    <article className="ph-edge ph-glow group flex h-full flex-col overflow-hidden rounded-[24px] border border-line bg-surface p-6 transition-colors duration-300 hover:border-line-strong">
      <Spotlight className="bg-accent/10 blur-3xl" size={280} />
      <div className="relative flex items-center justify-between gap-3">
        <IconTile icon={icon} />
        <Chip>{audience}</Chip>
      </div>
      <h3 className="relative mt-5 text-lg font-semibold tracking-[-0.01em] text-ink">{title}</h3>
      <p className="relative mt-2 text-sm leading-relaxed text-ink-dim">{text}</p>
      {command && (
        <div className="relative mt-4 flex items-center justify-between gap-2 rounded-xl border border-line bg-sunken py-1.5 pl-3 pr-1.5">
          <code className="min-w-0 font-mono text-xs leading-relaxed text-ink [overflow-wrap:anywhere]">{command}</code>
          <CopyButton text={command} />
        </div>
      )}
      <ul className="relative mt-5 grid gap-2.5">
        {points.map((point) => (
          <li key={point} className="flex gap-2.5 text-[13px] leading-snug text-ink-dim">
            <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" strokeWidth={2} aria-hidden="true" />
            {point}
          </li>
        ))}
      </ul>
      {target && cta && (
        <Link href={target} className="relative mt-auto inline-flex items-center gap-1.5 pt-6 text-sm font-medium text-ink transition-colors hover:text-accent">
          {cta}
          <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5 motion-reduce:transition-none" strokeWidth={1.75} aria-hidden="true" />
        </Link>
      )}
    </article>
  );
}

function Ways({ signedIn }: { signedIn: boolean }) {
  const [audience, setAudience] = useState<'All' | Audience>('All');
  const shown = WAYS.filter((way) => audience === 'All' || way.audience === audience);
  return (
    <section id="ways" aria-labelledby="ways-title" className={cn(WRAP, 'scroll-mt-28 py-24 sm:py-28')}>
      <div className="flex flex-wrap items-end justify-between gap-8">
        <SectionHead eyebrow="Ways to use it" title="One engine, wherever the reports arrive." titleId="ways-title">
          Analysts work in the browser or the terminal; admins connect mailboxes and scripts, and run the server.
        </SectionHead>
        <Reveal>
          <div className="w-max rounded-full border border-line bg-sunken p-1" role="group" aria-label="Show the ways for">
            <AnimatedBackground
              defaultValue="All"
              onValueChange={(id) => id && setAudience(id as 'All' | Audience)}
              className="rounded-full [background:var(--pill-active-bg)]"
              transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
            >
              {(['All', 'Analysts', 'Admins'] as const).map((id) => (
                <button
                  key={id}
                  data-id={id}
                  type="button"
                  aria-pressed={audience === id}
                  className={cn(
                    'h-9 items-center justify-center rounded-full px-4 text-sm font-medium transition-colors duration-300',
                    audience === id ? 'text-[var(--pill-active-ink)]' : 'text-ink-dim hover:text-ink',
                  )}
                >
                  {id}
                </button>
              ))}
            </AnimatedBackground>
          </div>
        </Reveal>
      </div>
      <motion.ul layout className="mt-12 grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3">
        <AnimatePresence initial={false}>
          {shown.map((way) => (
            <motion.li
              key={way.title}
              layout
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.96 }}
              transition={{ duration: 0.3, ease: EASE }}
            >
              <WayCard way={way} signedIn={signedIn} />
            </motion.li>
          ))}
        </AnimatePresence>
      </motion.ul>
    </section>
  );
}

/* ---- built for sensitive mail ---- */

const TRUST = [
  { icon: Server, title: 'Runs where you choose', text: 'Self-host it, and messages are analysed on a server you control. On a PhishHawk someone else runs, they are analysed on that server: Privacy says whose, and where.' },
  { icon: WifiOff, title: 'Offline by default', text: 'A new installation sends nothing anywhere. With providers on, only indicators are looked up, never the message, and Offline analysis turns them off for one message.' },
  { icon: Lock, title: 'Encrypted at rest', text: 'Each message, its report and its export files are stored encrypted, and so are mailbox credentials and provider keys.' },
  { icon: Hourglass, title: 'Kept only as long as needed', text: 'Messages are deleted after 30 days unless your admin changes it. Hold keeps one longer; Delete now removes it at once.' },
  { icon: ScrollText, title: 'An audit log you can check', text: 'Sign-ins, downloads, deletions and setting changes are recorded, each chained to the one before, so a changed or missing record is detected.' },
  { icon: ShieldCheck, title: 'Defanged and sandboxed', text: 'Links are shown as hxxp and [.] so they cannot be opened by mistake, and the HTML report opens in a sandbox.' },
  { icon: Users, title: 'Two roles, clear limits', text: 'Analysts submit and read analyses. Admins also manage users, tokens, mailboxes and settings. Only the submitter and admins can download the original message.' },
  { icon: Cookie, title: 'One cookie, no tracking', text: 'PhishHawk sets a single sign-in cookie that scripts cannot read. No analytics, no advertising, nothing loaded from other sites.' },
];

function Trust() {
  return (
    <section id="trust" aria-labelledby="trust-title" className="relative scroll-mt-28 overflow-hidden border-t border-line bg-surface/40">
      <div className="ph-glow-bg pointer-events-none absolute inset-0 opacity-80" aria-hidden="true" />
      <div className={cn(WRAP, 'relative py-24 sm:py-28')}>
        <SectionHead center eyebrow="Built for sensitive mail" title="Reported email holds personal data and live attacks." titleId="trust-title">
          PhishHawk is built to keep both contained: on the server that runs it, encrypted, recorded, and deleted on schedule.
        </SectionHead>
        <ul className="mt-14 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {TRUST.map(({ icon, title, text }, i) => (
            <li key={title}>
              <Reveal delay={(i % 4) * 0.07} className="h-full">
                <div className="ph-edge ph-glow h-full rounded-[22px] border border-line bg-surface/90 p-5 backdrop-blur">
                  <IconTile icon={icon} />
                  <h3 className="mt-4 text-[15px] font-semibold text-ink">{title}</h3>
                  <p className="mt-2 text-[13px] leading-relaxed text-ink-dim">{text}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ul>
        <p className="mt-8 text-center text-[13px] text-ink-muted">
          The details are in{' '}
          <Link href="/app/privacy" className="text-ink underline underline-offset-2 hover:text-accent">
            Privacy and terms
          </Link>
          .
        </p>
      </div>
    </section>
  );
}

/* ---- questions ---- */

function Faq() {
  return (
    <section id="faq" aria-labelledby="faq-title" className={cn(WRAP, 'scroll-mt-28 py-24 sm:py-28')}>
      <div className="grid grid-cols-1 gap-12 lg:grid-cols-[0.75fr_1.25fr] lg:gap-16">
        <div className="lg:sticky lg:top-28 lg:self-start">
          <SectionHead eyebrow="Questions" title="Questions and answers." titleId="faq-title">
            What people ask before they use PhishHawk for the first time.
          </SectionHead>
          <Reveal className="mt-6">
            <p className="text-sm text-ink-dim">
              More answers are in{' '}
              <Link href="/app/help" className="text-ink underline underline-offset-2 hover:text-accent">
                Help
              </Link>
              . For anything else, ask your PhishHawk admin.
            </p>
          </Reveal>
        </div>
        <Reveal>
          <Card className="ph-edge ph-glow overflow-hidden">
            <Question question="What is PhishHawk?">
              <p>
                An open-source phishing triage tool, built to run on your organisation&apos;s own server. An analyst gives it a reported email; it reads the headers, links, attachments and QR codes, and
                gives back a verdict, the findings behind it, a full HTML report and export files. It is open-source software under the MIT licence.
              </p>
            </Question>
            <Question question="Does a reported email leave our server?">
              <p>
                Nothing does, on a new installation. An admin can turn on reputation providers: VirusTotal, urlscan.io, AbuseIPDB and RDAP. PhishHawk then looks up indicators from
                the message with them, such as links, domains and IP addresses. It never sends them the message itself.
              </p>
              <p>To send nothing for one message, turn on Offline analysis when you submit it. Each analysis records which providers were asked.</p>
              <p>If you use a PhishHawk someone else runs, the email you submit goes to their server: Privacy says who runs it and where.</p>
            </Question>
            <Question question="How do I get an account?">
              <p>
                If this server is open for sign-up, choose Create account. Otherwise, ask your PhishHawk admin, who adds people on the Users page or sends them an invitation. If
                this server sends email, Forgot password? on the sign-in form resets a lost password.
              </p>
            </Question>
            <Question question="Which files can I submit?">
              <p>
                One or more .eml or .msg files, an .mbox or a .zip, or the full message pasted with its headers. Several messages are analysed together as a batch. Each message can be
                up to 25 MB, a whole upload four times that, and a batch up to 500 messages; your admin can change these limits.
              </p>
            </Question>
            <Question question="Does it open or run the attachments?">
              <p>
                It opens them as data and never runs them. Archives and disk images are unpacked in memory, documents and PDFs are read for macros, scripts and launch actions, and every
                file&apos;s hashes are recorded. To watch a file run, use your sandbox: the findings tell you which files deserve it.
              </p>
            </Question>
            <Question question="How accurate is it?">
              <p>
                On 5,714 real phishing emails it had never seen, it flagged 81.3%, and it flagged 46 of 5,945 legitimate emails by mistake (0.8%). That was offline, with no reputation
                lookups. A verdict can still be wrong in either direction, which is why every verdict comes with the findings behind it.
              </p>
            </Question>
            <Question question="Who can see what?">
              <p>
                Everyone in your workspace sees its analyses and can download their reports; no one sees another workspace&apos;s. The original message can be downloaded by the analyst who
                submitted it and by admins.
                Analysts see their own entries in the audit log; admins see all of it, and also Health, Settings, Users, API tokens and Mailboxes.
              </p>
            </Question>
            <Question question="How long is a message kept?">
              <p>
                The message and its reports are deleted after the retention period: 30 days unless your admin changed it. Delete now removes them at once. An admin can put a message on
                hold to keep it past the retention period.
              </p>
            </Question>
            <Question question="Can it watch our report mailbox?">
              <p>
                Yes. An admin connects it on the Mailboxes page, over IMAP, Microsoft Graph or Gmail. PhishHawk reads new messages without changing anything in the mailbox, analyses each
                one and puts it in the queue with the rest.
              </p>
            </Question>
            <Question question="Can our other tools use it?">
              <p>
                Yes. Admins create API tokens for scripts and SOAR playbooks, which submit messages and fetch results over the same API this app uses. Every analysis also downloads as
                JSON, STIX 2.1, MISP, Markdown and CSV.
              </p>
            </Question>
            <Question question="What does it not do?">
              <p>It does not block, move or delete mail in anyone&apos;s mailbox, and it does not run attachments. It reports, with the evidence; people decide.</p>
            </Question>
          </Card>
        </Reveal>
      </div>
    </section>
  );
}

/* ---- the last call ---- */

function FinalCall({ signedIn }: { signedIn: boolean }) {
  return (
    <section aria-labelledby="final-title" className={cn(WRAP, 'pt-4')}>
      <Reveal>
        <div className="ph-ring rounded-[28px]">
          <Panel inner="relative overflow-hidden">
            <div className="ph-glow-bg pointer-events-none absolute inset-0" aria-hidden="true" />
            <div className="ph-breathe pointer-events-none absolute inset-x-0 -top-28 mx-auto h-72 w-72 rounded-full bg-brand/25 blur-3xl" aria-hidden="true" />
            <div className="relative grid justify-items-center gap-6 px-6 py-16 text-center sm:py-20">
              <img src={asset('brand/phishhawk-mark.svg')} alt="" className="ph-float h-20 w-20 rounded-[22px] shadow-[0_24px_60px_-18px_var(--brand)]" />
              <h2 id="final-title" className="max-w-[20ch] text-[32px] font-semibold leading-[1.08] tracking-[-0.03em] text-ink sm:text-[44px]">
                Ready for the next reported email?
              </h2>
              <p className="max-w-[52ch] text-[15px] leading-relaxed text-ink-dim">
                {signedIn
                  ? 'Your console is one click away.'
                  : 'Sign in, or create an account if this server is open for sign-up. No account yet? Ask your PhishHawk admin.'}
              </p>
              <EnterButton signedIn={signedIn} />
            </div>
          </Panel>
        </div>
      </Reveal>
    </section>
  );
}

export default function LandingScreen({ signedIn }: { signedIn: boolean }) {
  // arriving with an address like /app/about#faq: go to that section
  useEffect(() => {
    const id = decodeURIComponent(window.location.hash.slice(1));
    if (!id) return;
    const timer = window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ block: 'start' }), 60);
    return () => window.clearTimeout(timer);
  }, []);

  return (
    <div
      className="ph-landing"
      onPointerMove={(event) => {
        // the light on a box's edge follows the pointer
        const box = (event.target as Element).closest<HTMLElement>('.ph-glow');
        if (!box) return;
        const rect = box.getBoundingClientRect();
        box.style.setProperty('--mx', `${event.clientX - rect.left}px`);
        box.style.setProperty('--my', `${event.clientY - rect.top}px`);
      }}
    >
      <div className="pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 overflow-hidden print:hidden">
        <ScrollProgress className="absolute h-0.5 bg-[linear-gradient(90deg,var(--accent),var(--brand))]" />
      </div>
      <Hero signedIn={signedIn} />
      <Strip />
      <Why />
      <HowItWorks />
      <Checks />
      <Results />
      <ReportPreview />
      <Numbers />
      <Verdicts />
      <Ways signedIn={signedIn} />
      <Trust />
      <Faq />
      <FinalCall signedIn={signedIn} />
    </div>
  );
}
