// This code comes from https://github.com/adobe/react-spectrum/blob/main/packages/%40react-aria/overlays/src/usePreventScroll.ts

import { useEffect, useLayoutEffect } from 'react';

function isMac(): boolean | undefined {
  return testPlatform(/^Mac/);
}

function isIPhone(): boolean | undefined {
  return testPlatform(/^iPhone/);
}

function isIPad(): boolean | undefined {
  return (
    testPlatform(/^iPad/) ||
    (isMac() && navigator.maxTouchPoints > 1)
  );
}

function isIOS(): boolean | undefined {
  return isIPhone() || isIPad();
}

function testPlatform(re: RegExp): boolean | undefined {
  return typeof window !== 'undefined' && window.navigator != null
    ? re.test(window.navigator.platform)
    : undefined;
}

const KEYBOARD_BUFFER = 24;

export const useIsomorphicLayoutEffect =
  typeof window !== 'undefined' ? useLayoutEffect : useEffect;

interface PreventScrollOptions {
  /** Whether the scroll lock is disabled. */
  isDisabled?: boolean;
  focusCallback?: () => void;
}

function chain(...callbacks: any[]): (...args: any[]) => void {
  return (...args: any[]) => {
    for (let callback of callbacks) {
      if (typeof callback === 'function') {
        callback(...args);
      }
    }
  };
}

// @ts-ignore
const visualViewport = typeof document !== 'undefined' && window.visualViewport;

export function isScrollable(node: Element): boolean {
  let style = window.getComputedStyle(node);
  return /(auto|scroll)/.test(
    style.overflow + style.overflowX + style.overflowY
  );
}

export function getScrollParent(node: Element): Element {
  if (isScrollable(node)) {
    node = node.parentElement as HTMLElement;
  }

  while (node && !isScrollable(node)) {
    node = node.parentElement as HTMLElement;
  }

  return node || document.scrollingElement || document.documentElement;
}

const nonTextInputTypes = new Set([
  'checkbox',
  'radio',
  'range',
  'color',
  'file',
  'image',
  'button',
  'submit',
  'reset',
]);

let preventScrollCount = 0;
let restore: () => void;

export function usePreventScroll(options: PreventScrollOptions = {}) {
  let { isDisabled } = options;

  useIsomorphicLayoutEffect(() => {
    if (isDisabled) {
      return;
    }

    preventScrollCount++;
    if (preventScrollCount === 1) {
      if (isIOS()) {
        restore = preventScrollMobileSafari();
      }
    }

    return () => {
      preventScrollCount--;
      if (preventScrollCount === 0) {
        restore?.();
      }
    };
  }, [isDisabled]);
}

function preventScrollMobileSafari() {
  let scrollable: Element;
  let lastY = 0;
  let onTouchStart = (e: TouchEvent) => {
    scrollable = getScrollParent(e.target as Element);
    if (
      scrollable === document.documentElement &&
      scrollable === document.body
    ) {
      return;
    }

    lastY = e.changedTouches[0].pageY;
  };

  let onTouchMove = (e: TouchEvent) => {
    if (
      !scrollable ||
      scrollable === document.documentElement ||
      scrollable === document.body
    ) {
      e.preventDefault();
      return;
    }

    let y = e.changedTouches[0].pageY;
    let scrollTop = scrollable.scrollTop;
    let bottom = scrollable.scrollHeight - scrollable.clientHeight;

    if (bottom === 0) {
      return;
    }

    if ((scrollTop <= 0 && y > lastY) || (scrollTop >= bottom && y < lastY)) {
      e.preventDefault();
    }

    lastY = y;
  };

  let onTouchEnd = (e: TouchEvent) => {
    let target = e.target as HTMLElement;

    if (isInput(target) && target !== document.activeElement) {
      e.preventDefault();

      target.style.transform = 'translateY(-2000px)';
      target.focus();
      requestAnimationFrame(() => {
        target.style.transform = '';
      });
    }
  };

  let onFocus = (e: FocusEvent) => {
    let target = e.target as HTMLElement;
    if (isInput(target)) {
      target.style.transform = 'translateY(-2000px)';
      requestAnimationFrame(() => {
        target.style.transform = '';

        if (visualViewport) {
          if (visualViewport.height < window.innerHeight) {
            requestAnimationFrame(() => {
              scrollIntoView(target);
            });
          } else {
            visualViewport.addEventListener(
              'resize',
              () => scrollIntoView(target),
              { once: true }
            );
          }
        }
      });
    }
  };

  let onWindowScroll = () => {
    window.scrollTo(0, 0);
  };

  let scrollX = window.pageXOffset;
  let scrollY = window.pageYOffset;

  let restoreStyles = chain(
    setStyle(
      document.documentElement,
      'paddingRight',
      `${window.innerWidth - document.documentElement.clientWidth}px`
    )
  );

  window.scrollTo(0, 0);

  let removeEvents = chain(
    addEvent(document, 'touchstart', onTouchStart, {
      passive: false,
      capture: true,
    }),
    addEvent(document, 'touchmove', onTouchMove, {
      passive: false,
      capture: true,
    }),
    addEvent(document, 'touchend', onTouchEnd, {
      passive: false,
      capture: true,
    }),
    addEvent(document, 'focus', onFocus, true),
    addEvent(window, 'scroll', onWindowScroll)
  );

  return () => {
    restoreStyles();
    removeEvents();
    window.scrollTo(scrollX, scrollY);
  };
}

function setStyle(
  element: HTMLElement,
  style: keyof React.CSSProperties,
  value: string
) {
  // @ts-ignore
  let cur = element.style[style];
  // @ts-ignore
  element.style[style] = value;

  return () => {
    // @ts-ignore
    element.style[style] = cur;
  };
}

function addEvent<K extends keyof GlobalEventHandlersEventMap>(
  target: EventTarget,
  event: K,
  handler: (this: Document, ev: GlobalEventHandlersEventMap[K]) => any,
  options?: boolean | AddEventListenerOptions
) {
  // @ts-ignore
  target.addEventListener(event, handler, options);

  return () => {
    // @ts-ignore
    target.removeEventListener(event, handler, options);
  };
}

function scrollIntoView(target: Element) {
  let root = document.scrollingElement || document.documentElement;
  while (target && target !== root) {
    let scrollable = getScrollParent(target);
    if (
      scrollable !== document.documentElement &&
      scrollable !== document.body &&
      scrollable !== target
    ) {
      let scrollableTop = scrollable.getBoundingClientRect().top;
      let targetTop = target.getBoundingClientRect().top;
      let targetBottom = target.getBoundingClientRect().bottom;
      const keyboardHeight =
        scrollable.getBoundingClientRect().bottom + KEYBOARD_BUFFER;

      if (targetBottom > keyboardHeight) {
        scrollable.scrollTop += targetTop - scrollableTop;
      }
    }

    // @ts-ignore
    target = scrollable.parentElement;
  }
}

export function isInput(target: Element) {
  return (
    (target instanceof HTMLInputElement &&
      !nonTextInputTypes.has(target.type)) ||
    target instanceof HTMLTextAreaElement ||
    (target instanceof HTMLElement && target.isContentEditable)
  );
}
