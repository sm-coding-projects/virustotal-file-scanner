/**
 * Accessibility helper functions and utilities
 */

// Announce content to screen readers
export const announceToScreenReader = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
  const announcement = document.createElement('div');
  announcement.setAttribute('aria-live', priority);
  announcement.setAttribute('aria-atomic', 'true');
  announcement.className = 'sr-only';
  announcement.textContent = message;
  
  document.body.appendChild(announcement);
  
  // Remove the announcement after a short delay
  setTimeout(() => {
    document.body.removeChild(announcement);
  }, 1000);
};

// Focus management utilities
export const focusElement = (selector: string) => {
  const element = document.querySelector(selector) as HTMLElement;
  if (element) {
    element.focus();
  }
};

export const trapFocus = (container: HTMLElement) => {
  const focusableElements = container.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  
  const firstFocusable = focusableElements[0] as HTMLElement;
  const lastFocusable = focusableElements[focusableElements.length - 1] as HTMLElement;
  
  const handleTabKey = (e: KeyboardEvent) => {
    if (e.key === 'Tab') {
      if (e.shiftKey) {
        if (document.activeElement === firstFocusable) {
          lastFocusable.focus();
          e.preventDefault();
        }
      } else {
        if (document.activeElement === lastFocusable) {
          firstFocusable.focus();
          e.preventDefault();
        }
      }
    }
  };
  
  container.addEventListener('keydown', handleTabKey);
  
  // Return cleanup function
  return () => {
    container.removeEventListener('keydown', handleTabKey);
  };
};

// Keyboard navigation helpers
export const handleKeyboardNavigation = (
  event: React.KeyboardEvent,
  onActivate: () => void,
  keys: string[] = ['Enter', ' ']
) => {
  if (keys.includes(event.key)) {
    event.preventDefault();
    onActivate();
  }
};

// ARIA helpers
export const generateId = (prefix: string = 'element'): string => {
  return `${prefix}-${Math.random().toString(36).substring(2, 11)}`;
};

export const setAriaExpanded = (element: HTMLElement, expanded: boolean) => {
  element.setAttribute('aria-expanded', expanded.toString());
};

// Color contrast checker (basic implementation)
export const checkColorContrast = (foreground: string, background: string): number => {
  // This is a simplified implementation
  // In a real application, you'd want a more robust color contrast checker
  const getLuminance = (color: string): number => {
    // Convert hex to RGB and calculate luminance
    const hex = color.replace('#', '');
    const r = parseInt(hex.substring(0, 2), 16) / 255;
    const g = parseInt(hex.substring(2, 4), 16) / 255;
    const b = parseInt(hex.substring(4, 6), 16) / 255;
    
    const sRGB = [r, g, b].map(c => {
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    
    return 0.2126 * sRGB[0] + 0.7152 * sRGB[1] + 0.0722 * sRGB[2];
  };
  
  const l1 = getLuminance(foreground);
  const l2 = getLuminance(background);
  
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  
  return (lighter + 0.05) / (darker + 0.05);
};

// Screen reader detection
export const isScreenReaderActive = (): boolean => {
  // This is a basic check - in reality, screen reader detection is complex
  return window.navigator.userAgent.includes('NVDA') || 
         window.navigator.userAgent.includes('JAWS') || 
         window.speechSynthesis !== undefined;
};

// Reduced motion preference
export const prefersReducedMotion = (): boolean => {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
};

// High contrast preference
export const prefersHighContrast = (): boolean => {
  return window.matchMedia('(prefers-contrast: high)').matches;
};

// Focus visible utility
export const addFocusVisiblePolyfill = () => {
  let hadKeyboardEvent = true;

  const detectKeyboard = (e: KeyboardEvent) => {
    if (e.metaKey || e.altKey || e.ctrlKey) {
      return;
    }
    hadKeyboardEvent = true;
  };

  const detectPointer = () => {
    hadKeyboardEvent = false;
  };

  const onFocus = (e: FocusEvent) => {
    const target = e.target as HTMLElement;
    if (hadKeyboardEvent || target.matches(':focus-visible')) {
      target.classList.add('focus-visible');
    }
  };

  const onBlur = (e: FocusEvent) => {
    const target = e.target as HTMLElement;
    target.classList.remove('focus-visible');
  };

  document.addEventListener('keydown', detectKeyboard, true);
  document.addEventListener('mousedown', detectPointer, true);
  document.addEventListener('pointerdown', detectPointer, true);
  document.addEventListener('touchstart', detectPointer, true);
  document.addEventListener('focus', onFocus, true);
  document.addEventListener('blur', onBlur, true);
};

// Accessibility audit helpers
export const auditAccessibility = () => {
  const issues: string[] = [];
  
  // Check for images without alt text
  const images = document.querySelectorAll('img:not([alt])');
  if (images.length > 0) {
    issues.push(`${images.length} images found without alt text`);
  }
  
  // Check for buttons without accessible names
  const buttons = document.querySelectorAll('button:not([aria-label]):not([aria-labelledby])');
  buttons.forEach(button => {
    if (!button.textContent?.trim()) {
      issues.push('Button found without accessible name');
    }
  });
  
  // Check for form inputs without labels
  const inputs = document.querySelectorAll('input:not([aria-label]):not([aria-labelledby])');
  inputs.forEach(input => {
    const id = input.getAttribute('id');
    if (!id || !document.querySelector(`label[for="${id}"]`)) {
      issues.push('Form input found without associated label');
    }
  });
  
  // Check for headings hierarchy
  const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6'));
  let previousLevel = 0;
  headings.forEach(heading => {
    const level = parseInt(heading.tagName.charAt(1));
    if (level > previousLevel + 1) {
      issues.push(`Heading level ${level} follows heading level ${previousLevel} - skipped levels`);
    }
    previousLevel = level;
  });
  
  return issues;
};