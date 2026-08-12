/**
 * Clinical line icons. Emoji are banned in production, so every glyph the
 * chart uses is drawn here.
 */

interface IconProps {
  size?: number;
  class?: string;
}

const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  'stroke-width': 2,
  'stroke-linecap': 'round' as const,
  'stroke-linejoin': 'round' as const,
  'aria-hidden': true,
  focusable: 'false',
});

export function PulseIcon({ size = 16, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M2 12h5l2-5 3 10 2.5-5H22" />
    </svg>
  );
}

export function ArrowIcon({ size = 16, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M4 12h15M13 6l6 6-6 6" />
    </svg>
  );
}

export function TickIcon({ size = 16, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M4 12.5l5 5L20 6.5" />
    </svg>
  );
}

export function CrossIcon({ size = 16, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

/** Used for the "you can be spoofed" verdict — an open envelope with a warning. */
export function AlertIcon({ size = 22, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M12 3l9 16H3l9-16z" />
      <path d="M12 9v5" />
      <path d="M12 17.5v.01" />
    </svg>
  );
}

export function ShieldIcon({ size = 22, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

export function StethoscopeIcon({ size = 16, class: className }: IconProps) {
  return (
    <svg {...base(size)} class={className}>
      <path d="M5 3v6a4 4 0 0 0 8 0V3" />
      <path d="M3 3h3M12 3h3" />
      <path d="M9 13v3a5 5 0 0 0 9.5 2" />
      <circle cx="19" cy="12" r="2.5" />
    </svg>
  );
}
