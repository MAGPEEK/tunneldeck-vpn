import type { ReactNode } from 'react';

/** A link to another site; it opens in a new tab without access to this page. */
export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}
