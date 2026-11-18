import type { AnchorHTMLAttributes } from 'react';
import { useRouter } from '@tanstack/react-router';

/** Link for server-provided SPA paths (e.g. dashboard attention links). */
export function SpaLink({ href, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  const router = useRouter();
  const internal = href.startsWith('/') && !href.startsWith('//');
  return (
    <a
      href={href}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || !internal || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        router.history.push(href);
      }}
      {...rest}
    />
  );
}
