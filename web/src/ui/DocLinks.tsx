// Links for documentation paths ("docs/restore.md#postgresql") that the server
// and the UI mention in text: the docs live in the public repository.
import { Fragment } from 'react';

const DOCS_BASE = 'https://github.com/Warewave-Technology/olympos/blob/main/';
const DOC_PATH = /(docs\/[\w./-]+\.md(?:#[\w-]+)?)/g;

export function docUrl(path: string): string {
  return DOCS_BASE + path.replace(/^\/+/, '');
}

export function DocLink({ path, children }: { path: string; children?: React.ReactNode }) {
  return (
    <a className="mono" href={docUrl(path)} target="_blank" rel="noreferrer">
      {children ?? path}
    </a>
  );
}

/** Text with every docs/… path turned into a link. */
export function WithDocLinks({ text }: { text: string }) {
  const parts = text.split(DOC_PATH);
  return <>{parts.map((p, i) => (i % 2 === 1 ? <DocLink key={i} path={p} /> : <Fragment key={i}>{p}</Fragment>))}</>;
}
