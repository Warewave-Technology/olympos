/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Dev-only fixture layer: "1" = mock every endpoint, "fallback" = real server first, mock on 404. */
  readonly VITE_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare const __APP_VERSION__: string;
