// The install command of Add cluster and Install probe, for Helm or for a GitOps tool (#59,
// docs/design/dialog-add-cluster-gitops.html). In GitOps the token goes only into Secrets created once on the
// cluster; the chart values for Git hold no token and set identity.manageSecrets=false.
import type { InstallResponse } from '../api/types';
import { DocLink } from './DocLinks';
import { CopyButton } from './kit';

export type InstallMode = 'helm' | 'gitops';

/** Helm or GitOps: a pill group; GitOps only when the server sent its variant. */
export function InstallModePills({ mode, onMode, install }: { mode: InstallMode; onMode: (m: InstallMode) => void; install: InstallResponse }) {
  if (!install.gitops) return null;
  return (
    <div className="pills" role="group" aria-label="Install with">
      <button type="button" className="pill" aria-pressed={mode === 'helm'} onClick={() => onMode('helm')}>
        Helm
      </button>
      <button type="button" className="pill" aria-pressed={mode === 'gitops'} onClick={() => onMode('gitops')}>
        GitOps (Argo CD, Flux)
      </button>
    </div>
  );
}

/** The two GitOps steps: the Secrets with the token, once, and the values for Git. */
export function GitOpsCommands({ gitops, tokenNote }: { gitops: NonNullable<InstallResponse['gitops']>; tokenNote: string }) {
  return (
    <>
      <div>
        <div className="spread" style={{ marginBottom: 6 }}>
          <span className="lbl" style={{ margin: 0 }}>
            1 · Run once on the cluster
          </span>
          <CopyButton text={gitops.secrets} label="Copy" className="btn sm" />
        </div>
        <pre className="code scroll" aria-label="Commands that create the identity Secrets" tabIndex={0}>
          {gitops.secrets}
        </pre>
        <div className="field-hint">{tokenNote}</div>
      </div>
      <div>
        <div className="spread" style={{ marginBottom: 6 }}>
          <span className="lbl" style={{ margin: 0 }}>
            2 · Chart values for your Git repository
          </span>
          <CopyButton text={gitops.values} label="Copy" className="btn sm" />
        </div>
        <pre className="code scroll" aria-label="Chart values" tabIndex={0}>
          {gitops.values}
        </pre>
        <div className="field-hint">
          Point an Argo CD Application or a Flux HelmRelease at the chart with these values. Do not sync with Replace or force: it would wipe the
          enrolled certificates. See <DocLink path="docs/install.md#install-with-argo-cd-or-flux">Install with Argo CD or Flux</DocLink>.
        </div>
      </div>
    </>
  );
}
