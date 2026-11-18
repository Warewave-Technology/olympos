# Runbook: Vault / OpenBao break-glass

Olympos cannot read secret values and every change goes through maker/checker. When that is not
enough (Olympos is down, the AppRole is broken, or an emergency value must be read), use Vault's own
break-glass, **outside Olympos**. Drift detection makes every such write visible afterwards.

## When

- Olympos is unavailable and a secret must be rotated now.
- The Olympos AppRole/policy was deleted or the secret_id expired (Vaults page shows *error*).
- A value must be **read** (Olympos never can).

## Procedure

1. Open an incident and name two people (operator + witness). Record the reason.
2. Get unseal/recovery key holders to generate a root token (Vault ≥ 1.x, OpenBao identical):
   ```bash
   vault operator generate-root -init                 # prints nonce + OTP
   vault operator generate-root -nonce=<nonce>        # each key holder, enter their key share
   vault operator generate-root -decode=<encoded> -otp=<otp>
   ```
   Reach the Vault through your normal admin path (bastion / `kubectl port-forward`), not through Olympos.
3. Do the minimum change. Prefer `vault kv patch` over `put`, so other keys stay untouched.
4. **Revoke the root token immediately**: `vault token revoke <root-token>` (or `vault token revoke -self`).
5. If the Olympos AppRole was the problem, re-run *Vaults › Configure* in Olympos (it recreates the
   policy and AppRole with a new root token used once, then discarded).
6. In Olympos, the next index refresh (≤ 10 min, or *Refresh now*) shows a **vault-drift**
   *Unmanaged change* finding and sends `vault.unmanaged_write`. Link the incident in the activity log
   comment of the follow-up change request, then resolve the finding by bringing the secret back under
   management (a reviewed change request that writes the intended value).
7. Review the Vault audit device log for the root token's accessor and attach it to the incident.

## Never

- Store a root token in Key Vault, Olympos, a ticket or chat.
- Grant a human a permanent policy with `read` on `<mount>/data/*` to "avoid break-glass next time".
- Disable drift detection to silence the finding.
