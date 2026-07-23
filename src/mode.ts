/**
 * The action is explicitly disabled when the caller passes an empty `mode`
 * input. This matters for wrapper workflows that expose safer-runner as an
 * optional feature (e.g. `mode: ${{ inputs.safer-runner-mode }}` guarded by a
 * step-level `if:`): GitHub runs an action's pre/post hooks for every job that
 * references it, regardless of the step-level `if:`, so an empty mode is the
 * only signal through which a disabled configuration can be honoured before
 * any setup work happens.
 *
 * Deliberately checks the raw environment variable rather than
 * `core.getInput()`: `getInput` cannot distinguish "explicitly empty" from
 * "not set at all". On a real runner INPUT_MODE is always set (action.yaml's
 * default is materialised), but in tests or direct invocation an unset input
 * keeps the previous behaviour rather than silently disabling a security tool.
 */
export function isActionDisabled(): boolean {
  const raw = process.env['INPUT_MODE'];
  return raw !== undefined && raw.trim() === '';
}
