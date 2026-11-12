// The operator check, opened with #opproof=<nonce>&opfor=<instance>. Step 10 of the go-live scripts prints that link
// before it deploys a real instance. One tap: the operator passkey signs a check for that instance and that nonce, and
// nothing else, and the page shows the signed check to copy back. It needs no contract and no relay, and claims
// nothing: step 10 compares the signature with the key it is about to deploy, and its own nonce.
import { credentialToFragment } from '/site/lib/index.mjs';
import { OPERATOR_PROOF_FORMAT, operatorProofDigest } from '/tools/lib/operator-proof.mjs';
import { h, setState, show } from './kit.mjs';
import { askAssertion, PasskeyFailed } from './passkey-ask.mjs';
import { problemWords } from './sense.mjs';

export function runOperatorCheck(ctx, { nonce, instance }) {
  const draw = (note = null) => {
    setState('op_check');
    show(
      h('p', { class: 'step' }, 'Operator check, before a deploy'),
      h('p', { class: 'say' }, `This signs one check for ${instance}, and nothing else. Pick the passkey labelled operator.`),
      h('p', { class: 'small' }, 'The deploy compares this signature with the operator key it is about to use, and stops if they differ.'),
      note ? h('p', { class: 'notice warn', id: 'why' }, note) : null,
      h('div', { class: 'grow' }),
      ctx.credentials ? h('button', { class: 'go', type: 'button', id: 'op-sign', onclick: tap }, 'Sign the check') : h('p', { class: 'say', id: 'why' }, problemWords('no_webauthn')),
    );
  };
  const tap = () => {
    const digest = operatorProofDigest({ instance, nonce });
    const asking = askAssertion(ctx, { digest, credentialId: null });
    setState('op_wait');
    show(h('p', { class: 'say big' }, 'Waiting for your passkey'), h('p', { class: 'line dim' }, 'Pick the one labelled operator.'));
    asking.then(({ assertion }) => signed(assertion), (err) => draw(err instanceof PasskeyFailed && (err.kind === 'dismissed' || err.kind === 'blocked') ? 'The passkey did not sign.' : `The passkey call failed: ${err.message}`));
  };
  const signed = (assertion) => {
    const text = JSON.stringify({ format: OPERATOR_PROOF_FORMAT, instance, nonce, credential_id: credentialToFragment(assertion.credentialId), ...assertion.args });
    setState('op_signed');
    const copy = async () => {
      try {
        await navigator.clipboard.writeText(text);
        document.getElementById('op-copy').textContent = 'Copied';
      } catch {
        document.getElementById('op-proof').focus();
      }
    };
    show(
      h('p', { class: 'say big', id: 'done' }, 'Signed. Copy this and send it to whoever runs the deploy.'),
      h('button', { class: 'go', type: 'button', id: 'op-copy', onclick: copy }, 'Copy the signed check'),
      h('pre', { class: 'report', id: 'op-proof', tabindex: '0' }, text),
    );
  };
  draw();
}
