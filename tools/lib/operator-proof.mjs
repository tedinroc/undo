// The operator's proof that they hold the passkey a real instance is about to name in `new`. Step 10 of the go-live
// scripts makes a fresh nonce; the phone page signs this digest with the operator passkey; step 10 checks the assertion
// against the key before it deploys. The tag keeps this digest apart from every intent the contract checks, so the
// signature can do nothing on chain. Same bytes on the page and in Node.
import { utf8 } from './bytes.mjs';
import { sha256 } from './crypto.mjs';

export const OPERATOR_PROOF_TAG = 'undo-operator-proof-v1';
export const OPERATOR_PROOF_FORMAT = 'undo-operator-proof-v1';

/** `instance` is the contract account the deploy will create; `nonce` is step 10's fresh 32 bytes as hex. */
export const operatorProofDigest = ({ instance, nonce }) => sha256(utf8(`${OPERATOR_PROOF_TAG}\n${instance}\n${nonce}`));
