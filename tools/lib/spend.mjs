// Spend-key intents: the K_s signature and one K_u half-signature per input. The two signatures cover
// different things on purpose: K_s binds the NEAR intent, K_u signs what Bitcoin will check.
import { makeTx, SEQUENCE_COSIGNED, sighash } from './btc.mjs';
import { toHex } from './bytes.mjs';
import { argBytes, intentDigest, signEd25519, signSecp, SPEND_TAG } from './intent.mjs';
import { spendKeys } from './keys.mjs';

function halfSigs({ secret, script, tx, inputs }) {
  return inputs.map((c, i) => toHex(signSecp(sighash(tx, i, script, c.value), secret)));
}

function utxoJson(c) {
  return { txid: c.txid, vout: c.vout, value: c.value };
}

export const signSpend = {
  propose({ seed, contract, vault, script, spk, inputs, to, amount, change, nonce, expiresAt, memo = null }) {
    const { ks, ku } = spendKeys(seed);
    const outputs = [{ value: amount, spk: to }];
    if (change !== null && change !== undefined) outputs.push({ value: change, spk });
    const tx = makeTx(inputs, SEQUENCE_COSIGNED, outputs);
    const digest = intentDigest({
      tag: SPEND_TAG, contract, vault, method: 'propose_btc',
      args: argBytes.propose_btc({ inputs, to, amount, change: change ?? null, memo }),
      expiresAt, nonce,
    });
    return {
      signer: toHex(ks.pub),
      args: {
        vault: toHex(vault),
        inputs: inputs.map(utxoJson),
        to: toHex(to),
        amount,
        change: change ?? null,
        half_sigs: halfSigs({ secret: ku.secret, script, tx, inputs }),
        nonce,
        expires_at: expiresAt,
        spend_sig: toHex(signEd25519(digest, ks.secret)),
        memo,
      },
    };
  },

  reclaim({ seed, contract, vault, script, spk, inputs, fee, nonce, expiresAt }) {
    if (inputs.length !== 1) throw new Error('reclaim takes exactly one outpoint');
    const { ks, ku } = spendKeys(seed);
    const [coin] = inputs;
    const tx = makeTx(inputs, SEQUENCE_COSIGNED, [{ value: coin.value - fee, spk }]);
    const digest = intentDigest({ tag: SPEND_TAG, contract, vault, method: 'reclaim', args: argBytes.reclaim({ inputs, fee }), expiresAt, nonce });
    return {
      signer: toHex(ks.pub),
      args: {
        vault: toHex(vault),
        utxo: utxoJson(coin),
        fee,
        half_sig: halfSigs({ secret: ku.secret, script, tx, inputs })[0],
        nonce,
        expires_at: expiresAt,
        spend_sig: toHex(signEd25519(digest, ks.secret)),
      },
    };
  },
};
