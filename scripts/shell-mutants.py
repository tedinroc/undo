#!/usr/bin/env python3
"""Breaks one rule of the contract shell at a time and expects a sandbox test to notice.

undo-core has its own mutation check. This one covers what only the shell does: signature checks,
WebAuthn rules, the signer callbacks and storage credit. It works on a copy of the tree, so a crash
leaves the repo alone, and it rebuilds the wasm for each mutant.

    shell-mutants.py [PROTOCOL] [NAME]    default 88, all mutants; NAME narrows to names containing it
    shell-mutants.py --check              only that each mutant's text is in the source exactly once

UNDO_MUTANTS_FROM and UNDO_MUTANTS_UNTIL run a stretch of the list, by mutant name.

Needs the environment scripts/protocol-check.sh needs.
"""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LIB = "contracts/undo/src/lib.rs"
AUTH = "contracts/undo/src/auth.rs"
STORE = "contracts/undo/src/storage.rs"
BTC = "contracts/undo/src/btc.rs"
API = "contracts/undo/src/api.rs"

# (name, file, old text, new text, test files, name filter)
MUTANTS = [
    ("propose skips half-signatures", LIB, 'require_half_sigs(&script, vault, &inputs, &outputs, &half_sigs);', '', "shell", "half_signatures"),
    ("reclaim skips the half-signature", LIB, 'require_half_sigs(&script, vault, &[input], &outputs, core::slice::from_ref(&half_sig));', '', "review_contract", "f8_reclaim"),
    ("propose skips K_s", LIB, 'auth::require_ed25519(&digest, &spend_sig, &loaded.row.vault.k_s, "K_s");\n        let vault = &loaded.row.vault;\n        let script = btc::script_of(vault);\n        require_half_sigs(&script, vault, &inputs', 'let vault = &loaded.row.vault;\n        let script = btc::script_of(vault);\n        require_half_sigs(&script, vault, &inputs', "shell", "spend_signatures"),
    ("creation skips K_u proof", LIB, 'auth::require_secp(&digest, &args.pop_u, &args.k_u.0, "K_u");', '', "review_contract", "f1_create"),
    ("creation skips K_e proof", LIB, 'auth::require_secp(&digest, &args.pop_e, &args.k_e_intent.0, "K_e");', '', "review_contract", "f1_create"),
    ("creation skips K_s proof", LIB, 'auth::require_ed25519(&digest, &args.pop_s, &k_s, "K_s");', '', "review_contract", "f1_create"),
    ("creation ignores the operator rule", LIB, 'require!(!cfg.restrict_create || env::predecessor_account_id() == cfg.operator, "only the operator creates vaults here");', '', "shell", "restricted"),
    ("creation ignores expiry", LIB, 'require!(now() <= args.expires_at, "creation intent expired");', '', "shell", "creation_intent"),
    ("wrong K_m activates", LIB, 'let activated = derived.is_some_and(|key| loaded.row.vault.activate(&key).is_ok());', 'let _ = derived; let k_m = loaded.row.vault.k_m.clone(); let activated = loaded.row.vault.activate(&k_m).is_ok();', "review_contract", "f1_create"),
    ("on_signed trusts its payload argument", LIB, 'let outcome = loaded.row.vault.on_signed(request, attempt, index, payload, recomputed, signature, now());', 'let outcome = loaded.row.vault.on_signed(request, attempt, index, payload, payload, signature, now());', "review_contract", "f8_callback"),
    ("on_signed stores any key's answer", LIB, 'if !auth::secp_signed_by(digest, &sig, k_m) {\n        return None;\n    }', 'let _ = (digest, k_m);', "shell", "wrong_signer"),
    ("cold cancel takes the leaf key", LIB, '"cancel", &request, expires_at, None);\n                auth::require_secp(&digest, &signature, &loaded.row.vault.k_e_intent, "K_e");', '"cancel", &request, expires_at, None);\n                auth::require_secp(&digest, &signature, &loaded.row.vault.k_e_leaf, "K_e");', "shell", "cold_key"),
    ("execute takes any sign gas", LIB, 'require!((cfg.sign_tgas..=MAX_SIGN_TGAS).contains(&sign_tgas), "sign gas out of range");', '', "review_contract", "f13"),
    ("execute has no deposit cap", LIB, 'require!(per_sign <= MAX_SIGN_DEPOSIT, "deposit per sign above the cap");', '', "review_contract", "f13"),
    ("execute signs as the wrong path", LIB, 'let path = format!("{PATH_PREFIX}{}", hex::encode(id));', 'let path = format!("{PATH_PREFIX}other");', "shell", "execute_asks"),
    ("view hides a dead request's coin", LIB, 'OutpointState::Pending(r) if !v.is_live(r, now()) => ("Free", None),', '', "review_contract", "f5_thief"),
    ("webauthn skips UV", AUTH, 'require!(flags & FLAG_UV != 0, "webauthn: user not verified");', '', "review_contract", "f17"),
    ("webauthn skips UP", AUTH, 'require!(flags & FLAG_UP != 0, "webauthn: user not present");', '', "review_contract", "f17"),
    ("webauthn skips the type", AUTH, 'require!(client.kind == "webauthn.get", "webauthn: wrong type");', '', "review_contract", "f17"),
    ("webauthn skips the challenge", AUTH, 'require!(client.challenge == base64url(digest), "webauthn: wrong challenge");', '', "review_contract", "f17"),
    ("webauthn allows cross origin", AUTH, 'require!(!client.cross_origin, "webauthn: cross origin");', '', "review_contract", "f17"),
    ("webauthn allows any origin", AUTH, 'require!(origins.contains(&client.origin), "webauthn: origin not allowed");', '', "review_contract", "f17"),
    ("webauthn allows any rp id", AUTH, 'require!(&auth[..32] == rp_id_hash, "webauthn: wrong rp id");', '', "review_contract", "f17"),
    ("webauthn skips the signature", AUTH, 'require!(env::p256_verify(&sig, &prehash, &key), "webauthn: bad signature");', 'let _ = (sig, prehash, key);', "review_contract", "f17"),
    ("backup flags not read", AUTH, 'backup_eligible: flags & FLAG_BE != 0', 'backup_eligible: false', "review_contract", "f17"),
    ("no reservation", STORE, 'fn request_reserve(request: &Request) -> u64 {', 'fn request_reserve(request: &Request) -> u64 {\n    if request.inputs.len() < 99 { return 0; }', "review_contract", "f11_on_signed"),
    ("rotate skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "cancel_all_and_rotate", &new_key, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "review1", "rotate_needs"),
    ("raise_fee_cap skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "raise_fee_cap", &(request, cap), expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "review1", "raise_fee_cap_needs"),
    ("reclaim skips K_s", LIB, 'let digest = intent_digest(SPEND_TAG, &id, "reclaim", &args, expires_at, Some(nonce));\n        auth::require_ed25519(&digest, &spend_sig, &loaded.row.vault.k_s, "K_s");', 'let _ = (&args, &spend_sig);', "review1", "reclaim_needs"),
    ("on_derived deletes an active vault", LIB, 'if loaded.row.vault.active {\n            return;\n        }\n        let derived', 'let derived', "review1", "racing_activate"),
    ("on_derived is public", LIB, '#[private]\n    pub fn on_derived', 'pub fn on_derived', "review1", "second_on_derived"),
    ("on_derived deletes an active vault, direct delivery", LIB, 'if loaded.row.vault.active {\n            return;\n        }\n        let derived', 'let derived', "review1", "second_on_derived"),
    ("creation skips the leaf proof", LIB, 'auth::require_secp(&auth::leaf_pop_digest(&digest), &args.pop_leaf, &args.k_e_leaf.0, "K_e leaf");', '', "review1", "escape_key"),
    ("the leaf proof has no domain tag", LIB, 'auth::require_secp(&auth::leaf_pop_digest(&digest), &args.pop_leaf, &args.k_e_leaf.0, "K_e leaf");', 'auth::require_secp(&digest, &args.pop_leaf, &args.k_e_leaf.0, "K_e leaf");', "review1", "escape_key"),
    ("the leaf proof takes the intent key", LIB, 'auth::require_secp(&auth::leaf_pop_digest(&digest), &args.pop_leaf, &args.k_e_leaf.0, "K_e leaf");', 'auth::require_secp(&digest, &args.pop_leaf, &args.k_e_intent.0, "K_e leaf");', "review1", "escape_key"),
    ("freeze skips K_e", LIB, 'let caller = cold_caller(&id, &loaded, "freeze", &until, expires_at, Some(nonce), &signature);', 'let _ = &signature; let caller = Caller::Cold(loaded.row.vault.k_e_intent.clone());', "review1", "freeze_and_unfreeze"),
    ("unfreeze skips K_e", LIB, 'let caller = cold_caller(&id, &loaded, "unfreeze", &(), expires_at, Some(nonce), &signature);', 'let _ = &signature; let caller = Caller::Cold(loaded.row.vault.k_e_intent.clone());', "review1", "freeze_and_unfreeze"),
    ("veto skips K_e", LIB, 'let caller = cold_caller(&id, &loaded, "veto_grant", &grant, expires_at, Some(nonce), &signature);', 'let _ = &signature; let caller = Caller::Cold(loaded.row.vault.k_e_intent.clone());', "review1", "veto_grant"),
    ("cold intents take the leaf key", LIB, 'auth::require_secp(&digest, signature, &loaded.row.vault.k_e_intent, "K_e");', 'auth::require_secp(&digest, signature, &loaded.row.vault.k_e_leaf, "K_e");', "review1", "veto_grant"),
    ("recover_begin skips K_e", LIB, 'auth::require_secp(&digest, &signature, &loaded.row.vault.k_e_intent, "K_e");\n        let flags', 'let _ = &signature;\n        let flags', "review1", "recovery_needs"),
    ("recover_begin skips the new passkey's proof", LIB, 'let flags = auth::require_webauthn(&pop_p, &digest, &new_passkey.pubkey.0, &rp_id_hash, &self.config.origins);', 'let _ = &pop_p; let flags = auth::AssertionFlags { backup_eligible: false, backup_state: false };', "review1", "recovery_needs"),
    ("recover_cancel skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "recover_cancel", &(), expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "review1", "recovery_needs"),
    ("propose reads no ledger, so pins are forgotten", LIB, '        loaded.load_outpoints(&id, &inputs.iter().map(|i| i.outpoint).collect::<Vec<_>>());\n        let args = (spend_args', '        let args = (spend_args', "review1", "pins_survive"),
    ("reclaim leaves the old request", LIB, 'loaded.load_request(&id, owner);', 'let _ = owner;', "review_contract", "f0_false_amount"),
    ("on_signed leaves the ledger behind", LIB, 'if completes {\n            loaded.load_inputs(&id, request);\n        }', 'let _ = completes;', "review1", "prune_returns"),
    ("prune keeps no transaction", LIB, 'env::log_str(&format!("undo:pruned request={request} tx={}", tx.map(hex::encode).unwrap_or_default()));', 'let _ = tx;', "review1", "prune_returns"),
    ("prune pays no bytes back", STORE, 'for request in self.raw_requests.keys() {\n            if !requests.contains_key(request) {\n                env::storage_remove(&request_key(id, *request));\n            }\n        }', '', "review1", "prune_returns"),
    ("a dead request's coins stay held", STORE, 'if !loaded.row.vault.is_live(request, now) {\n            loaded.load_inputs(id, request);\n        }', 'let _ = now;', "review1", "dead_requests"),
    ("the row's reservation goes unpaid", STORE, 'if vault.recovery.is_none() {\n        bytes += RECOVERY_BYTES;\n    }', '', "review1", "cold_methods_need_no_credit"),
    # The third review: the chain rule on the wasm.
    ("execute reads no child entry, so a backwards chain passes", STORE, 'self.load_outpoints(id, &children);\n        txid', 'let _ = children;\n        txid', "review2", "backwards"),
    ("the txid is not the transaction's", STORE, 'let txid = crate::btc::txid_of(&vault.vault_spk, stored);', 'let txid = { let _ = crate::btc::txid_of(&vault.vault_spk, stored); [7u8; 32] };', "review2", "own_index"),
    ("the txid skips the outputs", BTC, 'tx_of(vault_spk, &request.inputs, &request.outputs).txid::<HostSha>().0', '{ let mut t = tx_of(vault_spk, &request.inputs, &request.outputs); t.outputs.truncate(1); t.txid::<HostSha>().0 }', "review2", "own_index"),
    ("view hides the birth time", LIB, 'born_at: v.ledger.get(&point).and_then(|e| e.born_at) }', 'born_at: None }', "review2", "own_index"),
    # The third review: the reservation rules, each constant both ways.
    ("reserve: override bytes stay reserved after use", STORE, 'if request.fee_override.is_none() { FEE_OVERRIDE_BYTES } else { 0 }', 'FEE_OVERRIDE_BYTES', "review2", "raise_fee_cap_at_zero"),
    ("reserve: override not reserved", STORE, 'const FEE_OVERRIDE_BYTES: u64 = 8;', 'const FEE_OVERRIDE_BYTES: u64 = 0;', "review2", "raise_fee_cap_at_zero"),
    ("reserve: signature too small", STORE, 'const SIG_BYTES: u64 = 4 + 64;', 'const SIG_BYTES: u64 = 64;', "review2", "request_lives"),
    ("reserve: signature too large", STORE, 'const SIG_BYTES: u64 = 4 + 64;', 'const SIG_BYTES: u64 = 8 + 64;', "review2", "request_lives"),
    ("reserve: in-flight too small", STORE, 'const IN_FLIGHT_BYTES: u64 = 8;', 'const IN_FLIGHT_BYTES: u64 = 0;', "review2", "request_lives"),
    ("reserve: pin too small", STORE, 'const PIN_BYTES: u64 = 16;', 'const PIN_BYTES: u64 = 8;', "review2", "request_lives"),
    ("reserve: pin too large", STORE, 'const PIN_BYTES: u64 = 16;', 'const PIN_BYTES: u64 = 24;', "review2", "request_lives"),
    ("reserve: first execute too small", STORE, 'const FIRST_EXECUTE_BYTES: u64 = 8 + 16;', 'const FIRST_EXECUTE_BYTES: u64 = 8;', "review2", "request_lives"),
    ("reserve: first execute too large", STORE, 'const FIRST_EXECUTE_BYTES: u64 = 8 + 16;', 'const FIRST_EXECUTE_BYTES: u64 = 16 + 16;', "review2", "request_lives"),
    ("reserve: signed_at too small", STORE, 'const SIGNED_AT_BYTES: u64 = 8;', 'const SIGNED_AT_BYTES: u64 = 0;', "review2", "request_lives"),
    ("reserve: child entry too small", STORE, 'const CHILD_ENTRY_BYTES: u64 = 40 + 69 + 1 + 1 + 1 + 9;', 'const CHILD_ENTRY_BYTES: u64 = 69;', "review2", "request_lives"),
    ("reserve: child entry too large", STORE, 'const CHILD_ENTRY_BYTES: u64 = 40 + 69 + 1 + 1 + 1 + 9;', 'const CHILD_ENTRY_BYTES: u64 = 40 + 69 + 1 + 1 + 1 + 17;', "review2", "request_lives"),
    ("reserve: a signing request keeps nothing", STORE, 'missing * SIG_BYTES\n                + missing.saturating_sub(request.in_flight.len() as u64) * IN_FLIGHT_BYTES\n                + SIGNED_AT_BYTES', '0', "review2", "request_lives"),
    ("reserve: retry slots not kept", STORE, '                + missing.saturating_sub(request.in_flight.len() as u64) * IN_FLIGHT_BYTES\n', '', "review2", "request_lives"),
    ("reserve: rotation too small", STORE, 'const ROTATE_GRANT_BYTES: u64 = 8 + 1 + 32 + 16;', 'const ROTATE_GRANT_BYTES: u64 = 32;', "review2", "panic_button"),
    ("reserve: rotation too large", STORE, 'const ROTATE_GRANT_BYTES: u64 = 8 + 1 + 32 + 16;', 'const ROTATE_GRANT_BYTES: u64 = 16 + 1 + 32 + 16;', "review2", "panic_button"),
    ("reserve: freeze too small", STORE, 'const FREEZE_BYTES: u64 = 8;', 'const FREEZE_BYTES: u64 = 0;', "review2", "panic_button"),
    ("reserve: freeze too large", STORE, 'const FREEZE_BYTES: u64 = 8;', 'const FREEZE_BYTES: u64 = 16;', "review2", "panic_button"),
    ("reserve: recovery too small", STORE, 'const RECOVERY_BYTES: u64 = 4 + 33 + 32 + 2 + 16;', 'const RECOVERY_BYTES: u64 = 33 + 32 + 2 + 16;', "review2", "panic_button"),
    ("reserve: recovery too large", STORE, 'const RECOVERY_BYTES: u64 = 4 + 33 + 32 + 2 + 16;', 'const RECOVERY_BYTES: u64 = 8 + 33 + 32 + 2 + 16;', "review2", "panic_button"),
    ("reserve: a held rotation grant still counts", STORE, 'if !vault.grants.iter().any(|g| matches!(g.kind, GrantKind::RotateSpend { .. })) {\n        bytes += ROTATE_GRANT_BYTES;\n    }', 'bytes += ROTATE_GRANT_BYTES;', "review2", "panic_button"),
    ("reserve: a held freeze still counts", STORE, 'if vault.frozen_until.is_none() {\n        bytes += FREEZE_BYTES;\n    }', 'bytes += FREEZE_BYTES;', "review2", "panic_button"),
    ("reserve: a held recovery still counts", STORE, 'if vault.recovery.is_none() {\n        bytes += RECOVERY_BYTES;\n    }', 'bytes += RECOVERY_BYTES;', "review2", "panic_button"),
    ("reclaim may run short", LIB, '.reclaim(&caller, Intent { nonce, expires_at }, input.outpoint, input.value, fee, half_sig.0, now())\n            .unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Refuse);', '.reclaim(&caller, Intent { nonce, expires_at }, input.outpoint, input.value, fee, half_sig.0, now())\n            .unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Reserved);', "review2", "reclaim_is_refused"),
    ("propose may run short", LIB, '.propose(\n                &caller,\n                Intent { nonce, expires_at },\n                ProposeArgs { inputs, outputs, half_sigs: half_sigs.into_iter().map(|s| s.0).collect(), memo },\n                now(),\n            )\n            .unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Refuse);', '.propose(\n                &caller,\n                Intent { nonce, expires_at },\n                ProposeArgs { inputs, outputs, half_sigs: half_sigs.into_iter().map(|s| s.0).collect(), memo },\n                now(),\n            )\n            .unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Reserved);', "shell", "rotation_needs"),
    ("a refund skips what was reserved", STORE, 'let freed = before.saturating_sub(env::storage_usage()) + loaded.row.reserved;', 'let freed = before.saturating_sub(env::storage_usage());', "review2", "whole_deposit"),
    ("a refund skips the credit", STORE, 'loaded.row.credit.saturating_add(cost(freed))', 'cost(freed)', "review2", "whole_deposit"),
    ("a refused vault keeps its deposit", LIB, 'if refund > 0 {\n                let promise', 'if false {\n                let promise', "review_contract", "f1_create"),
    ("a top-up is lost", LIB, 'loaded.row.credit = loaded.row.credit.saturating_add(env::attached_deposit().as_yoctonear());', '', "shell", "rotation_needs"),
    # The review of 10/31: instance rules.
    ("the mainnet preset may stay open", LIB, 'require!(preset != Preset::MainnetProof || restrict_create, "the mainnet preset needs restrict_create");', '', "review3", "instance_rules"),
    ("preset and network need not match", LIB, 'require!((preset == Preset::MainnetProof) == (chain == undo_btc::Network::Mainnet), "preset and network do not match");', 'let _ = chain;', "review3", "instance_rules"),
    ("the signer's answer may be any size", LIB, 'const MAX_SIGNER_RESPONSE: usize = 1024;', 'const MAX_SIGNER_RESPONSE: usize = 1_000_000;', "review3", "oversized_signer"),
    # Section 11: the last methods.
    ("add_destination skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "add_destination", &script.0, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "surface", "add_destination_negatives"),
    ("add_destination may run short", LIB, 'loaded.row.vault.add_destination(&caller, Intent { nonce, expires_at }, script.0, now()).unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Refuse);', 'loaded.row.vault.add_destination(&caller, Intent { nonce, expires_at }, script.0, now()).unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Reserved);', "surface", "need_no_credit"),
    ("remove_destination skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "remove_destination", &script.0, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "surface", "remove_destination_lands"),
    ("remove_destination reads no ledger", LIB, 'if loaded.row.vault.requests.get(&request).is_some_and(|r| r.outputs.dest_script == script.0) {\n                loaded.load_inputs(&id, request);\n            }', 'let _ = request;', "surface", "remove_destination_lands"),
    ("set_policy skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "set_policy", &policy, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "surface", "set_policy_is_bounded"),
    ("a loosening may run short", LIB, 'PolicyOutcome::Grant(grant) => {\n                loaded.commit(&id, Short::Refuse);', 'PolicyOutcome::Grant(grant) => {\n                loaded.commit(&id, Short::Reserved);', "surface", "loosening_with_no_credit"),
    ("set_guard skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "set_guard", &guard, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "surface", "set_guard_waits"),
    ("clear_hold skips the passkey", LIB, 'let caller = self.passkey_caller(&id, &loaded, "clear_hold", &request, expires_at, Some(nonce), &assertion);', 'let _ = &assertion; let caller = Caller::Passkey(loaded.row.vault.passkey.pubkey.clone());', "surface", "clear_hold"),
    ("clear_hold reads no request", LIB, 'loaded.fetch_request(&id, request);\n        let caller = self.passkey_caller(&id, &loaded, "clear_hold"', 'let caller = self.passkey_caller(&id, &loaded, "clear_hold"', "surface", "clear_hold"),
    ("heartbeat from anyone", LIB, 'let caller = Caller::Guard(env::predecessor_account_id().to_string());\n        loaded.row.vault.heartbeat(', 'let caller = Caller::Guard(loaded.row.vault.guard.clone().unwrap_or_default());\n        loaded.row.vault.heartbeat(', "surface", "heartbeat_keeps"),
    ("a first heartbeat may run short", LIB, 'loaded.row.vault.heartbeat(&caller, now()).unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Refuse);', 'loaded.row.vault.heartbeat(&caller, now()).unwrap_or_else(|e| fail(e));\n        loaded.commit(&id, Short::Reserved);', "surface", "first_heartbeat"),
    ("assess from anyone", LIB, 'let caller = Caller::Guard(env::predecessor_account_id().to_string());\n        loaded.row.vault.assess(', 'let caller = Caller::Guard(loaded.row.vault.guard.clone().unwrap_or_default());\n        loaded.row.vault.assess(', "surface", "assess_refuses"),
    ("assess skips the signature", LIB, 'require!(signed, "not signed by a registered signer for this model");', 'let _ = signed;', "surface", "assess_refuses"),
    ("assess takes any model's signer", LIB, '.any(|(model, key)| *model == cfg.guard_model && env::ed25519_verify(&sig, text.as_bytes(), key));', '.any(|(_, key)| env::ed25519_verify(&sig, text.as_bytes(), key));', "surface", "model_signers"),
    ("assess takes a response of any size", LIB, 'require!(response_bytes.0.len() <= MAX_GUARD_RESPONSE, "response too large");', '', "surface", "assess_refuses"),
    ("assess takes any reason", LIB, '.unwrap_or_else(|| env::panic_str("answer has an unknown reason"));', '.unwrap_or(Reason::Other);', "surface", "assess_refuses"),
    ("assess signs over the wrong text", AUTH, 'format!("{model}:{}:{}", hex::encode(env::sha256_array(request)), hex::encode(env::sha256_array(response)))', 'format!("{}:{}", hex::encode(env::sha256_array(request)), hex::encode(env::sha256_array(response)))', "surface", "assess_checks"),
    ("assess takes a request's bytes on trust", LIB, 'let text = auth::model_signed_text(&cfg.guard_model, body.as_bytes(), &response_bytes.0);', 'let _ = &body; let text = auth::model_signed_text(&cfg.guard_model, b"", &response_bytes.0);', "surface", "assess_checks"),
    ("an answer may carry other fields", API, '#[serde(crate = "near_sdk::serde", deny_unknown_fields)]', '#[serde(crate = "near_sdk::serde")]', "surface", "assess_refuses"),
    ("anyone adds a model signer", LIB, 'self.require_operator();\n        require!(self.config.model_signers.len() < MAX_MODEL_SIGNERS, "too many model signers");', 'require!(self.config.model_signers.len() < MAX_MODEL_SIGNERS, "too many model signers");', "surface", "model_signers"),
    ("anyone switches the model", LIB, 'self.require_operator();\n        require!(self.config.model_signers.iter().any(', 'require!(self.config.model_signers.iter().any(', "surface", "model_signers"),
    ("the model may have no signer", LIB, 'require!(self.config.model_signers.iter().any(|(m, _)| *m == model), "no signer for that model");', '', "surface", "model_signers"),
    ("the memo is not signed", LIB, 'outputs.dest_value, outputs.change_value, &memo);', 'outputs.dest_value, outputs.change_value, &None::<String>);', "surface", "memo_is_bound"),
    ("anyone proposes an upgrade", LIB, 'self.require_operator();\n        let hash: [u8; 32]', 'let hash: [u8; 32]', "surface", "upgrade_authority"),
    ("upgrade_cancel skips the passkey", LIB, 'auth::require_webauthn(&assertion, &digest, &cfg.operator_passkey, &cfg.operator_rp_id_hash, &cfg.origins);', 'let _ = (&assertion, &digest, cfg);', "surface", "upgrade_authority"),
    ("upgrade_cancel ignores its expiry", LIB, 'require!(now() <= expires_at, "intent expired");', '', "surface", "upgrade_authority"),
    ("upgrade_cancel does not name the proposal", LIB, 'let args = (pending.code_hash, pending.proposed_at);', 'let args = pending.code_hash;', "surface", "upgrade_authority"),
    ("upgrade_apply takes any code", LIB, 'self.upgrade.take_for_apply(env::sha256_array(&code), now())', 'self.upgrade.take_for_apply(self.upgrade.pending.map_or([0; 32], |p| p.code_hash), now())', "surface", "lands_after_the_wait"),
    ("upgrade_apply deploys nothing", LIB, 'env::promise_batch_action_deploy_contract(promise, &code);\n', '', "surface", "lands_after_the_wait"),
    ("upgrade_apply runs no migrate", LIB, 'env::promise_batch_action_function_call(promise, "migrate", &[], NearToken::from_yoctonear(0), Gas::from_tgas(MIGRATE_TGAS));\n', '', "surface", "without_a_migrate"),
    ("migrate is public", LIB, '#[private]\n    pub fn migrate', 'pub fn migrate', "surface", "migrate_is_private"),
    ("the operator passkey need not be a key", LIB, 'require!(operator_passkey.pubkey.0.len() == 33, "the operator passkey must be a compressed P-256 key");', '', "review3", "instance_rules"),
    ("stats: a cancel does not count", LIB, 'self.note_completed(&mut loaded);\n        loaded.commit(&id, Short::Reserved);\n        env::log_str(&format!("undo:cancelled', 'loaded.commit(&id, Short::Reserved);\n        env::log_str(&format!("undo:cancelled', "surface", "stats_counts"),
    ("stats: a spend does not count", LIB, 'if outcome == (SignedOutcome::Stored { complete: true }) {\n            self.note_completed(&mut loaded);\n        }', '', "surface", "stats_counts"),
    ("stats: every vault counts its passkey again", LIB, 'if loaded.row.vault.mark_completed() && loaded.count_passkey() {', 'if loaded.row.vault.mark_completed() {', "surface", "stats_counts"),
    ("stats: a refused vault stays counted", LIB, 'self.stats.vaults_created = self.stats.vaults_created.saturating_sub(1);\n', '', "surface", "stats_counts"),
    ("stats: anyone can exclude", LIB, 'self.require_operator();\n        require!(self.config.stats_excluded.len()', 'require!(self.config.stats_excluded.len()', "surface", "stats_counts"),
    ("stats: an excluded passkey still counts", LIB, 'counted: self.stats.passkeys_completed.saturating_sub(excluded_that_completed),', 'counted: self.stats.passkeys_completed,', "surface", "stats_counts"),
    # What the page reads in the film.
    ("the view hides a request's epoch", API, 'epoch: r.epoch,', 'epoch: 0,', "surface", "film_the_phones"),
    ("the view hides the vault's epoch", LIB, 'spend_epoch: v.spend_epoch,', 'spend_epoch: 0,', "surface", "film_the_phones"),
    ("the view hides a hold", API, 'hold_active: r.hold_active,', 'hold_active: false,', "surface", "film_a_hold"),
    ("the view hides the reason", API, 'assess_reason: r.assess_reason.name().to_string(),', 'assess_reason: "none".to_string(),', "surface", "film_a_hold"),
    ("the view hides the suspension", LIB, 'k_s_suspended: v.k_s_suspended,', 'k_s_suspended: false,', "surface", "film_the_phones"),
    ("status leaves the vault out", LIB, 'lines.extend(vault_lines);\n', 'let _ = vault_lines;\n', "surface", "status_is_plain"),
    ("status hides a pending upgrade", LIB, 'Some(p) => {\n                ok = false;\n                lines.push(format!(\n                    "upgrade pending', 'Some(p) => {\n                lines.push(format!(\n                    "upgrade pending', "surface", "lands_after_the_wait"),
    ("reserve: count entry too small", STORE, 'const COUNT_ENTRY_BYTES: u64 = 40 + 33 + 1;', 'const COUNT_ENTRY_BYTES: u64 = 33;', "surface", "cancel_at_zero_credit"),
    ("reserve: count entry too large", STORE, 'const COUNT_ENTRY_BYTES: u64 = 40 + 33 + 1;', 'const COUNT_ENTRY_BYTES: u64 = 40 + 33 + 9;', "surface", "cancel_at_zero_credit"),
    ("the count's bytes go unsettled", STORE, 'let usage_before = env::storage_usage() - self.written_early;', 'let usage_before = env::storage_usage();', "surface", "cancel_at_zero_credit"),
    # The third review: creation.
    ("creation does not bind K_m", AUTH, 'let bytes = (CREATE_TAG, env::current_account_id(), vault, k_m, rp_id_hash, guard, policy, expires_at);', 'let _ = k_m; let bytes = (CREATE_TAG, env::current_account_id(), vault, rp_id_hash, guard, policy, expires_at);', "shell", "create_vault_matches"),
    ("the vault id can be recreated", LIB, 'require!(!storage::exists(&id), "vault exists");', '', "review_contract", "f22"),
    ("activate works on an active vault", LIB, 'require!(!storage::load_row(&id).row.vault.active, "already active");', '', "shell", "create_vault_matches"),
    ("activate never asks", LIB, 'require!(!storage::load_row(&id).row.vault.active, "already active");\n        self.ask_signer_for_key(&id);', 'require!(!storage::load_row(&id).row.vault.active, "already active");', "review1", "racing_activate"),
    ("anyone may initialise", LIB, '#[init]\n    #[private]\n    pub fn new', '#[init]\n    pub fn new', "review2", "only_the_account"),
    ("any network is accepted", LIB, 'undo_btc::Network::from_name(&network).unwrap_or_else(|_| env::panic_str("unknown network"))', 'undo_btc::Network::from_name(&network).unwrap_or(undo_btc::Network::Regtest)', "review2", "only_the_account"),
    ("on_signed is public", LIB, '#[private]\n    pub fn on_signed', 'pub fn on_signed', "review_contract", "f8_callback"),
    # The third review: execute and the signer.
    ("execute skips its gas check", LIB, 'let left = env::prepaid_gas().saturating_sub(env::used_gas());\n        require!(left >= need, format!("attach at least {} Tgas more", need.as_tgas()));\n\n        let attached', 'let _ = need;\n\n        let attached', "review2", "too_little_gas"),
    ("creation skips its gas check", LIB, 'let left = env::prepaid_gas().saturating_sub(env::used_gas());\n        require!(left >= need, format!("attach at least {} Tgas more", need.as_tgas()));\n        let hex_id', 'let _ = need;\n        let hex_id', "review2", "too_little_gas"),
    ("the deposit is not split", LIB, 'let per_sign = (attached / u128::from(count)).max(1);', 'let per_sign = attached.max(1);', "review2", "deposit_is_split"),
    ("the contract funds no yocto", LIB, 'let per_sign = (attached / u128::from(count)).max(1);', 'let per_sign = attached / u128::from(count);', "shell", "execute_asks"),
    ("any scheme is accepted", LIB, 'if resp.scheme != "Secp256k1" || resp.big_r', 'if resp.big_r', "review2", "malformed_signer"),
    ("big_r length unchecked", LIB, ' || resp.big_r.affine_point.0.len() != 33', '', "review2", "malformed_signer"),
    ("creation ignores the chosen policy", LIB, 'let policy = args.policy.map_or(cfg.policy, Policy::from);', 'let policy = cfg.policy;', "review2", "chosen_policy"),
    ("creation drops the guard", LIB, 'guard: args.guard.map(|a| a.to_string()),', 'guard: None,', "review2", "chosen_policy"),
    ("a freed ledger entry stays", STORE, 'for outpoint in self.raw_ledger.keys() {\n            if !ledger.contains_key(outpoint) {\n                env::storage_remove(&ledger_key(id, outpoint));\n            }\n        }', '', "review_contract", "f5_cancel"),
    ("the old reservation is not taken off", STORE, 'self.row.reserved = self.row.reserved.saturating_sub(self.reserve_read) + reserve_after;', 'self.row.reserved += reserve_after;', "review2", "request_lives"),
    ("a loaded request's reservation is not counted", STORE, 'self.reserve_read += request_reserve(&parsed);', '', "review2", "request_lives"),
    ("on_signed trusts the input index", LIB, '.filter(|r| index < r.inputs.len())', '', "review2", "on_signed_drops"),
    ("on_signed panics on an unknown vault", LIB, 'let Some(mut loaded) = storage::try_load_row(&id) else {\n            env::log_str("undo:on_signed dropped unknown_vault");\n            return;\n        };', 'let mut loaded = storage::load_row(&id);', "review2", "on_signed_drops"),
    ("on_signed forgets a failed answer", LIB, 'SignedOutcome::DroppedDigestMismatch | SignedOutcome::Failed => {\n                env::log_str(&format!("undo:on_signed {outcome:?} request={request} input={input}"));\n            }', 'SignedOutcome::DroppedDigestMismatch | SignedOutcome::Failed => {\n                env::log_str(&format!("undo:on_signed {outcome:?} request={request} input={input}"));\n                return;\n            }', "review_contract", "f13"),
    ("execute reads no ledger", LIB, 'let mut loaded = storage::load(&id);\n        loaded.load_request(&id, request);\n        let cfg = &self.config;', 'let mut loaded = storage::load(&id);\n        loaded.fetch_request(&id, request);\n        let cfg = &self.config;', "shell", "split_execute"),
    ("cancel reads no ledger", LIB, 'let mut loaded = storage::load(&id);\n        loaded.load_request(&id, request);\n        let caller = match auth {', 'let mut loaded = storage::load(&id);\n        loaded.fetch_request(&id, request);\n        let caller = match auth {', "review_contract", "f5_cancel"),
    ("reclaim reads no ledger", LIB, 'loaded.load_outpoints(&id, &[input.outpoint]);\n', '', "review_contract", "f0_false_amount"),
    ("raise_fee_cap reads no request", LIB, 'loaded.fetch_request(&id, request);\n        let caller = self.passkey_caller(&id, &loaded, "raise_fee_cap"', 'let caller = self.passkey_caller(&id, &loaded, "raise_fee_cap"', "review2", "free_views"),
    # The third review: views and WebAuthn shape.
    ("check_propose reads no ledger", LIB, 'loaded.load_outpoints(&id, &inputs.iter().map(|i| i.outpoint).collect::<Vec<_>>());\n        let check', 'let check', "review2", "free_views"),
    ("delay_now is wrong", LIB, 'storage::load_row(&vault_key(&vault)).row.vault.delay_now(now())', 'storage::load_row(&vault_key(&vault)).row.vault.policy.t_new_ms', "review2", "free_views"),
    ("webauthn skips the length check", AUTH, 'require!(auth.len() >= AUTH_DATA_MIN, "webauthn: short authenticator data");', 'require!(auth.len() >= 33, "webauthn: short");', "review2", "malformed_webauthn"),
    ("credit never refuses", STORE, 'if short == Short::Refuse {', 'if false && short == Short::Refuse {', "shell", "rotation_needs"),
    ("deleted bytes not paid back", STORE, 'self.row.credit = self.row.credit.saturating_add(cost(before - after));', '', "review_contract", "f5_cancel"),
]

def check():
    wrong = 0
    for name, path, old, _new, _test, _filt in MUTANTS:
        with open(os.path.join(REPO, path)) as f:
            count = f.read().count(old)
        if count != 1:
            wrong += 1
            print(f"NOT APPLIED {name}: found {count} times", flush=True)
    print(f"{len(MUTANTS) - wrong} of {len(MUTANTS)} mutants apply")
    return 1 if wrong else 0

def main():
    if sys.argv[1:] == ["--check"]:
        return check()
    protocol = sys.argv[1] if len(sys.argv) > 1 else "88"
    only = sys.argv[2] if len(sys.argv) > 2 else ""
    mutants = [m for m in MUTANTS if only in m[0]]
    start = os.environ.get("UNDO_MUTANTS_FROM")
    if start:
        mutants = mutants[[m[0] for m in mutants].index(start):]
    stop = os.environ.get("UNDO_MUTANTS_UNTIL")
    if stop:
        mutants = mutants[:[m[0] for m in mutants].index(stop)]
    base = tempfile.mkdtemp(prefix="undo-mutants-")
    tree = os.path.join(base, "undo")
    shutil.copytree(REPO, tree, ignore=shutil.ignore_patterns("target", ".git", ".tools", "props"))
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(base, "target"), CARGO_BUILD_JOBS=os.environ.get("CARGO_BUILD_JOBS", "3"))
    survived, wrong = [], []
    try:
        # A control first: the unmutated tree, on exactly the tests that will judge these mutants. A red
        # or empty one would read as a kill for every mutant that names it.
        build = subprocess.run([os.path.join(tree, "scripts/build.sh")], cwd=tree, env=env, capture_output=True, text=True)
        if build.returncode != 0:
            print(f"BASELINE FAILED: the unmutated tree does not build: {build.stderr[-400:]}", flush=True)
            return 2
        for test, filt in sorted({(m[4], m[5]) for m in mutants}):
            run = subprocess.run(
                [os.path.join(tree, "scripts/protocol-check.sh"), "--test", test, protocol],
                cwd=tree, env=dict(env, UNDO_TEST_FILTER=filt), capture_output=True, text=True,
            )
            if run.returncode != 0 or "0 passed, 0 failed" in run.stdout or "protocol" not in run.stdout:
                print(f"BASELINE FAILED: {test}: {filt} is not green or names no test\n{run.stdout[-400:]}", flush=True)
                return 2
        print("baseline green", flush=True)
        for name, path, old, new, test, filt in mutants:
            full = os.path.join(tree, path)
            with open(full) as f:
                text = f.read()
            if text.count(old) != 1:
                wrong.append(name)
                print(f"NOT APPLIED {name}", flush=True)
                continue
            with open(full, "w") as f:
                f.write(text.replace(old, new))
            try:
                build = subprocess.run([os.path.join(tree, "scripts/build.sh")], cwd=tree, env=env, capture_output=True, text=True)
                if build.returncode != 0:
                    wrong.append(name)
                    print(f"DID NOT BUILD {name}: {build.stderr[-400:]}", flush=True)
                    continue
                run = subprocess.run(
                    [os.path.join(tree, "scripts/protocol-check.sh"), "--test", test, protocol],
                    cwd=tree, env=dict(env, UNDO_TEST_FILTER=filt), capture_output=True, text=True,
                )
                ran = "0 passed, 0 failed" not in run.stdout and "protocol" in run.stdout
                if run.returncode == 0 or not ran:
                    survived.append(name)
                    print(f"SURVIVED {name}", flush=True)
                else:
                    print(f"KILLED {name} ({test}: {filt})", flush=True)
            finally:
                with open(full, "w") as f:
                    f.write(text)
        total = len(mutants)
        print(f"{total - len(survived) - len(wrong)} of {total} killed, {len(survived)} survived, {len(wrong)} did not apply")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return 1 if survived or wrong else 0

if __name__ == "__main__":
    sys.exit(main())
