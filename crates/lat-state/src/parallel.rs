//! T8 — deterministic parallel execution of a block's **transparent lane**.
//!
//! # Model
//!
//! Transparent transactions have a property the confidential lane doesn't:
//! their complete state-access set is known **statically** from the
//! transaction bytes alone — a `PublicTransfer`/`Shield` touches exactly
//! `{from, to}`, a `Register` exactly `{pubkey}`. (Fees don't break this:
//! lat-chain collects them from the transaction data and credits the miner
//! once, at the coinbase.) That turns parallel scheduling into a solved
//! problem — no optimistic re-execution, no aborts:
//!
//! 1. Split the block into **runs** of consecutive parallel-lane transactions;
//!    anything else (confidential proofs, contracts, token creation — dynamic
//!    or global state access) is a **barrier** applied serially in place.
//! 2. Within a run, assign each transaction the earliest **wave** after the
//!    last wave that touched any account in its access set. Transactions in
//!    the same wave are pairwise disjoint *by construction*.
//! 3. Execute each wave's transactions across worker threads, each on its own
//!    cheap [`Ledger`] clone (T5b: clones share the committed base and copy
//!    only the small uncommitted top). Merge each worker's written account
//!    records back into the main ledger after the wave.
//!
//! # Why the result is bit-identical to sequential execution
//!
//! A transaction reads and writes only its access set (the invariant this
//! module rests on — see [`access_set`]). Every earlier transaction that
//! shares any of those accounts was placed in an earlier wave and its writes
//! merged before this wave started; every disjoint transaction can't affect
//! it. So each transaction observes exactly the state it would have seen
//! sequentially — same success/failure, same writes, same final root. A block
//! is rejected in the parallel schedule if and only if it is rejected
//! sequentially (which error is reported may differ when several transactions
//! are independently invalid; the block-level outcome is identical).
//!
//! The speedup comes from the per-transaction Schnorr verification and account
//! record encode/decode running on all cores; the merge moves only the few
//! hundred bytes each transaction actually wrote.

use std::collections::{HashMap, HashSet};
use std::thread;

use lat_types::Transaction;

use crate::{Ledger, LedgerError, ProofPass};

/// The complete set of accounts `tx` may read or write, or `None` if the
/// transaction's access is dynamic/global (barrier: applied serially).
///
/// INVARIANT: for every transaction this returns `Some(set)` for, the
/// `Ledger::apply_at` arm must touch **no account outside `set` and no
/// non-account state**. Widening an arm's access (or adding one here) without
/// updating the other breaks the equivalence proof above — the randomized
/// parallel-vs-sequential oracle test exists to catch exactly that.
fn access_set(tx: &Transaction) -> Option<Vec<[u8; 32]>> {
    match tx {
        Transaction::Register { pubkey, .. } => Some(vec![*pubkey]),
        Transaction::PublicTransfer { from, to, .. } | Transaction::Shield { from, to, .. } => {
            Some(vec![*from, *to])
        }
        _ => None,
    }
}

/// Below this many transactions in a wave, spawning threads costs more than
/// the signatures they would verify; the wave is applied serially instead.
const MIN_PARALLEL: usize = 8;

/// Apply a block's transactions with the same semantics as
/// `for tx in txs { ledger.apply_at(tx, height)? }` — same final state on
/// success, an error exactly when the sequential loop would error — but with
/// the transparent lane executed across all cores. On error the ledger is
/// left partially applied, as the sequential loop leaves it; callers
/// (lat-chain) apply blocks to a discardable clone and drop it on rejection.
pub fn apply_block_parallel(
    ledger: &mut Ledger,
    txs: &[Transaction],
    height: u64,
) -> Result<(), LedgerError> {
    // T12: verify eligible confidential proofs across all cores up front, so
    // the serial barrier below skips the ~ms zero-knowledge math per proof.
    let preverified = preverify_confidential(ledger, txs);
    let mut i = 0;
    while i < txs.len() {
        if access_set(&txs[i]).is_none() {
            // Barrier: serial, in place (with the pre-pass evidence, if any).
            match preverified.get(&i) {
                Some(p) => ledger.apply_at_with(&txs[i], height, Some(p))?,
                None => ledger.apply_at(&txs[i], height)?,
            }
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < txs.len() && access_set(&txs[j]).is_some() {
            j += 1;
        }
        apply_run(ledger, &txs[i..j], height)?;
        i = j;
    }
    Ok(())
}

/// T12 pre-pass: verify confidential proofs across all cores **before**
/// application, producing [`ProofPass`] evidence the apply arms can reuse.
///
/// Eligibility:
/// * `AnonTransfer` — the ring proof is a pure function of the transfer, so
///   every one is eligible regardless of position.
/// * `SolventTransfer` / `Unshield` — the proof binds to the sender's balance
///   ciphertext *at its block position*. It is pre-verified against the
///   block-START balance, which equals the positional one iff no earlier
///   transaction writes the sender — predicted here with the same superset
///   write-sets the commitment uses. The prediction is a pure heuristic: the
///   apply arm re-verifies unless the live ciphertext is bit-identical to the
///   one recorded here, so a wrong guess costs time, never soundness.
///
/// A proof that FAILS pre-verification simply yields no evidence — the apply
/// arm re-verifies at the true position and reports the exact sequential
/// error, keeping the block verdict bit-identical.
fn preverify_confidential(
    ledger: &Ledger,
    txs: &[Transaction],
) -> HashMap<usize, ProofPass> {
    // Collect the verification jobs and each one's bound balance.
    #[allow(clippy::large_enum_variant)] // a 64-byte ciphertext; one per job
    enum Job<'a> {
        Anon(&'a Transaction),
        Solvent(&'a Transaction, crate::Ciphertext),
    }
    let mut written: HashSet<[u8; 32]> = HashSet::new();
    let mut jobs: Vec<(usize, Job)> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        match tx {
            Transaction::AnonTransfer { .. } => jobs.push((i, Job::Anon(tx))),
            Transaction::SolventTransfer { token, xfer } => {
                let sender = xfer.sender.to_bytes();
                if !written.contains(&sender) {
                    if let Some(bal) = ledger.balance(&sender, *token) {
                        jobs.push((i, Job::Solvent(tx, bal)));
                    }
                }
            }
            Transaction::Unshield { token, xfer, .. } => {
                let sender = xfer.sender.to_bytes();
                if !written.contains(&sender) {
                    if let Some(bal) = ledger.balance(&sender, *token) {
                        jobs.push((i, Job::Solvent(tx, bal)));
                    }
                }
            }
            _ => {}
        }
        for key in ledger.dirty_keys_for(tx) {
            if let crate::DirtyKey::Account(id) = key {
                written.insert(id);
            }
        }
    }
    if jobs.len() < 2 {
        return HashMap::new(); // one proof gains nothing from a pre-pass
    }

    let workers = thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(jobs.len());
    let chunk_len = jobs.len().div_ceil(workers);
    let verified: Vec<Vec<(usize, ProofPass)>> = thread::scope(|s| {
        let handles: Vec<_> = jobs
            .chunks(chunk_len)
            .map(|chunk| {
                s.spawn(move || {
                    let mut out = Vec::new();
                    for (i, job) in chunk {
                        match job {
                            Job::Anon(tx) => {
                                if let Transaction::AnonTransfer { xfer, .. } = tx {
                                    if xfer.verify() {
                                        out.push((*i, ProofPass::Anon));
                                    }
                                }
                            }
                            Job::Solvent(tx, bal) => {
                                let ok = match tx {
                                    Transaction::SolventTransfer { xfer, .. } => xfer.verify(bal),
                                    Transaction::Unshield { xfer, .. } => xfer.verify(bal),
                                    _ => false,
                                };
                                if ok {
                                    out.push((*i, ProofPass::AgainstBalance(*bal)));
                                }
                            }
                        }
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("preverify worker panicked")).collect()
    });
    verified.into_iter().flatten().collect()
}

/// Schedule a run of parallel-lane transactions into conflict-free waves and
/// execute them. `run` indices are relative to the run; ordering within the
/// run is the block ordering.
fn apply_run(ledger: &mut Ledger, run: &[Transaction], height: u64) -> Result<(), LedgerError> {
    let sets: Vec<Vec<[u8; 32]>> =
        run.iter().map(|tx| access_set(tx).expect("run holds only parallel-lane txs")).collect();
    for wave in schedule_waves(&sets) {
        execute_wave(ledger, run, &sets, &wave, height)?;
    }
    Ok(())
}

/// Earliest-wave list scheduling: transaction `k` goes into the first wave
/// after the last wave that touched any account in its set. Conflicting
/// transactions therefore execute in block order across waves; transactions
/// sharing a wave are pairwise account-disjoint.
fn schedule_waves(sets: &[Vec<[u8; 32]>]) -> Vec<Vec<usize>> {
    // `next_wave[a]` = the first wave a future toucher of account `a` may use.
    let mut next_wave: HashMap<[u8; 32], usize> = HashMap::new();
    let mut waves: Vec<Vec<usize>> = Vec::new();
    for (k, set) in sets.iter().enumerate() {
        let w = set.iter().map(|a| next_wave.get(a).copied().unwrap_or(0)).max().unwrap_or(0);
        if w == waves.len() {
            waves.push(Vec::new());
        }
        waves[w].push(k);
        for a in set {
            next_wave.insert(*a, w + 1);
        }
    }
    waves
}

/// Execute one wave. Small waves run serially; larger ones fan out across
/// worker threads, each applying its chunk on its own ledger clone, then the
/// written account records are merged back (disjointness makes merge order
/// irrelevant). A worker error surfaces as the failing transaction with the
/// lowest block index, for a deterministic report.
fn execute_wave(
    ledger: &mut Ledger,
    run: &[Transaction],
    sets: &[Vec<[u8; 32]>],
    wave: &[usize],
    height: u64,
) -> Result<(), LedgerError> {
    if wave.len() < MIN_PARALLEL {
        for &k in wave {
            ledger.apply_at(&run[k], height)?;
        }
        return Ok(());
    }
    // Queried once per process: it's a syscall, and conflict-heavy runs hit
    // this path once per (tiny) wave.
    static WORKERS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let workers = *WORKERS
        .get_or_init(|| thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    let workers = workers.min(wave.len());
    if workers < 2 {
        for &k in wave {
            ledger.apply_at(&run[k], height)?;
        }
        return Ok(());
    }

    type WorkerOut = Result<Vec<([u8; 32], Vec<u8>)>, (usize, LedgerError)>;
    let chunk_len = wave.len().div_ceil(workers);
    let results: Vec<WorkerOut> = thread::scope(|s| {
        let handles: Vec<_> = wave
            .chunks(chunk_len)
            .map(|chunk| {
                let mut view = ledger.clone();
                s.spawn(move || -> WorkerOut {
                    for &k in chunk {
                        view.apply_at(&run[k], height).map_err(|e| (k, e))?;
                    }
                    // Export every access-set record once — those are, by the
                    // module invariant, exactly the accounts this chunk wrote.
                    let mut seen = HashSet::new();
                    let mut written = Vec::new();
                    for &k in chunk {
                        for a in &sets[k] {
                            if seen.insert(*a) {
                                if let Some(bytes) = view.account_record(a) {
                                    written.push((*a, bytes));
                                }
                            }
                        }
                    }
                    Ok(written)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("parallel worker panicked")).collect()
    });

    let mut first_err: Option<(usize, LedgerError)> = None;
    let mut merged = Vec::new();
    for r in results {
        match r {
            Ok(written) => merged.push(written),
            Err((k, e)) => {
                if first_err.as_ref().is_none_or(|(fk, _)| k < *fk) {
                    first_err = Some((k, e));
                }
            }
        }
    }
    if let Some((_, e)) = first_err {
        return Err(e);
    }
    for written in merged {
        for (id, bytes) in written {
            ledger.adopt_account_record(&id, bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LAT_TOKEN;
    use lat_crypto::SecretKey;
    use rand::rngs::OsRng;

    fn signed(mut tx: Transaction, sk: &SecretKey) -> Transaction {
        let sig_bytes = sk.sign(&tx.signing_bytes()).to_bytes();
        match &mut tx {
            Transaction::PublicTransfer { sig, .. }
            | Transaction::Shield { sig, .. }
            | Transaction::CreateToken { sig, .. } => *sig = sig_bytes,
            _ => {}
        }
        tx
    }

    /// `n` funded accounts on a fresh ledger; returns (ledger, keys, ids).
    fn funded(n: usize) -> (Ledger, Vec<SecretKey>, Vec<[u8; 32]>) {
        let mut rng = OsRng;
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let mut l = Ledger::new();
        for id in &ids {
            l.register(*id).unwrap();
            l.credit_public(id, LAT_TOKEN, 10_000);
        }
        l.state_root();
        l.flush();
        (l, sks, ids)
    }

    fn transfer(
        sks: &[SecretKey],
        ids: &[[u8; 32]],
        from: usize,
        to: usize,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN,
                from: ids[from],
                to: ids[to],
                amount,
                fee: 1,
                nonce,
                sig: [0u8; 64],
            },
            &sks[from],
        )
    }

    #[test]
    fn waves_pack_disjoint_and_serialize_conflicts() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let d = [4u8; 32];
        // tx0 {a,b}, tx1 {c,d} disjoint → wave 0. tx2 {b,c} conflicts with both
        // → wave 1. tx3 {a,d} conflicts only with wave-0 txs → wave 1 too.
        // tx4 {a,c} conflicts with wave-1 → wave 2.
        let sets = vec![vec![a, b], vec![c, d], vec![b, c], vec![a, d], vec![a, c]];
        assert_eq!(schedule_waves(&sets), vec![vec![0, 1], vec![2, 3], vec![4]]);
    }

    #[test]
    fn parallel_matches_sequential_over_random_transparent_workload() {
        let n = 64;
        let (l, sks, ids) = funded(n);
        let mut seq = l.clone();
        let mut par = l;

        // A workload with real conflict structure: disjoint pairs, chained
        // transfers, self-transfers, a hot receiver — all with correct
        // per-sender nonces (tracked as the sequential apply would advance them).
        let mut nonces = vec![0u64; n];
        let mut txs = Vec::new();
        for round in 0..4 {
            for i in 0..n / 2 {
                let (from, to) = match round {
                    0 => (i, n / 2 + i),           // disjoint pairs
                    1 => (i, (i + 1) % (n / 2)),   // chained ring
                    2 => (n / 2 + i, 0),           // hot receiver
                    _ => (i, i),                   // self-transfers
                };
                txs.push(transfer(&sks, &ids, from, to, 10 + round as u64, nonces[from]));
                nonces[from] += 1;
            }
        }
        // A registration inside the run and a barrier in the middle.
        let new_sk = SecretKey::random(&mut OsRng);
        txs.insert(40, Transaction::Register { pubkey: new_sk.public_key().to_bytes(), pow_nonce: 0 });
        txs.insert(
            70,
            signed(
                Transaction::CreateToken {
                    ticker: "PARA".into(),
                    creator: ids[0],
                    supply: 9,
                    sig: [0u8; 64],
                },
                &sks[0],
            ),
        );

        for tx in &txs {
            seq.apply_at(tx, 1).unwrap();
        }
        apply_block_parallel(&mut par, &txs, 1).unwrap();

        assert_eq!(par.state_root(), seq.state_root(), "parallel diverged from sequential");
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                par.public_balance(id, LAT_TOKEN),
                seq.public_balance(id, LAT_TOKEN),
                "balance {i}"
            );
        }
    }

    #[test]
    fn parallel_rejects_exactly_when_sequential_rejects() {
        let n = 32;
        let (l, sks, ids) = funded(n);
        let mut seq = l.clone();
        let mut par = l;

        // A big disjoint wave with one bad-nonce transaction buried in it.
        let mut txs: Vec<Transaction> =
            (0..n / 2).map(|i| transfer(&sks, &ids, i, n / 2 + i, 5, 0)).collect();
        txs[9] = transfer(&sks, &ids, 9, n / 2 + 9, 5, 77); // wrong nonce

        let seq_err = (|| -> Result<(), LedgerError> {
            for tx in &txs {
                seq.apply_at(tx, 1)?;
            }
            Ok(())
        })();
        let par_err = apply_block_parallel(&mut par, &txs, 1);
        assert_eq!(seq_err, Err(LedgerError::BadNonce));
        assert_eq!(par_err, Err(LedgerError::BadNonce), "same block-level verdict");

        // And an all-valid version of the same wave passes both.
        let (l2, sks2, ids2) = funded(n);
        let mut seq2 = l2.clone();
        let mut par2 = l2;
        let txs: Vec<Transaction> =
            (0..n / 2).map(|i| transfer(&sks2, &ids2, i, n / 2 + i, 5, 0)).collect();
        for tx in &txs {
            seq2.apply_at(tx, 1).unwrap();
        }
        apply_block_parallel(&mut par2, &txs, 1).unwrap();
        assert_eq!(par2.state_root(), seq2.state_root());
    }

    #[test]
    fn confidential_preverify_matches_sequential_on_a_mixed_block() {
        let mut rng = OsRng;
        // Confidentially-funded ring accounts + public funds for the same ids.
        let (mut l, csks, cids) = crate::tests::ledger_with_ring(8, 100_000, &mut rng);
        for id in &cids {
            l.credit_public(id, LAT_TOKEN, 10_000);
        }
        l.state_root();
        l.flush();
        let height = 45; // fixes the anon epoch

        // Solvent transfers from three DIFFERENT senders (all eligible for the
        // pre-pass), one anon transfer (always eligible), and a second solvent
        // from a sender whose balance an earlier tx changed (ineligible →
        // serial re-verify fallback), plus transparent noise around them.
        let bal0 = l.balance(&cids[0], LAT_TOKEN).unwrap();
        let s0 = Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[0], &csks[1].public_key(), 5_000, 100, 100_000, &bal0, 0, &mut rng,
            )
            .unwrap(),
        };
        let bal2 = l.balance(&cids[2], LAT_TOKEN).unwrap();
        let s2 = Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[2], &csks[3].public_key(), 700, 100, 100_000, &bal2, 0, &mut rng,
            )
            .unwrap(),
        };
        // The anon transfer's ring covers ALL the accounts, so it must bind to
        // the balances AFTER s0/s2 (its block position). Same for s6 below —
        // the anon debit touches cids[6] too. Build both against a scratch
        // clone that replays the block prefix.
        let mut scratch = l.clone();
        scratch.apply_at(&s0, height).unwrap();
        scratch.apply_at(&s2, height).unwrap();
        let anon = crate::tests::anon_tx(
            &scratch, &csks, &cids, 4, 100_000, &csks[5].public_key(), 2_000, 1_000, height,
            &mut rng,
        );
        scratch.apply_at(&anon, height).unwrap();
        let bal6 = scratch.balance(&cids[6], LAT_TOKEN).unwrap();
        let s6 = Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[6], &csks[7].public_key(), 300, 100, 100_000, &bal6, 0, &mut rng,
            )
            .unwrap(),
        };

        // Transparent noise after the confidential txs. The spend nonce is
        // shared across tx kinds: s0/s2/s6 bumped cids[0]/[2]/[6] to 1; the
        // anon transfer bumps nobody (naming the spender would defeat it).
        let mut txs = vec![s0, s2, anon, s6];
        for (i, nonce) in [(0usize, 1u64), (1, 0), (2, 1), (3, 0)] {
            txs.push(transfer(&csks, &cids, i, 7 - i, 50, nonce));
        }

        let mut seq = l.clone();
        let mut par = l;
        for tx in &txs {
            seq.apply_at(tx, height).unwrap();
        }
        apply_block_parallel(&mut par, &txs, height).unwrap();
        assert_eq!(par.state_root(), seq.state_root(), "mixed confidential block diverged");
    }

    #[test]
    fn tampered_confidential_proof_rejected_with_and_without_prepass() {
        let mut rng = OsRng;
        let (l, csks, cids) = crate::tests::ledger_with_ring(4, 50_000, &mut rng);
        let mut seq = l.clone();
        let mut par = l.clone();

        // A proof built against a FABRICATED balance: pre-verification fails
        // (no evidence), apply re-verifies serially and rejects — both modes.
        let fake = lat_crypto::Ciphertext::mint(999_999);
        let bad = Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[0], &csks[1].public_key(), 60_000, 0, 999_999, &fake, 0, &mut rng,
            )
            .unwrap(),
        };
        let bal2 = l.balance(&cids[2], LAT_TOKEN).unwrap();
        let good = Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[2], &csks[3].public_key(), 100, 0, 50_000, &bal2, 0, &mut rng,
            )
            .unwrap(),
        };
        let txs = vec![good, bad];

        let seq_err = (|| -> Result<(), LedgerError> {
            for tx in &txs {
                seq.apply_at(tx, 1)?;
            }
            Ok(())
        })();
        assert_eq!(seq_err, Err(LedgerError::InvalidProof));
        assert_eq!(
            apply_block_parallel(&mut par, &txs, 1),
            Err(LedgerError::InvalidProof),
            "pre-pass must not launder a bad proof"
        );
    }

    #[test]
    fn shield_joins_the_parallel_lane() {
        let n = 32;
        let (l, sks, ids) = funded(n);
        let mut seq = l.clone();
        let mut par = l;
        let txs: Vec<Transaction> = (0..n / 2)
            .map(|i| {
                signed(
                    Transaction::Shield {
                        token: LAT_TOKEN,
                        from: ids[i],
                        to: ids[n / 2 + i],
                        amount: 100,
                        fee: 1,
                        nonce: 0,
                        sig: [0u8; 64],
                    },
                    &sks[i],
                )
            })
            .collect();
        for tx in &txs {
            seq.apply_at(tx, 1).unwrap();
        }
        apply_block_parallel(&mut par, &txs, 1).unwrap();
        assert_eq!(par.state_root(), seq.state_root());
    }
}
