//! Latebra wallet (clean-room, from `SPEC.md`).
//!
//! A wallet is a seed-derived keypair. It can:
//! * show its `lat`/`latt` address,
//! * back up / restore from a hex seed,
//! * produce a registration transaction (with anti-spam PoW),
//! * build a confidential transfer to another address, and
//! * read its own balance from the chain, and scan blocks for funds received.
//!
//! The private seed never leaves the wallet. Balances are decrypted locally with
//! the secret key; the chain only ever stores ciphertexts.
//!
//! ## Privacy note (honest)
//! A transfer currently names its receiver's public key in the clear, so an
//! observer can see *who* received funds (but never *how much*). Hiding the
//! recipient among an anonymity set is a later enhancement, not in this milestone.

use lat_chain::{mine_registration, Blockchain, Block};
use lat_crypto::{AnonTransfer, Ciphertext, PublicKey, SecretKey, SolventTransfer};
use lat_types::{Address, Network, Transaction};

/// The consensus fee floor, re-exported so wallet users can pass it as the
/// default `fee` when building transfers.
pub use lat_chain::MIN_TRANSFER_FEE;

/// Default anonymity-set size for anonymous transfers (within the consensus
/// bound [`lat_chain::MAX_RING_SIZE`]): the true sender hides among 7 decoys.
pub const DEFAULT_RING_SIZE: usize = 8;

/// Bits searched when decrypting a balance — the maximum recoverable balance is
/// `2^BALANCE_BITS` base units. 40 bits covers ~11 million LAT. Small balances are
/// still found quickly (the search stops as soon as it matches); only a very large
/// balance, or a failed decrypt, walks the full range. For even larger balances or
/// faster decryption, a bigger shared discrete-log table (à la DERO) is the
/// optimization.
pub const BALANCE_BITS: u32 = 40;

/// Errors restoring a wallet from a backup string.
#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    BadSeedHex,
}

pub struct Wallet {
    network: Network,
    seed: [u8; 32],
    secret: SecretKey,
}

/// A stealth shield this wallet owns, found by [`Wallet::scan_stealth`]. Wrap
/// `secret` with [`Wallet::from_secret`] to spend the one-time account.
pub struct StealthReceipt {
    /// The one-time account id (its public key bytes) that was credited.
    pub one_time: [u8; 32],
    /// The one-time spend key for that account (only this wallet can derive it).
    pub secret: SecretKey,
    pub token: u32,
    pub amount: u64,
}

impl Wallet {
    /// Create a brand-new random wallet on the given network.
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(network: Network, rng: &mut R) -> Wallet {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Wallet::from_seed(network, seed)
    }

    /// Deterministically build a wallet from a 32-byte seed.
    pub fn from_seed(network: Network, seed: [u8; 32]) -> Wallet {
        let secret = SecretKey::from_seed(&seed);
        Wallet { network, seed, secret }
    }

    /// Wrap an existing secret key as a wallet. Used for **one-time stealth
    /// accounts**, whose spend keys are derived (via [`scan_stealth`](Self::scan_stealth)),
    /// not seed-generated — so the seed backup is meaningless here (zeroed).
    pub fn from_secret(network: Network, secret: SecretKey) -> Wallet {
        Wallet { network, seed: [0u8; 32], secret }
    }

    /// Restore a wallet from its hex seed backup.
    pub fn from_seed_hex(network: Network, seed_hex: &str) -> Result<Wallet, WalletError> {
        let bytes = hex::decode(seed_hex.trim()).map_err(|_| WalletError::BadSeedHex)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| WalletError::BadSeedHex)?;
        Ok(Wallet::from_seed(network, seed))
    }

    /// The hex seed backup. Anyone with this controls the wallet — guard it.
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed)
    }

    /// The wallet's secret key — e.g. to sign finality votes when the account
    /// runs as a validator (T14). Guard it like the seed.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// This wallet's address.
    pub fn address(&self) -> Address {
        Address::new(self.network, self.secret.public_key())
    }

    /// The encoded address string (`lat1...` / `latt1...`).
    pub fn address_string(&self) -> String {
        self.address().encode()
    }

    /// The 32-byte account id used as the state-tree key.
    pub fn id(&self) -> [u8; 32] {
        self.secret.public_key().to_bytes()
    }

    /// Build a registration transaction (solves the anti-spam PoW).
    pub fn registration_tx(&self) -> Transaction {
        mine_registration(self.id())
    }

    /// Sign a transparent transaction's payload with this wallet's key, filling
    /// in its `sig` field. (Confidential transfers prove ownership in their
    /// Σ-proof instead and pass through unchanged.)
    fn sign_tx(&self, mut tx: Transaction) -> Transaction {
        let sig_bytes = self.secret.sign(&tx.signing_bytes()).to_bytes();
        match &mut tx {
            Transaction::CreateToken { sig, .. }
            | Transaction::Rollover { sig, .. }
            | Transaction::DeployContract { sig, .. }
            | Transaction::CallContract { sig, .. }
            | Transaction::PublicTransfer { sig, .. }
            | Transaction::Shield { sig, .. }
            | Transaction::Unshield { sig, .. }
            | Transaction::ShieldStealth { sig, .. }
            | Transaction::Stake { sig, .. }
            | Transaction::Unstake { sig, .. }
            | Transaction::AddLiquidity { sig, .. }
            | Transaction::RemoveLiquidity { sig, .. }
            | Transaction::Swap { sig, .. }
            | Transaction::CurveTrade { sig, .. }
            | Transaction::HtlcLock { sig, .. } => *sig = sig_bytes,
            _ => {}
        }
        tx
    }

    // -- native DEX (AMM) + bridge (HTLC) builders ----------------------------

    /// Build + sign an `AddLiquidity` deposit into the pool for `token`:
    /// exactly `lat_amount` LAT plus up to `tok_amount` of the token (the
    /// ratio-matched amount is what consensus actually debits).
    pub fn add_liquidity(
        &self,
        token: u32,
        lat_amount: u64,
        tok_amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        self.sign_tx(Transaction::AddLiquidity {
            token,
            provider: self.id(),
            lat_amount,
            tok_amount,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build + sign a `RemoveLiquidity` burning `lp_amount` of this wallet's
    /// LP shares in the pool for `token`.
    pub fn remove_liquidity(&self, token: u32, lp_amount: u64, fee: u64, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::RemoveLiquidity {
            token,
            provider: self.id(),
            lp_amount,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build + sign a `Swap` against the pool for `token`. `lat_in` picks the
    /// direction (LAT → token or token → LAT); `min_out` is the slippage bound.
    pub fn swap(
        &self,
        token: u32,
        lat_in: bool,
        amount_in: u64,
        min_out: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        self.sign_tx(Transaction::Swap {
            token,
            trader: self.id(),
            lat_in,
            amount_in,
            min_out,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build + sign a `CurveTrade` against `token`'s native bonding curve. A buy
    /// (`is_buy`) pays `amount` LAT for tokens; a sell offers `amount` tokens for
    /// LAT. `min_out` is the slippage bound.
    pub fn curve_trade(
        &self,
        token: u32,
        is_buy: bool,
        amount: u64,
        min_out: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        self.sign_tx(Transaction::CurveTrade {
            token,
            trader: self.id(),
            is_buy,
            amount,
            min_out,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build + sign an `HtlcLock` escrowing `amount` of `token` for `to` under
    /// a SHA-256 `hashlock`, refundable to this wallet from block `expiry` on.
    /// Returns the transaction and the lock's deterministic id (needed to
    /// claim or refund it).
    pub fn htlc_lock(
        &self,
        token: u32,
        to: &Address,
        amount: u64,
        hashlock: [u8; 32],
        expiry: u64,
        fee: u64,
        nonce: u64,
    ) -> (Transaction, [u8; 32]) {
        let to = to.key.to_bytes();
        let id = lat_types::htlc_id(token, &self.id(), &to, amount, &hashlock, expiry, nonce);
        let tx = self.sign_tx(Transaction::HtlcLock {
            token,
            from: self.id(),
            to,
            amount,
            hashlock,
            expiry,
            fee,
            nonce,
            sig: [0u8; 64],
        });
        (tx, id)
    }

    /// Build an `HtlcClaim` revealing `preimage` for the lock `id`. No
    /// signature needed — the preimage is the authority, and funds can only go
    /// to the recipient the lock recorded.
    pub fn htlc_claim(id: [u8; 32], preimage: [u8; 32]) -> Transaction {
        Transaction::HtlcClaim { id, preimage }
    }

    /// Build an `HtlcRefund` for the expired lock `id` (permissionless; funds
    /// return to the lock's original sender).
    pub fn htlc_refund(id: [u8; 32]) -> Transaction {
        Transaction::HtlcRefund { id }
    }

    /// Build a signed transaction creating a new token under `ticker`, with the
    /// whole `supply` credited to this wallet. Rejected by consensus if the
    /// ticker is already taken (global uniqueness).
    pub fn create_token(&self, ticker: &str, supply: u64) -> Transaction {
        self.sign_tx(Transaction::CreateToken {
            ticker: ticker.to_string(),
            creator: self.id(),
            supply,
            sig: [0u8; 64],
        })
    }

    /// Build a signed transaction deploying contract `code` from this wallet.
    pub fn deploy_contract(&self, code: Vec<u8>) -> Transaction {
        self.sign_tx(Transaction::DeployContract {
            deployer: self.id(),
            code,
            sig: [0u8; 64],
        })
    }

    /// Build a signed transaction calling `contract` with `input`, at this
    /// wallet's current spend `nonce` (read it from the chain or over RPC).
    pub fn call_contract(&self, contract: [u8; 32], input: u64, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::CallContract {
            contract,
            caller: self.id(),
            input,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build a SOLVENT confidential transfer of `amount` of `token` to `receiver`.
    /// Reads this wallet's current balance from `chain`, decrypts it, and proves —
    /// in zero knowledge — that the remaining balance stays non-negative. Returns
    /// `None` if the wallet isn't registered, can't read its balance, or can't
    /// afford the amount (in which case no valid proof exists).
    pub fn create_solvent_transfer<R: rand::RngCore + rand::CryptoRng>(
        &self,
        chain: &Blockchain,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let balance_ct = chain.balance(&self.id(), token)?;
        let current = self.secret.decrypt(&balance_ct, BALANCE_BITS)?;
        let nonce = chain.nonce(&self.id())?;
        let xfer = SolventTransfer::create(
            &self.secret,
            &receiver.key,
            token,
            amount,
            fee,
            current,
            &balance_ct,
            nonce,
            rng,
        )?;
        Some(Transaction::SolventTransfer { token, xfer })
    }

    /// Build a signed **public** (transparent) transfer of `amount` of `token`
    /// to `receiver`, reading this wallet's public balance and spend nonce from
    /// `chain`. Everything is in the clear — no proof, just a signature. Returns
    /// `None` if the wallet isn't registered or can't afford `amount + fee`.
    pub fn create_public_transfer(
        &self,
        chain: &Blockchain,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
    ) -> Option<Transaction> {
        let nonce = chain.nonce(&self.id())?;
        let balance = chain.public_balance(&self.id(), token)?;
        if balance < amount.checked_add(fee)? {
            return None; // consensus would reject it anyway
        }
        Some(self.build_public_transfer(receiver, token, amount, fee, nonce))
    }

    /// Build + sign a public transfer from an explicit `nonce` (for a networked
    /// wallet that read its nonce over RPC). Affordability is enforced by
    /// consensus; this only assembles and signs the transaction.
    pub fn build_public_transfer(
        &self,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        self.sign_tx(Transaction::PublicTransfer {
            token,
            from: self.id(),
            to: receiver.key.to_bytes(),
            amount,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Read this wallet's transparent (plaintext) public balance of `token`.
    pub fn public_balance(&self, chain: &Blockchain, token: u32) -> Option<u64> {
        chain.public_balance(&self.id(), token)
    }

    /// **Stealth shield**: shield `amount` of `token` from this wallet's PUBLIC
    /// balance to `recipient`, hiding *who* the recipient is. The transaction
    /// credits a fresh one-time account only `recipient` can detect (via
    /// [`scan_stealth`](Self::scan_stealth)); observers can't link it to them.
    /// `None` if this wallet can't afford `amount + fee`.
    pub fn create_shield_stealth<R: rand::RngCore + rand::CryptoRng>(
        &self,
        chain: &Blockchain,
        recipient: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let nonce = chain.nonce(&self.id())?;
        let balance = chain.public_balance(&self.id(), token)?;
        if balance < amount.checked_add(fee)? {
            return None;
        }
        Some(self.build_shield_stealth(recipient, token, amount, fee, nonce, rng))
    }

    /// Build + sign a stealth shield from an explicit `nonce` (networked wallet).
    pub fn build_shield_stealth<R: rand::RngCore + rand::CryptoRng>(
        &self,
        recipient: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        nonce: u64,
        rng: &mut R,
    ) -> Transaction {
        let out = lat_crypto::stealth_send(&recipient.key, rng);
        self.sign_tx(Transaction::ShieldStealth {
            token,
            from: self.id(),
            ephemeral: out.ephemeral.to_bytes(),
            one_time: out.one_time.to_bytes(),
            amount,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Scan `block` for **stealth outputs addressed to this wallet** — both
    /// stealth shields and anonymous transfers pay into one-time accounts only
    /// the recipient can detect. For each one owned, returns the one-time
    /// account and its derived spend key, so the funds can be claimed with
    /// `Wallet::from_secret(net, receipt.secret)`.
    pub fn scan_stealth(&self, block: &Block) -> Vec<StealthReceipt> {
        let mut found = Vec::new();
        for tx in &block.txs {
            match tx {
                Transaction::ShieldStealth { token, ephemeral, one_time, amount, .. } => {
                    let eph = match PublicKey::from_bytes(ephemeral) {
                        Some(p) => p,
                        None => continue,
                    };
                    let ot = match PublicKey::from_bytes(one_time) {
                        Some(p) => p,
                        None => continue,
                    };
                    if let Some(secret) = lat_crypto::stealth_receive(&self.secret, &eph, &ot) {
                        found.push(StealthReceipt { one_time: *one_time, secret, token: *token, amount: *amount });
                    }
                }
                // An anonymous transfer's receiver leg is the same stealth
                // mechanism. v3: the amount is HIDDEN on the wire — only the
                // derived one-time spend key can decrypt the carried credit
                // ciphertext (bounded discrete log, same range as balances).
                Transaction::AnonTransfer { token, xfer } => {
                    if let Some(secret) =
                        lat_crypto::stealth_receive(&self.secret, &xfer.output.ephemeral, &xfer.output.one_time)
                    {
                        let amount = secret.decrypt(&xfer.credit, BALANCE_BITS).unwrap_or(0);
                        found.push(StealthReceipt {
                            one_time: xfer.output.one_time.to_bytes(),
                            secret,
                            token: *token,
                            amount,
                        });
                    }
                }
                _ => {}
            }
        }
        found
    }

    /// Like [`scan_stealth`](Self::scan_stealth) but takes raw encoded block bytes
    /// (e.g. fetched over RPC), decoding internally. Empty on undecodable input —
    /// so a networked wallet can scan without depending on `lat-chain` directly.
    pub fn scan_stealth_bytes(&self, block_bytes: &[u8]) -> Vec<StealthReceipt> {
        match Block::decode(block_bytes) {
            Some(b) => self.scan_stealth(&b),
            None => Vec::new(),
        }
    }

    /// **Shield** `amount` of `token` from this wallet's PUBLIC balance into
    /// `to`'s PRIVATE balance (often `to` == this wallet — "make my LAT private").
    /// Reads the public balance + nonce from `chain`; `None` if it can't afford
    /// `amount + fee`. The shielded funds land in the recipient's private *pending*
    /// pool — they roll over to make them spendable.
    pub fn create_shield(
        &self,
        chain: &Blockchain,
        to: &Address,
        token: u32,
        amount: u64,
        fee: u64,
    ) -> Option<Transaction> {
        let nonce = chain.nonce(&self.id())?;
        let balance = chain.public_balance(&self.id(), token)?;
        if balance < amount.checked_add(fee)? {
            return None;
        }
        Some(self.build_shield(to, token, amount, fee, nonce))
    }

    /// Build + sign a shield from an explicit `nonce` (for a networked wallet that
    /// read its nonce over RPC). Affordability is enforced by consensus.
    pub fn build_shield(&self, to: &Address, token: u32, amount: u64, fee: u64, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::Shield {
            token,
            from: self.id(),
            to: to.key.to_bytes(),
            amount,
            fee,
            nonce,
            sig: [0u8; 64],
        })
    }

    /// **Unshield** `amount` of `token` from this wallet's PRIVATE balance to
    /// `to`'s PUBLIC balance. Builds a confidential solvent transfer to the public
    /// unshield view key (which reveals the amount) and signs it to bind `to`.
    /// `None` if the wallet can't read its balance or can't afford `amount + fee`.
    pub fn create_unshield<R: rand::RngCore + rand::CryptoRng>(
        &self,
        chain: &Blockchain,
        to: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let balance_ct = chain.balance(&self.id(), token)?;
        let nonce = chain.nonce(&self.id())?;
        self.build_unshield(to, token, amount, fee, &balance_ct, nonce, rng)
    }

    /// Build + sign an unshield from data fetched over RPC (the sender's encrypted
    /// balance ciphertext + spend nonce) rather than a local chain. `None` if the
    /// balance can't be decrypted or the amount + fee isn't affordable.
    pub fn build_unshield<R: rand::RngCore + rand::CryptoRng>(
        &self,
        to: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        balance_ct: &lat_crypto::Ciphertext,
        nonce: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let current = self.secret.decrypt(balance_ct, BALANCE_BITS)?;
        self.build_unshield_with_balance(to, token, amount, fee, current, balance_ct, nonce, rng)
    }

    /// [`build_unshield`](Self::build_unshield) for a caller that already knows
    /// the decrypted balance, skipping the discrete-log decrypt (which costs
    /// minutes for balances near 2^40 — e.g. a market-maker's inventory). If
    /// `current` is wrong the proof simply fails verification on-chain.
    #[allow(clippy::too_many_arguments)]
    pub fn build_unshield_with_balance<R: rand::RngCore + rand::CryptoRng>(
        &self,
        to: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        current: u64,
        balance_ct: &lat_crypto::Ciphertext,
        nonce: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let xfer = SolventTransfer::create(
            &self.secret,
            &lat_crypto::unshield_view_key(),
            token,
            amount,
            fee,
            current,
            balance_ct,
            nonce,
            rng,
        )?;
        Some(self.sign_tx(Transaction::Unshield {
            token,
            to: to.key.to_bytes(),
            amount,
            xfer,
            sig: [0u8; 64],
        }))
    }

    /// Build an **ANONYMOUS** transfer of `amount` of `token` to `receiver`:
    /// this wallet hides inside a ring of `ring_size` accounts and the receiver
    /// behind a one-time stealth key, so the transaction's public fields name
    /// nobody. The amount and fee stay public (this phase). Decoys are sampled
    /// uniformly from the chain's candidate pool; the epoch is the next block's.
    ///
    /// Returns `None` if the wallet can't read/afford its balance, or there
    /// aren't enough distinct decoys to form a ring of at least 2.
    ///
    /// Caveats (inherent to the design, see `ANON_INTEGRATION.md`): one
    /// anonymous spend per wallet per epoch; the proof binds every ring
    /// member's CURRENT balance, so if any decoy's balance changes before the
    /// transaction mines, it must be rebuilt.
    pub fn create_anon_transfer<R: rand::RngCore + rand::CryptoRng>(
        &self,
        chain: &Blockchain,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        ring_size: usize,
        rng: &mut R,
    ) -> Option<Transaction> {
        let my_balance_ct = chain.balance(&self.id(), token)?;
        let candidates = chain.ring_candidates(token);
        let epoch = lat_chain::epoch_of(chain.height() + 1);
        self.build_anon_transfer(receiver, token, amount, fee, &my_balance_ct, &candidates, epoch, ring_size, rng)
    }

    /// Build an anonymous transfer from data fetched over RPC: this wallet's
    /// balance ciphertext, the candidate decoy pool (`(account id, balance
    /// ciphertext)` pairs, e.g. from `lat_p2p::get_ring_candidates`), and the
    /// target `epoch` (of the block expected to include it). See
    /// [`create_anon_transfer`](Self::create_anon_transfer) for semantics.
    ///
    /// Decoy selection is a **uniform** sample of the candidates (self
    /// excluded), and the wallet's own position in the ring is uniform too.
    /// Uniform sampling is the documented baseline of `ANON_INTEGRATION.md` §7;
    /// resistance of this distribution to chain analysis is an open audit item.
    #[allow(clippy::too_many_arguments)]
    pub fn build_anon_transfer<R: rand::RngCore + rand::CryptoRng>(
        &self,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        my_balance_ct: &Ciphertext,
        candidates: &[([u8; 32], Ciphertext)],
        epoch: u64,
        ring_size: usize,
        rng: &mut R,
    ) -> Option<Transaction> {
        let my_id = self.id();
        let my_balance = self.secret.decrypt(my_balance_ct, BALANCE_BITS)?;
        if my_balance < amount.checked_add(fee)? {
            return None; // no valid solvency proof exists
        }

        // Uniform partial Fisher–Yates over the pool (self excluded), taking
        // ring_size − 1 decoys. Fewer available decoys shrink the ring (and the
        // anonymity); zero decoys means no ring at all.
        let mut pool: Vec<(PublicKey, Ciphertext)> = candidates
            .iter()
            .filter(|(id, _)| *id != my_id)
            .filter_map(|(id, ct)| PublicKey::from_bytes(id).map(|pk| (pk, *ct)))
            .collect();
        let want = ring_size.clamp(2, lat_chain::MAX_RING_SIZE) - 1;
        let take = want.min(pool.len());
        if take == 0 {
            return None;
        }
        for i in 0..take {
            let j = i + (rng.next_u64() as usize) % (pool.len() - i);
            pool.swap(i, j);
        }
        pool.truncate(take);

        // Insert ourselves at a uniform position.
        let sender_index = (rng.next_u64() as usize) % (take + 1);
        pool.insert(sender_index, (self.secret.public_key(), *my_balance_ct));
        let (ring, balances): (Vec<PublicKey>, Vec<Ciphertext>) = pool.into_iter().unzip();

        let xfer = AnonTransfer::create(
            &ring, &balances, &self.secret, sender_index, my_balance, &receiver.key, token,
            amount, fee, epoch, rng,
        )?;
        Some(Transaction::AnonTransfer { token, xfer })
    }

    /// Build a signed rollover transaction that merges this wallet's received
    /// (pending) funds into its spendable balance, at this wallet's current
    /// spend `nonce` (read it from the chain or over RPC).
    pub fn rollover_tx(&self, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::Rollover {
            account: self.id(),
            nonce,
            sig: [0u8; 64],
        })
    }

    /// Build a signed `Stake` (T13): bond `amount` public LAT into this
    /// account's validator stake. `amount = 0` claims matured unbonding funds.
    pub fn stake_tx(&self, amount: u64, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::Stake { validator: self.id(), amount, nonce, sig: [0u8; 64] })
    }

    /// Build a signed `Unstake` (T13): begin unbonding `amount` of this
    /// account's stake (released after the unbonding window).
    pub fn unstake_tx(&self, amount: u64, nonce: u64) -> Transaction {
        self.sign_tx(Transaction::Unstake { validator: self.id(), amount, nonce, sig: [0u8; 64] })
    }

    /// Build a solvent transfer from data fetched over RPC (balance ciphertext +
    /// spend nonce) rather than a local chain — for a networked wallet. Returns
    /// `None` if the balance can't be read or the amount isn't affordable.
    pub fn build_transfer<R: rand::RngCore + rand::CryptoRng>(
        &self,
        receiver: &Address,
        token: u32,
        amount: u64,
        fee: u64,
        balance_ct: &lat_crypto::Ciphertext,
        nonce: u64,
        rng: &mut R,
    ) -> Option<Transaction> {
        let current = self.secret.decrypt(balance_ct, BALANCE_BITS)?;
        let xfer = SolventTransfer::create(&self.secret, &receiver.key, token, amount, fee, current, balance_ct, nonce, rng)?;
        Some(Transaction::SolventTransfer { token, xfer })
    }

    /// Decrypt an arbitrary ciphertext with this wallet's key (e.g. a balance
    /// fetched over RPC). `None` if it isn't this wallet's, or is out of range.
    pub fn decrypt_ciphertext(&self, ct: &lat_crypto::Ciphertext) -> Option<u64> {
        self.secret.decrypt(ct, BALANCE_BITS)
    }

    /// Read and decrypt this wallet's PENDING (received, not yet rolled-over)
    /// balance of `token`.
    pub fn pending(&self, chain: &Blockchain, token: u32) -> Option<u64> {
        let ct = chain.pending(&self.id(), token)?;
        self.secret.decrypt(&ct, BALANCE_BITS)
    }

    /// Read and decrypt this wallet's balance of `token` from the chain. `None`
    /// if the account isn't registered or the balance exceeds the searched range.
    pub fn balance(&self, chain: &Blockchain, token: u32) -> Option<u64> {
        let ct = chain.balance(&self.id(), token)?;
        self.secret.decrypt(&ct, BALANCE_BITS)
    }

    /// Scan a block for transfers addressed to this wallet, returning the
    /// `(token, amount)` pairs received (decrypted locally with the secret key).
    pub fn scan_received(&self, block: &Block) -> Vec<(u32, u64)> {
        let me = self.secret.public_key();
        let my_id = self.id();
        let mut received = Vec::new();
        for tx in &block.txs {
            match tx {
                Transaction::SolventTransfer { token, xfer } if xfer.receiver == me => {
                    if let Some(amount) = self.secret.decrypt(&xfer.receiver_ciphertext(), BALANCE_BITS) {
                        received.push((*token, amount));
                    }
                }
                // Public transfers are in the clear — the amount needs no decrypt.
                Transaction::PublicTransfer { token, to, amount, .. } if *to == my_id => {
                    received.push((*token, *amount));
                }
                // Shield credits our private balance; the amount is public at
                // shield time, so it's read directly from the transaction.
                Transaction::Shield { token, to, amount, .. } if *to == my_id => {
                    received.push((*token, *amount));
                }
                // Unshield credits our public balance with a revealed amount.
                Transaction::Unshield { token, to, amount, .. } if *to == my_id => {
                    received.push((*token, *amount));
                }
                _ => {}
            }
        }
        received
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_chain::DEFAULT_DIFFICULTY;
    use rand::rngs::OsRng;

    #[test]
    fn seed_backup_restores_same_address() {
        let w = Wallet::generate(Network::Testnet, &mut OsRng);
        let restored = Wallet::from_seed_hex(Network::Testnet, &w.seed_hex()).unwrap();
        assert_eq!(w.address(), restored.address());
        assert_eq!(w.address_string(), restored.address_string());
    }

    #[test]
    fn address_has_network_prefix() {
        let main = Wallet::generate(Network::Mainnet, &mut OsRng);
        let test = Wallet::generate(Network::Testnet, &mut OsRng);
        assert!(main.address_string().starts_with("lat1"));
        assert!(test.address_string().starts_with("latt1"));
    }

    #[test]
    fn full_wallet_flow_over_the_chain() {
        let mut rng = OsRng;

        // The genesis wallet (premined) and a fresh receiver wallet.
        let genesis = Wallet::from_seed(Network::Testnet, [7u8; 32]);
        let receiver = Wallet::generate(Network::Testnet, &mut rng);

        const LAT: u32 = 0;
        let mut chain = Blockchain::genesis(&[(genesis.id(), 1_000_000)], DEFAULT_DIFFICULTY);
        assert_eq!(genesis.balance(&chain, LAT), Some(1_000_000));

        // Receiver registers (anti-spam PoW handled by the wallet).
        let block1 = chain.mine(vec![receiver.registration_tx()]);
        chain.apply_block(&block1).unwrap();

        // Genesis sends 250,000 with a solvency proof. It lands in the receiver's
        // pending pool; the genesis wallet is debited the amount plus the fee.
        let tx = genesis
            .create_solvent_transfer(&chain, &receiver.address(), LAT, 250_000, MIN_TRANSFER_FEE, &mut rng)
            .unwrap();
        let block2 = chain.mine(vec![tx]);
        chain.apply_block(&block2).unwrap();
        assert_eq!(genesis.balance(&chain, LAT), Some(750_000 - MIN_TRANSFER_FEE));
        assert_eq!(receiver.pending(&chain, LAT), Some(250_000));

        // The receiver discovers the incoming amount by scanning the block...
        assert_eq!(receiver.scan_received(&block2), vec![(LAT, 250_000)]);
        assert_eq!(genesis.scan_received(&block1), Vec::<(u32, u64)>::new());

        // ...then rolls it over into a spendable balance (at their nonce).
        let block3 = chain.mine(vec![receiver.rollover_tx(chain.nonce(&receiver.id()).unwrap())]);
        chain.apply_block(&block3).unwrap();
        assert_eq!(receiver.balance(&chain, LAT), Some(250_000));
    }

    #[test]
    fn public_transfer_flow_over_the_chain() {
        let mut rng = OsRng;
        let genesis = Wallet::from_seed(Network::Testnet, [7u8; 32]);
        let receiver = Wallet::generate(Network::Testnet, &mut rng);
        const LAT: u32 = 0;

        // Genesis holds a transparent public premine.
        let mut chain =
            Blockchain::genesis_with_public(&[], &[(genesis.id(), 1_000_000)], DEFAULT_DIFFICULTY);
        assert_eq!(genesis.public_balance(&chain, LAT), Some(1_000_000));

        // Receiver registers.
        let block1 = chain.mine(vec![receiver.registration_tx()]);
        chain.apply_block(&block1).unwrap();

        // Genesis builds + submits a fully public transfer of 250,000 LAT.
        let tx = genesis
            .create_public_transfer(&chain, &receiver.address(), LAT, 250_000, MIN_TRANSFER_FEE)
            .unwrap();
        let block2 = chain.mine(vec![tx]);
        chain.apply_block(&block2).unwrap();

        assert_eq!(genesis.public_balance(&chain, LAT), Some(1_000_000 - 250_000 - MIN_TRANSFER_FEE));
        assert_eq!(receiver.public_balance(&chain, LAT), Some(250_000));
        // Unlike a confidential transfer, the amount is immediately spendable and
        // in the clear — the receiver reads it as a plaintext receipt.
        assert_eq!(receiver.scan_received(&block2), vec![(LAT, 250_000)]);

        // Overspending yields no transaction (would fail consensus solvency).
        assert!(genesis
            .create_public_transfer(&chain, &receiver.address(), LAT, u64::MAX, MIN_TRANSFER_FEE)
            .is_none());
    }

    #[test]
    fn shield_then_unshield_round_trip() {
        let mut rng = OsRng;
        let user = Wallet::from_seed(Network::Testnet, [11u8; 32]);
        let dest = Wallet::generate(Network::Testnet, &mut rng);
        const LAT: u32 = 0;

        // User starts with public LAT; dest is registered.
        let mut chain =
            Blockchain::genesis_with_public(&[], &[(user.id(), 1_000_000)], DEFAULT_DIFFICULTY);
        let b1 = chain.mine(vec![dest.registration_tx()]);
        chain.apply_block(&b1).unwrap();

        // SHIELD 300,000 into the user's OWN private balance ("make my LAT private").
        let sh = user
            .create_shield(&chain, &user.address(), LAT, 300_000, MIN_TRANSFER_FEE)
            .unwrap();
        let b2 = chain.mine(vec![sh]);
        chain.apply_block(&b2).unwrap();
        assert_eq!(user.public_balance(&chain, LAT), Some(1_000_000 - 300_000 - MIN_TRANSFER_FEE));
        assert_eq!(user.pending(&chain, LAT), Some(300_000));

        // Roll pending → spendable, then UNSHIELD 100,000 to dest's public balance.
        let roll = user.rollover_tx(chain.nonce(&user.id()).unwrap());
        chain.apply_block(&chain.mine(vec![roll])).unwrap();
        assert_eq!(user.balance(&chain, LAT), Some(300_000));

        let un = user
            .create_unshield(&chain, &dest.address(), LAT, 100_000, MIN_TRANSFER_FEE, &mut rng)
            .unwrap();
        let b4 = chain.mine(vec![un]);
        chain.apply_block(&b4).unwrap();

        assert_eq!(dest.public_balance(&chain, LAT), Some(100_000));
        assert_eq!(user.balance(&chain, LAT), Some(300_000 - 100_000 - MIN_TRANSFER_FEE));
        // dest reads the unshield as a plaintext receipt when scanning the block.
        assert_eq!(dest.scan_received(&b4), vec![(LAT, 100_000)]);
    }

    #[test]
    fn anonymous_transfer_full_wallet_flow() {
        let mut rng = OsRng;
        const LAT: u32 = 0;

        // Five funded wallets form the decoy pool; wallet 2 will spend.
        let wallets: Vec<Wallet> = (0..5).map(|_| Wallet::generate(Network::Testnet, &mut rng)).collect();
        let alice = Wallet::generate(Network::Testnet, &mut rng); // receiver
        let premine: Vec<_> = wallets.iter().map(|w| (w.id(), 1_000_000u64)).collect();
        let mut chain = Blockchain::genesis(&premine, lat_chain::DEFAULT_DIFFICULTY);

        // Not enough decoys → no transaction (a ring of 1 hides nobody).
        let lonely_chain = Blockchain::genesis(&[(wallets[0].id(), 1_000_000)], lat_chain::DEFAULT_DIFFICULTY);
        assert!(wallets[0]
            .create_anon_transfer(&lonely_chain, &alice.address(), LAT, 1_000, MIN_TRANSFER_FEE, 4, &mut rng)
            .is_none());

        // Overspend → no transaction (no valid solvency proof exists).
        assert!(wallets[2]
            .create_anon_transfer(&chain, &alice.address(), LAT, u64::MAX - MIN_TRANSFER_FEE, MIN_TRANSFER_FEE, 4, &mut rng)
            .is_none());

        // Wallet 2 sends 50,000 anonymously, hiding among 3 decoys.
        let tx = wallets[2]
            .create_anon_transfer(&chain, &alice.address(), LAT, 50_000, MIN_TRANSFER_FEE, 4, &mut rng)
            .expect("builds");
        if let Transaction::AnonTransfer { xfer, .. } = &tx {
            assert_eq!(xfer.ring.len(), 4, "self + 3 decoys");
            assert_eq!(xfer.epoch, lat_chain::epoch_of(chain.height() + 1));
        } else {
            panic!("wrong variant");
        }
        let block = chain.mine(vec![tx]);
        chain.apply_block(&block).unwrap();

        // The spender lost amount + fee; every other wallet is untouched.
        assert_eq!(wallets[2].balance(&chain, LAT), Some(1_000_000 - 50_000 - MIN_TRANSFER_FEE));
        for w in [&wallets[0], &wallets[1], &wallets[3], &wallets[4]] {
            assert_eq!(w.balance(&chain, LAT), Some(1_000_000));
        }

        // Nobody but Alice detects the payment; she scans, claims the one-time
        // account, rolls it over, and can spend.
        assert!(wallets[0].scan_stealth(&block).is_empty());
        let receipts = alice.scan_stealth(&block);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].amount, 50_000);
        let one_time = Wallet::from_secret(Network::Testnet, receipts[0].secret.clone());
        assert_eq!(one_time.id(), receipts[0].one_time);
        let roll = one_time.rollover_tx(chain.nonce(&one_time.id()).unwrap());
        chain.apply_block(&chain.mine(vec![roll])).unwrap();
        assert_eq!(one_time.balance(&chain, LAT), Some(50_000));

        // A second anonymous spend by the same wallet in the same epoch can be
        // BUILT (the wallet doesn't know its nullifier is burned) but is
        // consensus-rejected — the miner's filter drops it.
        let again = wallets[2]
            .create_anon_transfer(&chain, &alice.address(), LAT, 1_000, MIN_TRANSFER_FEE, 4, &mut rng)
            .expect("builds against current balances");
        assert!(chain.select_valid(vec![again]).is_empty(), "same-epoch respend filtered");
    }

    #[test]
    fn stealth_shield_hides_recipient_yet_recipient_can_claim() {
        let mut rng = OsRng;
        let bob = Wallet::from_seed(Network::Testnet, [21u8; 32]); // holds public LAT
        let alice = Wallet::generate(Network::Testnet, &mut rng);
        let carol = Wallet::generate(Network::Testnet, &mut rng); // unrelated observer
        const LAT: u32 = 0;

        let mut chain =
            Blockchain::genesis_with_public(&[], &[(bob.id(), 1_000_000)], DEFAULT_DIFFICULTY);

        // Bob stealth-shields 300,000 to Alice — the tx never names Alice.
        let tx = bob
            .create_shield_stealth(&chain, &alice.address(), LAT, 300_000, MIN_TRANSFER_FEE, &mut rng)
            .unwrap();
        let b1 = chain.mine(vec![tx]);
        chain.apply_block(&b1).unwrap();
        assert_eq!(bob.public_balance(&chain, LAT), Some(1_000_000 - 300_000 - MIN_TRANSFER_FEE));

        // An unrelated observer scanning the block finds nothing addressed to them.
        assert!(carol.scan_stealth(&b1).is_empty(), "recipient must be unlinkable");

        // Alice scans, detects her stealth output, and derives its one-time key.
        let receipts = alice.scan_stealth(&b1);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].amount, 300_000);

        // Alice controls the one-time account and claims it (roll pending → spendable).
        let one_time = Wallet::from_secret(Network::Testnet, receipts[0].secret.clone());
        assert_eq!(one_time.id(), receipts[0].one_time, "derived key opens the account");
        let roll = one_time.rollover_tx(chain.nonce(&one_time.id()).unwrap());
        chain.apply_block(&chain.mine(vec![roll])).unwrap();
        assert_eq!(one_time.balance(&chain, LAT), Some(300_000));
    }
}
