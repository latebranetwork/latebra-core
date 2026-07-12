//! Latebra core types: networks, addresses, and transactions.
//!
//! Clean-room, written from `SPEC.md`. Addresses are Bech32m-encoded public keys
//! with human-readable prefixes `lat` (mainnet) / `latt` (testnet).

use bech32::{Bech32m, Hrp};
use lat_crypto::{AnonTransfer, PublicKey, SolventTransfer};

/// Which network an address / transaction belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Bech32 human-readable prefix.
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "lat",
            Network::Testnet => "latt",
        }
    }

    fn from_hrp(hrp: &str) -> Option<Network> {
        match hrp {
            "lat" => Some(Network::Mainnet),
            "latt" => Some(Network::Testnet),
            _ => None,
        }
    }
}

/// A Latebra account address — a public key plus the network it belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    pub network: Network,
    pub key: PublicKey,
}

/// Errors parsing an address string.
#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    Bech32,
    UnknownPrefix,
    BadLength,
    BadKey,
}

impl Address {
    pub fn new(network: Network, key: PublicKey) -> Self {
        Address { network, key }
    }

    /// The 32-byte account id (compressed public key) used as the state-tree key.
    pub fn id(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Encode as a Bech32m string, e.g. `latt1...` (testnet) / `lat1...` (mainnet).
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse(self.network.hrp()).expect("static hrp is valid");
        bech32::encode::<Bech32m>(hrp, &self.key.to_bytes()).expect("encoding cannot fail")
    }

    /// Parse a Bech32m address string back into an `Address`.
    pub fn parse(s: &str) -> Result<Address, AddressError> {
        let (hrp, data) = bech32::decode(s).map_err(|_| AddressError::Bech32)?;
        let network = Network::from_hrp(hrp.as_str()).ok_or(AddressError::UnknownPrefix)?;
        let bytes: [u8; 32] = data.try_into().map_err(|_| AddressError::BadLength)?;
        let key = PublicKey::from_bytes(&bytes).ok_or(AddressError::BadKey)?;
        Ok(Address { network, key })
    }
}

/// A Latebra transaction.
///
/// `Register` adds an account to the state (required before it can receive or
/// spend). A real chain gates this with a tiny anti-spam proof-of-work — carried
/// forward as a design lesson, wired in at the consensus layer (M3), where the
/// wallet, mempool, and block-verify PoW targets MUST stay identical.
///
/// * `Register` adds an account (anti-spam PoW gated at the consensus layer).
/// * `CreateToken` mints a new token under a globally-unique ticker.
/// * `Transfer` is a confidential value transfer of one token, with its proof.
///
/// ## Authentication
/// The confidential transfers prove account ownership inside their Σ-proof. The
/// transparent types (`CreateToken`, `Rollover`, `DeployContract`,
/// `CallContract`) instead carry a Schnorr signature by the named account key
/// over [`signing_bytes`](Transaction::signing_bytes), so nobody can spoof a
/// creator/caller or grief another account. `Rollover` and `CallContract` also
/// bind the account's spend nonce (replay protection); `CreateToken` and
/// `DeployContract` are naturally replay-proof (duplicate ticker/contract-id
/// is rejected).
#[derive(Clone)]
pub enum Transaction {
    Register {
        pubkey: [u8; 32],
        pow_nonce: u64,
    },
    CreateToken {
        ticker: String,
        creator: [u8; 32],
        supply: u64,
        /// Schnorr signature by `creator` over the signing bytes.
        sig: [u8; 64],
    },
    /// The confidential transfer: proves value conservation AND that the sender
    /// is solvent (no overspend of a hidden balance). The only confidential
    /// transfer type — an earlier `Transfer` that skipped the solvency proof was
    /// removed (wire tag `0x01` is retired and rejected on decode).
    SolventTransfer {
        token: u32,
        xfer: SolventTransfer,
    },
    /// Merge an account's received (pending) funds into its spendable balance.
    /// Signed + nonce-bound: an attacker must not be able to force a rollover,
    /// since changing the spendable balance invalidates the account's own
    /// in-flight solvency proofs.
    Rollover {
        account: [u8; 32],
        /// The account's current spend nonce (replay protection).
        nonce: u64,
        /// Schnorr signature by `account` over the signing bytes.
        sig: [u8; 64],
    },
    /// Deploy a smart-contract bytecode program. Its address is derived from the
    /// deployer and the code.
    DeployContract {
        deployer: [u8; 32],
        code: Vec<u8>,
        /// Schnorr signature by `deployer` over the signing bytes.
        sig: [u8; 64],
    },
    /// Call a deployed contract with an input word, running its bytecode and
    /// updating its storage.
    CallContract {
        contract: [u8; 32],
        caller: [u8; 32],
        input: u64,
        /// The caller's current spend nonce (replay protection).
        nonce: u64,
        /// Schnorr signature by `caller` over the signing bytes.
        sig: [u8; 64],
    },
    /// A fully transparent transfer of the account's **public** (plaintext)
    /// balance: sender, receiver, and amount are all visible on-chain — the
    /// public half of Latebra's dual-state model (see `PRIVACY_ARCHITECTURE.md`).
    /// Schnorr-signed by `from` and nonce-bound for replay protection, exactly
    /// like the other transparent types.
    PublicTransfer {
        token: u32,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        /// Public fee paid to the block's miner (into the miner's public balance).
        fee: u64,
        /// The sender's current spend nonce (replay protection).
        nonce: u64,
        /// Schnorr signature by `from` over the signing bytes.
        sig: [u8; 64],
    },
    /// **Shield** (public → private): move `amount` out of `from`'s transparent
    /// public balance and into `to`'s confidential balance. The amount is public
    /// (it leaves the public ledger in the clear); the recipient is named in the
    /// clear too (hiding it is the Phase-3 unlinkability step). Same transparent
    /// auth as `PublicTransfer`: Schnorr-signed by `from`, nonce-bound.
    Shield {
        token: u32,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        /// Public fee paid to the miner (from `from`'s public balance).
        fee: u64,
        nonce: u64,
        /// Schnorr signature by `from` over the signing bytes.
        sig: [u8; 64],
    },
    /// **Unshield** (private → public): a confidential `SolventTransfer` whose
    /// receiver is the publicly-known unshield view key, so `amount` is revealed
    /// as it re-enters `to`'s transparent public balance. The proof still hides
    /// nothing but confirms the sender was solvent for exactly `amount + fee`.
    /// `sig` is a Schnorr signature by the (revealed) sender binding `to`/`amount`
    /// so the destination can't be malleated.
    Unshield {
        token: u32,
        to: [u8; 32],
        amount: u64,
        xfer: SolventTransfer,
        sig: [u8; 64],
    },
    /// **Stealth shield** (public → private, recipient hidden): like `Shield`, but
    /// instead of naming the recipient it credits a fresh *one-time* account
    /// `one_time`, derived by the sender from an `ephemeral` key and the
    /// recipient's address. Observers can't link `one_time` to the recipient; only
    /// the recipient can detect it and derive its spend key (see
    /// `lat_crypto::stealth_send`/`stealth_receive`). Transparent auth by `from`.
    ShieldStealth {
        token: u32,
        from: [u8; 32],
        /// The sender's ephemeral public key `R` (recipient needs it to scan).
        ephemeral: [u8; 32],
        /// The one-time account `P` credited (an ordinary account key on-chain).
        one_time: [u8; 32],
        amount: u64,
        fee: u64,
        nonce: u64,
        /// Schnorr signature by `from` over the signing bytes.
        sig: [u8; 64],
    },
    /// **Anonymous transfer** (private → private, sender AND receiver hidden):
    /// the sender hides inside a public ring of accounts, every ring member's
    /// balance is homomorphically debited (the real sender by `amount + fee`,
    /// decoys by an encryption of 0), and the receiver is a one-time stealth
    /// account. The amount and fee stay **public** (hiding them is a later
    /// phase). Authenticated *inside* the proof (ownership of a ring member);
    /// replay-protected by an epoch nullifier tracked in the ledger — no
    /// account nonce, since the sender's identity is secret.
    AnonTransfer {
        token: u32,
        xfer: AnonTransfer,
    },
    /// **Stake** (T13): bond `amount` LAT from `validator`'s transparent public
    /// balance into its validator stake — the weight the BFT-PoS validator set
    /// is derived from. `amount = 0` is a valid no-op bond used to sweep any
    /// matured unbonding entries back into the public balance. Transparent
    /// auth: Schnorr-signed by `validator`, nonce-bound.
    Stake {
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
        /// Schnorr signature by `validator` over the signing bytes.
        sig: [u8; 64],
    },
    /// **Unstake** (T13): move `amount` from `validator`'s bonded stake into an
    /// unbonding entry that releases back to the public balance after the
    /// unbonding window (`lat_state::UNBONDING_BLOCKS`) — the delay is what
    /// makes long-range-attack slashing possible later (T16). Same auth as
    /// `Stake`.
    Unstake {
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
        /// Schnorr signature by `validator` over the signing bytes.
        sig: [u8; 64],
    },
    /// **Slash evidence** (T16, partial slashing since Gap-6): proof that
    /// `validator` equivocated — signed finality votes for TWO different blocks
    /// at the same height. The evidence is self-authenticating (both signatures
    /// verify against [`finality_vote_signing_bytes`]), so the transaction
    /// itself needs no signature or nonce: anyone may submit it. The penalty
    /// slashes a fraction of the offender's bonded + unbonding stake; a portion
    /// of the slashed amount is paid to `beneficiary` (the whistleblower's
    /// public account) as a reward, the rest is burned. Because the reward
    /// makes the tx no longer idempotent in whose favor it lands, the
    /// beneficiary is bound into the encoding (and thus the tx id). Replays
    /// find nothing left to slash and are rejected.
    SlashEvidence {
        validator: [u8; 32],
        beneficiary: [u8; 32],
        height: u64,
        block_a: [u8; 32],
        sig_a: [u8; 64],
        block_b: [u8; 32],
        sig_b: [u8; 64],
    },
}

impl Transaction {
    /// Canonical byte encoding, used to derive transaction ids and block roots.
    /// A leading tag byte distinguishes the variants.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Transaction::Register { pubkey, pow_nonce } => {
                let mut v = Vec::with_capacity(1 + 32 + 8);
                v.push(0x00);
                v.extend_from_slice(pubkey);
                v.extend_from_slice(&pow_nonce.to_le_bytes());
                v
            }
            Transaction::CreateToken {
                ticker,
                creator,
                supply,
                sig,
            } => {
                let t = ticker.as_bytes();
                let mut v = Vec::with_capacity(1 + 2 + t.len() + 32 + 8 + 64);
                v.push(0x02);
                v.extend_from_slice(&(t.len() as u16).to_le_bytes());
                v.extend_from_slice(t);
                v.extend_from_slice(creator);
                v.extend_from_slice(&supply.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::SolventTransfer { token, xfer } => {
                let mut v = Vec::with_capacity(1 + 4 + 700);
                v.push(0x03);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(&xfer.to_bytes());
                v
            }
            Transaction::Rollover { account, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 32 + 8 + 64);
                v.push(0x04);
                v.extend_from_slice(account);
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::DeployContract { deployer, code, sig } => {
                let mut v = Vec::with_capacity(1 + 32 + 4 + code.len() + 64);
                v.push(0x05);
                v.extend_from_slice(deployer);
                v.extend_from_slice(&(code.len() as u32).to_le_bytes());
                v.extend_from_slice(code);
                v.extend_from_slice(sig);
                v
            }
            Transaction::PublicTransfer { token, from, to, amount, fee, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 4 + 32 + 32 + 8 + 8 + 8 + 64);
                v.push(0x07);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(from);
                v.extend_from_slice(to);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&fee.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::Shield { token, from, to, amount, fee, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 4 + 32 + 32 + 8 + 8 + 8 + 64);
                v.push(0x08);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(from);
                v.extend_from_slice(to);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&fee.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::Unshield { token, to, amount, xfer, sig } => {
                let x = xfer.to_bytes();
                let mut v = Vec::with_capacity(1 + 4 + 32 + 8 + 4 + x.len() + 64);
                v.push(0x09);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(to);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&(x.len() as u32).to_le_bytes());
                v.extend_from_slice(&x);
                v.extend_from_slice(sig);
                v
            }
            Transaction::ShieldStealth { token, from, ephemeral, one_time, amount, fee, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 4 + 32 + 32 + 32 + 8 + 8 + 8 + 64);
                v.push(0x0A);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(from);
                v.extend_from_slice(ephemeral);
                v.extend_from_slice(one_time);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&fee.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::AnonTransfer { token, xfer } => {
                let x = xfer.to_bytes();
                let mut v = Vec::with_capacity(1 + 4 + 4 + x.len());
                v.push(0x0B);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(&(x.len() as u32).to_le_bytes());
                v.extend_from_slice(&x);
                v
            }
            Transaction::CallContract { contract, caller, input, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 32 + 32 + 8 + 8 + 64);
                v.push(0x06);
                v.extend_from_slice(contract);
                v.extend_from_slice(caller);
                v.extend_from_slice(&input.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::Stake { validator, amount, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 32 + 8 + 8 + 64);
                v.push(0x0C);
                v.extend_from_slice(validator);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::Unstake { validator, amount, nonce, sig } => {
                let mut v = Vec::with_capacity(1 + 32 + 8 + 8 + 64);
                v.push(0x0D);
                v.extend_from_slice(validator);
                v.extend_from_slice(&amount.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(sig);
                v
            }
            Transaction::SlashEvidence { validator, beneficiary, height, block_a, sig_a, block_b, sig_b } => {
                let mut v = Vec::with_capacity(1 + 32 + 32 + 8 + 32 + 64 + 32 + 64);
                v.push(0x0E);
                v.extend_from_slice(validator);
                v.extend_from_slice(beneficiary);
                v.extend_from_slice(&height.to_le_bytes());
                v.extend_from_slice(block_a);
                v.extend_from_slice(sig_a);
                v.extend_from_slice(block_b);
                v.extend_from_slice(sig_b);
                v
            }
        }
    }

    /// The bytes a signed transaction's Schnorr signature covers: the canonical
    /// encoding with the trailing 64-byte signature omitted. (For the variants
    /// that carry no signature this is the full encoding.)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = self.encode();
        if matches!(
            self,
            Transaction::CreateToken { .. }
                | Transaction::Rollover { .. }
                | Transaction::DeployContract { .. }
                | Transaction::CallContract { .. }
                | Transaction::PublicTransfer { .. }
                | Transaction::Shield { .. }
                | Transaction::Unshield { .. }
                | Transaction::ShieldStealth { .. }
                | Transaction::Stake { .. }
                | Transaction::Unstake { .. }
        ) {
            v.truncate(v.len() - 64);
        }
        v
    }
}

impl Transaction {
    /// Decode a transaction from its canonical encoding (inverse of [`encode`]).
    /// Returns `None` on malformed input.
    pub fn decode(b: &[u8]) -> Option<Transaction> {
        let (&tag, rest) = b.split_first()?;
        match tag {
            0x00 => {
                if rest.len() != 32 + 8 {
                    return None;
                }
                let pubkey: [u8; 32] = rest[0..32].try_into().ok()?;
                let pow_nonce = u64::from_le_bytes(rest[32..40].try_into().ok()?);
                Some(Transaction::Register { pubkey, pow_nonce })
            }
            // 0x01 (legacy unsound `Transfer`) is retired — decoding it fails.
            0x02 => {
                let len = u16::from_le_bytes(rest.get(0..2)?.try_into().ok()?) as usize;
                let ticker = String::from_utf8(rest.get(2..2 + len)?.to_vec()).ok()?;
                let creator: [u8; 32] = rest.get(2 + len..2 + len + 32)?.try_into().ok()?;
                let supply = u64::from_le_bytes(rest.get(2 + len + 32..2 + len + 40)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(2 + len + 40..2 + len + 104)?.try_into().ok()?;
                if rest.len() != 2 + len + 104 {
                    return None; // no trailing garbage
                }
                Some(Transaction::CreateToken { ticker, creator, supply, sig })
            }
            0x03 => {
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let xfer = SolventTransfer::from_bytes(rest.get(4..)?)?;
                Some(Transaction::SolventTransfer { token, xfer })
            }
            0x04 => {
                if rest.len() != 32 + 8 + 64 {
                    return None;
                }
                let account: [u8; 32] = rest[0..32].try_into().ok()?;
                let nonce = u64::from_le_bytes(rest[32..40].try_into().ok()?);
                let sig: [u8; 64] = rest[40..104].try_into().ok()?;
                Some(Transaction::Rollover { account, nonce, sig })
            }
            0x05 => {
                let deployer: [u8; 32] = rest.get(0..32)?.try_into().ok()?;
                let len = u32::from_le_bytes(rest.get(32..36)?.try_into().ok()?) as usize;
                let code = rest.get(36..36 + len)?.to_vec();
                let sig: [u8; 64] = rest.get(36 + len..36 + len + 64)?.try_into().ok()?;
                if rest.len() != 36 + len + 64 {
                    return None; // no trailing garbage
                }
                Some(Transaction::DeployContract { deployer, code, sig })
            }
            0x06 => {
                if rest.len() != 144 {
                    return None;
                }
                let contract: [u8; 32] = rest.get(0..32)?.try_into().ok()?;
                let caller: [u8; 32] = rest.get(32..64)?.try_into().ok()?;
                let input = u64::from_le_bytes(rest.get(64..72)?.try_into().ok()?);
                let nonce = u64::from_le_bytes(rest.get(72..80)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(80..144)?.try_into().ok()?;
                Some(Transaction::CallContract { contract, caller, input, nonce, sig })
            }
            0x07 => {
                if rest.len() != 4 + 32 + 32 + 8 + 8 + 8 + 64 {
                    return None;
                }
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let from: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let to: [u8; 32] = rest.get(36..68)?.try_into().ok()?;
                let amount = u64::from_le_bytes(rest.get(68..76)?.try_into().ok()?);
                let fee = u64::from_le_bytes(rest.get(76..84)?.try_into().ok()?);
                let nonce = u64::from_le_bytes(rest.get(84..92)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(92..156)?.try_into().ok()?;
                Some(Transaction::PublicTransfer { token, from, to, amount, fee, nonce, sig })
            }
            0x08 => {
                if rest.len() != 4 + 32 + 32 + 8 + 8 + 8 + 64 {
                    return None;
                }
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let from: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let to: [u8; 32] = rest.get(36..68)?.try_into().ok()?;
                let amount = u64::from_le_bytes(rest.get(68..76)?.try_into().ok()?);
                let fee = u64::from_le_bytes(rest.get(76..84)?.try_into().ok()?);
                let nonce = u64::from_le_bytes(rest.get(84..92)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(92..156)?.try_into().ok()?;
                Some(Transaction::Shield { token, from, to, amount, fee, nonce, sig })
            }
            0x09 => {
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let to: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let amount = u64::from_le_bytes(rest.get(36..44)?.try_into().ok()?);
                let xlen = u32::from_le_bytes(rest.get(44..48)?.try_into().ok()?) as usize;
                let xfer = SolventTransfer::from_bytes(rest.get(48..48 + xlen)?)?;
                let sig: [u8; 64] = rest.get(48 + xlen..48 + xlen + 64)?.try_into().ok()?;
                if rest.len() != 48 + xlen + 64 {
                    return None; // no trailing garbage
                }
                Some(Transaction::Unshield { token, to, amount, xfer, sig })
            }
            0x0A => {
                if rest.len() != 4 + 32 + 32 + 32 + 8 + 8 + 8 + 64 {
                    return None;
                }
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let from: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let ephemeral: [u8; 32] = rest.get(36..68)?.try_into().ok()?;
                let one_time: [u8; 32] = rest.get(68..100)?.try_into().ok()?;
                let amount = u64::from_le_bytes(rest.get(100..108)?.try_into().ok()?);
                let fee = u64::from_le_bytes(rest.get(108..116)?.try_into().ok()?);
                let nonce = u64::from_le_bytes(rest.get(116..124)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(124..188)?.try_into().ok()?;
                Some(Transaction::ShieldStealth { token, from, ephemeral, one_time, amount, fee, nonce, sig })
            }
            0x0B => {
                let token = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let xlen = u32::from_le_bytes(rest.get(4..8)?.try_into().ok()?) as usize;
                let xfer = AnonTransfer::from_bytes(rest.get(8..8 + xlen)?)?;
                if rest.len() != 8 + xlen {
                    return None; // no trailing garbage
                }
                Some(Transaction::AnonTransfer { token, xfer })
            }
            0x0C | 0x0D => {
                if rest.len() != 32 + 8 + 8 + 64 {
                    return None;
                }
                let validator: [u8; 32] = rest.get(0..32)?.try_into().ok()?;
                let amount = u64::from_le_bytes(rest.get(32..40)?.try_into().ok()?);
                let nonce = u64::from_le_bytes(rest.get(40..48)?.try_into().ok()?);
                let sig: [u8; 64] = rest.get(48..112)?.try_into().ok()?;
                Some(if tag == 0x0C {
                    Transaction::Stake { validator, amount, nonce, sig }
                } else {
                    Transaction::Unstake { validator, amount, nonce, sig }
                })
            }
            0x0E => {
                if rest.len() != 32 + 32 + 8 + 32 + 64 + 32 + 64 {
                    return None;
                }
                Some(Transaction::SlashEvidence {
                    validator: rest.get(0..32)?.try_into().ok()?,
                    beneficiary: rest.get(32..64)?.try_into().ok()?,
                    height: u64::from_le_bytes(rest.get(64..72)?.try_into().ok()?),
                    block_a: rest.get(72..104)?.try_into().ok()?,
                    sig_a: rest.get(104..168)?.try_into().ok()?,
                    block_b: rest.get(168..200)?.try_into().ok()?,
                    sig_b: rest.get(200..264)?.try_into().ok()?,
                })
            }
            _ => None,
        }
    }
}

/// The bytes a T14 finality vote signs: domain ‖ block id ‖ height. Lives here
/// (not lat-chain) so the ledger can verify [`Transaction::SlashEvidence`]
/// without a dependency cycle — the chain's finality module reuses it.
pub fn finality_vote_signing_bytes(block_id: &[u8; 32], height: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + 32 + 8);
    v.extend_from_slice(b"LAT-finality-v1\0");
    v.extend_from_slice(block_id);
    v.extend_from_slice(&height.to_le_bytes());
    v
}

/// Normalize a ticker to its canonical form: strip a leading `$`, uppercase, and
/// require 1–10 ASCII alphanumeric characters. Returns `None` if invalid. This is
/// what makes `$doge`, `DOGE`, and `Doge` the *same* ticker for uniqueness.
pub fn normalize_ticker(input: &str) -> Option<String> {
    let s = input.trim().strip_prefix('$').unwrap_or(input.trim());
    if s.is_empty() || s.len() > 10 || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(s.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_crypto::SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn address_roundtrip_testnet() {
        let key = SecretKey::random(&mut OsRng).public_key();
        let addr = Address::new(Network::Testnet, key);
        let s = addr.encode();
        assert!(s.starts_with("latt1"), "got {s}");
        assert_eq!(Address::parse(&s), Ok(addr));
    }

    #[test]
    fn address_roundtrip_mainnet() {
        let key = SecretKey::random(&mut OsRng).public_key();
        let addr = Address::new(Network::Mainnet, key);
        let s = addr.encode();
        assert!(s.starts_with("lat1"), "got {s}");
        assert_eq!(Address::parse(&s), Ok(addr));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Address::parse("not-an-address").is_err());
    }

    #[test]
    fn public_transfer_encoding_roundtrips() {
        let tx = Transaction::PublicTransfer {
            token: 7,
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 12_345,
            fee: 1_000,
            nonce: 9,
            sig: [3u8; 64],
        };
        let bytes = tx.encode();
        assert_eq!(bytes[0], 0x07, "tag byte");
        assert_eq!(bytes.len(), 1 + 4 + 32 + 32 + 8 + 8 + 8 + 64);
        // decode(encode(tx)) reproduces the same canonical bytes.
        let decoded = Transaction::decode(&bytes).expect("decodes");
        assert_eq!(decoded.encode(), bytes, "roundtrip");
        // The signature covers everything but the trailing 64-byte sig.
        assert_eq!(tx.signing_bytes(), bytes[..bytes.len() - 64].to_vec());
        // Decoding is total: trailing garbage and truncation are both rejected.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Transaction::decode(&extra).is_none(), "trailing garbage rejected");
        assert!(Transaction::decode(&bytes[..bytes.len() - 1]).is_none(), "truncation rejected");
    }

    #[test]
    fn stake_and_unstake_encoding_roundtrip() {
        for (tag, tx) in [
            (0x0Cu8, Transaction::Stake { validator: [5u8; 32], amount: 777, nonce: 3, sig: [9u8; 64] }),
            (0x0D, Transaction::Unstake { validator: [5u8; 32], amount: 777, nonce: 3, sig: [9u8; 64] }),
        ] {
            let bytes = tx.encode();
            assert_eq!(bytes[0], tag, "tag byte");
            assert_eq!(bytes.len(), 1 + 32 + 8 + 8 + 64);
            let decoded = Transaction::decode(&bytes).expect("decodes");
            assert_eq!(decoded.encode(), bytes, "roundtrip");
            assert_eq!(tx.signing_bytes(), bytes[..bytes.len() - 64].to_vec());
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(Transaction::decode(&extra).is_none(), "trailing garbage rejected");
            assert!(Transaction::decode(&bytes[..bytes.len() - 1]).is_none(), "truncation rejected");
        }
    }

    #[test]
    fn shield_and_unshield_encoding_roundtrip() {
        let mut rng = OsRng;

        // Shield shares PublicTransfer's fixed layout (tag 0x08).
        let shield = Transaction::Shield {
            token: 3, from: [1u8; 32], to: [2u8; 32], amount: 9, fee: 1_000, nonce: 4, sig: [7u8; 64],
        };
        let sb = shield.encode();
        assert_eq!(sb[0], 0x08);
        assert_eq!(Transaction::decode(&sb).unwrap().encode(), sb, "shield roundtrips");
        assert_eq!(shield.signing_bytes(), sb[..sb.len() - 64].to_vec());

        // Unshield carries a real (variable-length) SolventTransfer (tag 0x09).
        let sk = SecretKey::random(&mut rng);
        let bal = sk.public_key().encrypt(1_000, &mut rng);
        let xfer = lat_crypto::SolventTransfer::create(
            &sk, &lat_crypto::unshield_view_key(), 400, 100, 1_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let unshield = Transaction::Unshield { token: 0, to: [5u8; 32], amount: 400, xfer, sig: [9u8; 64] };
        let ub = unshield.encode();
        assert_eq!(ub[0], 0x09);
        assert_eq!(Transaction::decode(&ub).expect("decodes").encode(), ub, "unshield roundtrips");
        assert_eq!(unshield.signing_bytes(), ub[..ub.len() - 64].to_vec());
        let mut extra = ub.clone();
        extra.push(0);
        assert!(Transaction::decode(&extra).is_none(), "trailing garbage rejected");
    }

    #[test]
    fn anon_transfer_encoding_roundtrip() {
        let mut rng = OsRng;
        let sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::random(&mut rng)).collect();
        let ring: Vec<_> = sks.iter().map(|s| s.public_key()).collect();
        let balances: Vec<_> = sks
            .iter()
            .map(|s| s.public_key().encrypt(50_000, &mut rng))
            .collect();
        let receiver = SecretKey::random(&mut rng);
        let xfer = lat_crypto::AnonTransfer::create(
            &ring, &balances, &sks[1], 1, 50_000, &receiver.public_key(), 1_000, 100, 3, &mut rng,
        )
        .expect("solvent");

        let tx = Transaction::AnonTransfer { token: 0, xfer };
        let bytes = tx.encode();
        assert_eq!(bytes[0], 0x0B, "tag byte");
        let decoded = Transaction::decode(&bytes).expect("decodes");
        assert_eq!(decoded.encode(), bytes, "roundtrip");
        // No signature field: the proof itself authenticates, so signing bytes
        // are the full encoding.
        assert_eq!(tx.signing_bytes(), bytes);
        // The decoded proof is still valid and carries the same nullifier.
        if let (Transaction::AnonTransfer { xfer: a, .. }, Transaction::AnonTransfer { xfer: b, .. }) =
            (&tx, &decoded)
        {
            assert!(b.verify());
            assert_eq!(a.nullifier(), b.nullifier());
        } else {
            panic!("decoded to a different variant");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Transaction::decode(&extra).is_none(), "trailing garbage rejected");
        assert!(Transaction::decode(&bytes[..bytes.len() - 1]).is_none(), "truncation rejected");
    }

    #[test]
    fn shield_stealth_encoding_roundtrip() {
        let tx = Transaction::ShieldStealth {
            token: 2,
            from: [1u8; 32],
            ephemeral: [2u8; 32],
            one_time: [3u8; 32],
            amount: 55_555,
            fee: 1_000,
            nonce: 6,
            sig: [4u8; 64],
        };
        let b = tx.encode();
        assert_eq!(b[0], 0x0A);
        assert_eq!(b.len(), 1 + 4 + 32 + 32 + 32 + 8 + 8 + 8 + 64);
        assert_eq!(Transaction::decode(&b).unwrap().encode(), b, "roundtrips");
        assert_eq!(tx.signing_bytes(), b[..b.len() - 64].to_vec());
        let mut extra = b.clone();
        extra.push(0);
        assert!(Transaction::decode(&extra).is_none(), "trailing garbage rejected");
    }
}
