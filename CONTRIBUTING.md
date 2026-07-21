# Contributing to Latebra

Thanks for looking. Latebra is a privacy-first proof-of-work chain in Rust, and
contributions are welcome — especially review of the cryptography and consensus,
which is where the risk lives.

**Found a security bug? Do not open an issue.** Follow
[SECURITY.md](SECURITY.md) instead.

## Getting set up

```sh
git clone https://github.com/latebranetwork/latebra-core
cd latebra-core
cargo build --release      # always release: the curve math is ~15x slower unoptimised
cargo test --workspace --exclude latfun
```

[INSTALL.md](INSTALL.md) covers running a node from a prebuilt binary;
[TESTNET.md](TESTNET.md) covers running one from source and joining a network.

## Before you open a pull request

CI runs exactly these two commands, and a red build will not be merged:

```sh
cargo clippy --workspace --exclude latfun --all-targets -- \
  -A clippy::type-complexity -A clippy::too-many-arguments -D warnings
cargo test --workspace --exclude latfun
```

Run them locally first. `latfun` is excluded because it can hold file locks and
is exercised by its own repo's flows.

**rustfmt is deliberately not enforced.** The codebase predates a fmt pass and
reformatting ~18k LOC before the external audit would destroy `git blame`.
Match the style of the file you are editing; do not reformat untouched code.

## What makes a good change here

- **One concern per pull request.** A consensus fix and a refactor in the same
  diff is hard to review and harder to audit later.
- **Explain the why in the commit message, not the what.** The diff already says
  what changed. Reviewers need to know why it is correct.
- **Tests for behaviour, not coverage.** Anything touching `lat-crypto`,
  `lat-state` or `lat-chain` should come with a test that fails without the
  change. Consensus code without a test will be asked for one.
- **Comments explain constraints**, not narration. If a line looks wrong but is
  right, say why.

## Consensus changes

Anything altering state transitions, block validation, proof-of-work,
fork-choice, or the wire format is **consensus-breaking**: nodes on the old code
will reject the new blocks and the network splits. These changes need the
reasoning spelled out in the PR, and they usually mean a testnet reset. Flag
them explicitly — do not slip one in alongside unrelated work.

The same applies to the transaction encoding in `lat-types` and the P2P protocol
version in `lat-p2p`: peers compare protocol version and genesis id at the
handshake and drop each other on a mismatch.

## Cryptography changes

Held to a higher bar, and reviewed slowest — this is the part no test suite can
fully vouch for.

- Do not invent constructions. Cite the paper or the reference implementation.
- Do not add a dependency to `lat-crypto` without saying why an existing one
  cannot do it. Everything in the tree is permissively licensed (MIT/Apache/BSD)
  and that must stay true — see [Licence](#licence).
- Constant-time where secrets are involved; say so in the comment.
- If a change alters what is public on-chain, update
  [CRYPTO_SPEC.md](CRYPTO_SPEC.md) and [THREAT_MODEL.md](THREAT_MODEL.md) in the
  same PR. The docs claiming more privacy than the code delivers is a bug.

## Documentation

The docs are load-bearing — people run nodes from them. If your change alters
how something is operated, update the relevant guide in the same PR
(`INSTALL.md`, `TESTNET.md`, `DEPLOY.md`, `RPC.md`).

Be honest in them. [TESTNET.md](TESTNET.md) §9 lists the project's own
limitations plainly, and that is deliberate: a privacy chain that oversells what
it hides gets people hurt. Keep that tone.

## Licence

By contributing you agree your work is dual licensed `MIT OR Apache-2.0`, matching
the project — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
Only contribute code you have the right to license this way. Do not paste code
from GPL/AGPL projects, or from any other chain, into this tree: Latebra is a
clean-room implementation and that property is worth protecting.
