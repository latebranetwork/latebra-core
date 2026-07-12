# Latebra — Design & Build Brief

A ready-to-use prompt pack for four surfaces: the **marketing site**, the
**explorer (Latscan)**, the **web wallet**, and the **Chrome extension wallet**.
Everything here is calibrated to read *engineered and expensive*, not
"AI-generated template." Hand any section below to a builder or a generation
model as-is.

---

## 0. The design language (LOCKED — applies to every surface)

This is the single source of truth. Every surface must share it so the whole
product reads as one system.

**Aesthetic north star:** the instrument panel of something precise and
expensive — a trading terminal crossed with a Swiss watch. Near-black, high
contrast, one disciplined accent, obsessive typographic rhythm, restraint
everywhere. NOT glassmorphism, NOT gradients-everywhere, NOT glow-on-everything.
If it looks like a generic crypto template, it is wrong.

**Canvas & surfaces**
- Base canvas: `#08080A` (near-black, a hair warm).
- Raised surface (cards, panels): `#101014`.
- Hairline borders: `rgba(255,255,255,0.08)`, 1px. Borders do the structural
  work — not shadows, not fills.
- Elevation is expressed by border brightness and a *single* soft shadow, never
  by heavy drop-shadows.

**Accent & semantic color** — exactly one accent, used sparingly:
- Amber `#FFB43C` — the brand accent. Primary actions, active states, the logo
  mark, key numbers. Use it like punctuation, not paint.
- **Blue `#4C82FB` = transparent/public.** Every public-lane element.
- **Violet `#9B6BFF` = confidential/private.** Every private-lane element.
- Anonymous = violet with a subtle dashed/diffused treatment ("more hidden").
- Success green `#3FB98A`, danger red `#FF5C5C` — muted, never loud.

**Typography**
- Display / headings / UI: **Space Grotesk** (600/700 for headings, 500 for UI).
- **Every number, hash, address, amount, code: JetBrains Mono.** This is
  non-negotiable and is the single biggest "this is serious infrastructure"
  signal. Tabular figures on.
- Generous letter-spacing on all-caps labels (`0.08em`), tight leading on big
  display type.

**Motion (engineered, not decorative)**
- Numbers **count up** on load/update (balances, block height, market cap).
- Charts **draw in** left-to-right.
- New rows (blocks, txs, trades) **slide in** from the top with a soft stagger.
- Toggles/segmented controls move with a **spring** (not linear).
- Reveal content with a **staggered fade+rise** (16px, 40ms apart).
- Everything 150–300ms, `cubic-bezier(0.4, 0, 0.2, 1)`. No bounce-heavy easing,
  no infinite loops except a single subtle "live" pulse dot.

**Iconography**
- Line icons only, 1.5–1.7px stroke, `currentColor`, 24px grid, rounded joins.
- A small custom set, consistent weight: block (stacked cube), coin, clock,
  network node, transaction (crossing arrows), shield (transparent), eye-off
  (private), lock, key, validator (layered shield), stake (bars).
- Never mix icon families. Never use emoji as icons in-product.

**Layout**
- Max content width 1200px, generous whitespace, an 8px spacing grid.
- Hairline dividers instead of boxes wherever possible.
- Mobile-first responsive; wide content (tables, charts) scrolls inside its own
  container — the page body never scrolls sideways.
- Dark by default; a light theme is optional and, if built, must invert cleanly
  (test both).

**Voice / copy**
- Confident, plain, technical-but-human. Short sentences. No hype words
  ("revolutionary", "next-gen"). Let the product's precision speak.
- The tagline: **"Privacy is a choice, not a compromise."**

---

## 1. Marketing site prompt

> Build a single-page marketing site for **Latebra**, a Layer-1 blockchain whose
> pitch is: *the only chain that is private, public, programmable, and final —
> all at once, with privacy chosen per transaction.* Apply the LOCKED design
> language above exactly: `#08080A` canvas, Space Grotesk + JetBrains Mono
> (mono for all numbers/hashes), single amber `#FFB43C` accent, blue=public /
> violet=private, hairline borders, engineered motion. It must feel like premium
> financial infrastructure — think Linear × Stripe × a trading terminal — not a
> crypto template.

**Sections, in order:**

1. **Hero.** Full-height, near-black. Left: the tagline "Privacy is a choice, not
   a compromise." as a large Space Grotesk headline; a one-line subhead ("One
   ledger. Three ways to move value. You decide."); two buttons — amber
   "Launch Wallet", ghost "Read the Whitepaper". Right: an animated hero
   visualization — a single coin/token that splits into **three glowing paths**
   labeled *Transparent* (blue), *Confidential* (violet, amount blurred),
   *Anonymous* (violet dashed, everything blurred) — the paths draw in on load.
   A live "block #____" counter (mono, counting up) and a pulsing "live" dot in
   the corner.

2. **The trade-off, killed.** Three-column contrast: "Public chains expose
   everything" / "Privacy chains hide everything and can't build" / "**Latebra
   lets the user choose.**" The third column is amber-accented and elevated.

3. **Three modes.** Three cards — Transparent (blue), Confidential (violet),
   Anonymous (violet/dashed) — each with an icon, a one-line "what's hidden"
   summary (a tiny row of shield/eye-off/lock icons showing sender/amount/receiver
   visible-or-hidden), and a mono example line. Hovering a card highlights its
   path in the hero motif.

4. **The moat table.** The capability comparison (Latebra / Monero / Zcash /
   Ethereum / Solana) as a clean matrix with ✅/❌ in semantic colors, amber
   ring around the Latebra column. Caption: "The gaps are structural — Monero
   can't add contracts, Ethereum can't add native privacy."

5. **How it works.** A four-step horizontal stepper with the custom line icons:
   Encrypted balances → Choose your privacy → BFT finality (irreversible) →
   Build on it (contracts). Each step's number counts up.

6. **Built and proven.** A stat band (mono, count-up): "~260 tests", "3 privacy
   modes", "~15ms node boot", "chaos-tested", "0 trusted setup". Then a short
   "honesty" line linking the whitepaper + threat model + crypto spec — turn
   transparency into a trust signal.

7. **For builders.** A dark code panel showing a JSON-RPC call
   (`lat_status`) and its response, mono, syntax-tinted. "One HTTP endpoint.
   Exchanges, explorers, bots." Link to RPC docs.

8. **Footer / CTA.** "Privacy is a choice." Repeat the two buttons. Links:
   Explorer, Wallet, Whitepaper, GitHub, Threat Model. A clear
   **"Testnet — unaudited, not for real value yet"** honesty badge.

**Motion:** hero paths draw in; the block counter and every stat count up on
scroll-into-view; cards rise+fade with stagger; the comparison table checks
animate in column by column. Keep it tasteful — one deliberate motion per
section, not a carnival.

**Higgsfield asset prompts** (generate these, then embed):
- *Hero background loop:* "abstract dark financial data visualization, near-black
  #08080A background, thin amber and violet light traces flowing and splitting
  into three paths, extremely minimal, cinematic, high contrast, no text, subtle
  slow motion, premium fintech" — 16:9 loop.
- *Section texture:* "very subtle dark topographic contour lines, near-black,
  faint amber, minimal, for a section background" — static, low opacity.
- *Social/OG card:* "Latebra wordmark in Space Grotesk on near-black, single
  amber accent mark, minimalist, premium" — 1200×630.

---

## 2. Explorer (Latscan) prompt

> Redesign the Latebra block explorer to the LOCKED design language. It should
> feel like a Bloomberg terminal for a privacy chain: dense but calm, every
> number in JetBrains Mono, live updates that slide in, and an honest,
> beautiful treatment of *hidden* data.

**Home:**
- Top: a compact stat rail (mono, count-up) — latest block, difficulty, tps,
  finalized height, mempool size, peers — each with a tiny line icon.
- Two live columns, Etherscan-style but calmer: **Latest Blocks** and **Latest
  Transactions**, new rows sliding in from the top with a soft stagger and a
  one-shot amber flash.
- A live "finality watermark" indicator: blocks below it get a small violet
  "final" lock badge; above it, an amber "pending" pulse.

**Transaction rows — the signature detail:** each tx shows a **privacy-lane chip**
using the semantic colors — blue "Public", violet "Confidential", violet-dashed
"Anonymous". For hidden fields show elegant placeholders, never fake numbers:
amount renders as a violet "•••• hidden" or a small blurred glyph, sender/receiver
of anon txs render as "stealth" / "ring of 16". This turns privacy into a
*visible design feature* instead of missing data.

**Block page:** header with height (mono, big), hash, timestamp, miner,
tx count, finality status; a clean tx list; prev/next stepper.

**Address page:** balance (public shown, confidential shown as "encrypted — only
the owner can read this" with a lock), nonce, stake status if a validator, tx
history with lane chips.

**Faucet page:** minimal card, one input, one amber button, cooldown shown as a
mono countdown.

**Motion:** feed rows slide+flash; stat rail counts up; charts (tx-per-block
sparkline) draw in. A single "live" pulse dot in the header.

---

## 3. Web wallet prompt

> Redesign the Latebra web wallet to the LOCKED design language — sleek,
> minimal, confidence-inspiring, and built around the product's core idea:
> **the user chooses the privacy of every send.** Mono for all amounts and
> addresses; violet=private, blue=public throughout.

**Screens:**

1. **Welcome / create / import.** Near-black, centered. Big mono logo mark,
   tagline, two buttons: "Create wallet" / "Import". Seed phrase shown as a
   clean mono grid with a copy button and a stern "write this down" note.

2. **Home.** A large **balance hero** (mono, count-up) with a segmented toggle
   between **Public** (blue) and **Private** (violet) balances — the toggle
   springs. Below: a staggered-in transaction list with lane chips (matching the
   explorer). A prominent amber "Send" and a ghost "Receive".

3. **Send sheet — the hero interaction.** A bottom sheet with:
   - amount input (mono, large),
   - recipient input (mono; paste/QR),
   - and a **three-way privacy selector** — a springy segmented control:
     **Public** (blue) · **Confidential** (violet) · **Anonymous** (violet
     dashed). Selecting each updates a live one-line explainer of *what will be
     hidden* (icons for sender/amount/receiver flipping visible↔hidden) and the
     fee. This selector is the single most important UI element in the whole
     product — make it feel deliberate and satisfying.
   - For Anonymous: a subtle "ring size" stepper and a note that it uses a
     one-time stealth address.

4. **Receive.** QR of the address, mono address with copy, a note that others
   see only what the sender chooses to reveal.

5. **Stake (optional tab).** Bond LAT to become a validator; show stake,
   unbonding schedule (mono countdowns), and slashing warning.

**Motion:** balance counts up; toggles spring; send-sheet slides up; the privacy
selector animates the "what's hidden" icon row; success states use a single
clean check, not confetti.

---

## 4. Chrome extension wallet prompt

> Build a **Chrome (Manifest V3) browser-extension wallet** for Latebra, sharing
> the LOCKED design language with the web wallet so they feel like one product.
> It is the MetaMask-equivalent for Latebra: a compact popup wallet plus a page
> connector, but cleaner and privacy-first.

**Architecture:**
- **Manifest V3**, service-worker background, popup UI, content script for
  dapp connection, `chrome.storage` (encrypted) for the vault.
- Keys derived and held **only in the extension**; the private key never leaves.
  Signing and proof-building happen locally; the extension talks to a Latebra
  node over the **JSON-RPC endpoint** (`lat_status`, `lat_*Balance`, `lat_nonce`,
  `lat_ringCandidates`, `lat_submitTx`).
- A `window.latebra` provider injected into pages (connect, getAccount,
  signAndSend, getBalance) so the launchpad and future dapps integrate — the
  privacy-chain analogue of `window.ethereum`.

**Popup UI (compact, ~360×600):**
- **Header:** logo mark, network pill ("Testnet", amber), a live "•" node-status
  dot.
- **Balance:** mono count-up, Public/Private spring toggle.
- **Actions:** amber "Send", ghost "Receive", ghost "Activity".
- **Send:** the same three-way privacy selector as the web wallet (Public/
  Confidential/Anonymous) — carry the exact interaction; this is the brand.
- **Activity:** compact tx list with lane chips and hidden-field placeholders.
- **Lock screen:** password unlock, auto-lock timer, clear "your keys, your
  device" copy.

**Connection flow (dapp):** a page calls `window.latebra.connect()` → the popup
shows a clean permission card (site origin, what it's requesting) with amber
"Connect" / ghost "Reject" — never auto-approve. Transaction-signing requests
show the decoded tx and the chosen privacy lane before the user approves.

**Icons & polish:** the custom line-icon set at 20px in the popup; the toolbar
icon is the amber Latebra mark (pixel-dissolving edge = "data scattering into
privacy"); a subtle badge shows pending-tx count.

**Motion (subtle, extensions must feel instant):** balance count-up, spring
toggle, send-sheet slide, one-shot success check. Nothing that delays interaction.

---

## 5. Build order (recommended)

1. Marketing site (the pitch — for VCs, exchanges, users).
2. Explorer refresh (the proof it's live — screenshots sell).
3. Web wallet refresh (the product people touch).
4. Chrome extension (the distribution wedge — how users actually keep coming
   back, and how dapps integrate).

Ship each on the same tokens (colors, fonts, icons, motion) so the whole
Latebra surface reads as one precise, expensive, trustworthy system.
