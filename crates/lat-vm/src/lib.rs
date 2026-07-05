//! Latebra Virtual Machine (clean-room, from `SPEC.md`).
//!
//! A small, deterministic, sandboxed stack machine for on-chain smart contracts.
//! Contracts have persistent key→value storage (`u64 → u64`) and run a bytecode
//! program with a strict step (gas) limit, so execution always terminates and is
//! identical on every node. This is a v1 foundation — real, programmable, and
//! testable — not yet as rich as a high-level contract language.
//!
//! ## Instruction set (one byte opcode; `PUSH8` carries an 8-byte LE operand)
//! ```text
//!   00 STOP      08 EQ        10 SWAP
//!   01 PUSH8 x   09 LT        11 SLOAD   (key → storage[key])
//!   02 POP       0A GT        12 SSTORE  (key, value → )
//!   03 ADD       0B AND       13 CALLER  (→ first 8 bytes of caller id)
//!   04 SUB       0C NOT       14 INPUT   (→ the call's input word)
//!   05 MUL       0D JUMP      (dest → )
//!   06 DIV       0E JUMPI     (dest, cond → ; jumps if cond != 0)
//!   07 MOD       0F DUP
//! ```
//! Arithmetic wraps (mod 2^64); `DIV`/`MOD` by zero is an error.

use std::collections::HashMap;

/// Default execution budget (VM steps) for one contract call.
pub const DEFAULT_GAS: u64 = 100_000;
const MAX_STACK: usize = 1024;

/// Persistent contract storage.
pub type Storage = HashMap<u64, u64>;

#[derive(Debug, PartialEq, Eq)]
pub enum VmError {
    OutOfGas,
    StackUnderflow,
    StackOverflow,
    BadJump,
    DivByZero,
    BadOpcode(u8),
    Truncated,
}

/// Deterministic contract address = hash of deployer + code.
pub fn contract_id(deployer: &[u8; 32], code: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"LAT-contract");
    h.update(deployer);
    h.update(code);
    *h.finalize().as_bytes()
}

fn pop(s: &mut Vec<u64>) -> Result<u64, VmError> {
    s.pop().ok_or(VmError::StackUnderflow)
}

fn push(s: &mut Vec<u64>, v: u64) -> Result<(), VmError> {
    if s.len() >= MAX_STACK {
        return Err(VmError::StackOverflow);
    }
    s.push(v);
    Ok(())
}

/// Execute `code`, mutating `storage`. `caller` and `input` are the call context.
/// On success `storage` holds the updated state; on error it should be discarded.
pub fn execute(
    code: &[u8],
    storage: &mut Storage,
    caller: &[u8; 32],
    input: u64,
    gas_limit: u64,
) -> Result<(), VmError> {
    let mut stack: Vec<u64> = Vec::new();
    let mut pc: usize = 0;
    let mut gas = gas_limit;

    while pc < code.len() {
        if gas == 0 {
            return Err(VmError::OutOfGas);
        }
        gas -= 1;

        let op = code[pc];
        pc += 1;
        match op {
            0x00 => break, // STOP
            0x01 => {
                // PUSH8
                let end = pc.checked_add(8).ok_or(VmError::Truncated)?;
                let bytes = code.get(pc..end).ok_or(VmError::Truncated)?;
                push(&mut stack, u64::from_le_bytes(bytes.try_into().unwrap()))?;
                pc = end;
            }
            0x02 => {
                pop(&mut stack)?;
            }
            0x03 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, a.wrapping_add(b))?;
            }
            0x04 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, a.wrapping_sub(b))?;
            }
            0x05 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, a.wrapping_mul(b))?;
            }
            0x06 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                if b == 0 {
                    return Err(VmError::DivByZero);
                }
                push(&mut stack, a / b)?;
            }
            0x07 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                if b == 0 {
                    return Err(VmError::DivByZero);
                }
                push(&mut stack, a % b)?;
            }
            0x08 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, (a == b) as u64)?;
            }
            0x09 => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, (a < b) as u64)?;
            }
            0x0A => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, (a > b) as u64)?;
            }
            0x0B => {
                let (b, a) = (pop(&mut stack)?, pop(&mut stack)?);
                push(&mut stack, a & b)?;
            }
            0x0C => {
                let a = pop(&mut stack)?;
                push(&mut stack, (a == 0) as u64)?;
            }
            0x0D => {
                let dest = pop(&mut stack)? as usize;
                if dest >= code.len() {
                    return Err(VmError::BadJump);
                }
                pc = dest;
            }
            0x0E => {
                let dest = pop(&mut stack)? as usize;
                let cond = pop(&mut stack)?;
                if cond != 0 {
                    if dest >= code.len() {
                        return Err(VmError::BadJump);
                    }
                    pc = dest;
                }
            }
            0x0F => {
                let top = *stack.last().ok_or(VmError::StackUnderflow)?;
                push(&mut stack, top)?;
            }
            0x10 => {
                let n = stack.len();
                if n < 2 {
                    return Err(VmError::StackUnderflow);
                }
                stack.swap(n - 1, n - 2);
            }
            0x11 => {
                let key = pop(&mut stack)?;
                push(&mut stack, *storage.get(&key).unwrap_or(&0))?;
            }
            0x12 => {
                let value = pop(&mut stack)?;
                let key = pop(&mut stack)?;
                storage.insert(key, value);
            }
            0x13 => {
                push(&mut stack, u64::from_le_bytes(caller[0..8].try_into().unwrap()))?;
            }
            0x14 => {
                push(&mut stack, input)?;
            }
            other => return Err(VmError::BadOpcode(other)),
        }
    }
    Ok(())
}

/// Small assembler helpers for building bytecode (handy for contracts + tests).
pub mod asm {
    pub fn push(v: u64) -> Vec<u8> {
        let mut o = vec![0x01];
        o.extend_from_slice(&v.to_le_bytes());
        o
    }
    pub const STOP: u8 = 0x00;
    pub const ADD: u8 = 0x03;
    pub const MUL: u8 = 0x05;
    pub const SLOAD: u8 = 0x11;
    pub const SSTORE: u8 = 0x12;
}

/// A label-based assembler over the [`execute`] instruction set.
///
/// Writing branching bytecode by hand means computing absolute jump targets,
/// which is fragile: insert one instruction and every `PUSH <dest>` shifts. This
/// assembler lets a contract refer to positions by name — [`Instr::Label`] marks
/// a spot, [`Instr::PushLabel`] pushes its resolved byte offset — and
/// [`assemble`](Asm::assemble) fixes up the offsets in a second pass. It emits
/// the exact same bytecode the VM runs; it adds no new opcodes.
pub mod assembler {
    /// One assembler item: either a real instruction or a label marker.
    #[derive(Clone, Debug)]
    pub enum Instr {
        /// `PUSH8 v`.
        Push(u64),
        /// `PUSH8 <byte offset of the named label>` — resolved at assembly time.
        PushLabel(&'static str),
        /// A named position (emits no bytes); a `PushLabel` targets it.
        Label(&'static str),
        Pop,
        Add,
        Sub,
        Mul,
        Div,
        Mod,
        Eq,
        Lt,
        Gt,
        And,
        Not,
        /// Unconditional jump: pops the destination.
        Jump,
        /// Conditional jump: pops `dest` then `cond`, jumps if `cond != 0`.
        JumpI,
        Dup,
        Swap,
        Sload,
        Sstore,
        Caller,
        Input,
        Stop,
        /// Force a VM error (revert): the ledger discards the storage changes of a
        /// failed contract call, so this is how a contract rejects a bad call.
        /// Implemented as a deliberate divide-by-zero.
        Revert,
    }

    /// Errors assembling a program.
    #[derive(Debug, PartialEq, Eq)]
    pub enum AsmError {
        /// A `PushLabel`/`Label` referenced a name that was never defined.
        UndefinedLabel(&'static str),
        /// The same label name was defined more than once.
        DuplicateLabel(&'static str),
    }

    /// A program under construction.
    #[derive(Default)]
    pub struct Asm {
        items: Vec<Instr>,
    }

    impl Asm {
        pub fn new() -> Self {
            Asm { items: Vec::new() }
        }

        /// Append one instruction (builder style).
        pub fn ins(mut self, i: Instr) -> Self {
            self.items.push(i);
            self
        }

        /// Append several instructions.
        pub fn extend<I: IntoIterator<Item = Instr>>(mut self, it: I) -> Self {
            self.items.extend(it);
            self
        }

        /// Byte width an instruction occupies in the final program (labels: 0;
        /// pushes: 9 = opcode + 8-byte operand; everything else: 1).
        fn width(i: &Instr) -> usize {
            match i {
                Instr::Label(_) => 0,
                Instr::Push(_) | Instr::PushLabel(_) => 9,
                Instr::Revert => super::asm::push(0).len() + super::asm::push(0).len() + 1, // push a, push b, DIV
                _ => 1,
            }
        }

        /// Resolve labels and emit bytecode. Two passes: first compute each
        /// label's byte offset, then encode, substituting label offsets into
        /// `PushLabel`.
        pub fn assemble(&self) -> Result<Vec<u8>, AsmError> {
            use std::collections::HashMap;
            // Pass 1: label -> byte offset.
            let mut offsets: HashMap<&'static str, usize> = HashMap::new();
            let mut pc = 0usize;
            for item in &self.items {
                if let Instr::Label(name) = item {
                    if offsets.insert(name, pc).is_some() {
                        return Err(AsmError::DuplicateLabel(name));
                    }
                }
                pc += Self::width(item);
            }
            // Pass 2: emit.
            let mut out = Vec::with_capacity(pc);
            for item in &self.items {
                match item {
                    Instr::Label(_) => {}
                    Instr::Push(v) => out.extend_from_slice(&super::asm::push(*v)),
                    Instr::PushLabel(name) => {
                        let off = *offsets.get(name).ok_or(AsmError::UndefinedLabel(name))?;
                        out.extend_from_slice(&super::asm::push(off as u64));
                    }
                    Instr::Revert => {
                        // push 1 (a), push 0 (b), DIV -> DivByZero -> VM error.
                        out.extend_from_slice(&super::asm::push(1));
                        out.extend_from_slice(&super::asm::push(0));
                        out.push(0x06);
                    }
                    other => out.push(opcode(other)),
                }
            }
            Ok(out)
        }
    }

    /// The single-byte opcode for a non-push, non-label instruction.
    fn opcode(i: &Instr) -> u8 {
        match i {
            Instr::Pop => 0x02,
            Instr::Add => 0x03,
            Instr::Sub => 0x04,
            Instr::Mul => 0x05,
            Instr::Div => 0x06,
            Instr::Mod => 0x07,
            Instr::Eq => 0x08,
            Instr::Lt => 0x09,
            Instr::Gt => 0x0A,
            Instr::And => 0x0B,
            Instr::Not => 0x0C,
            Instr::Jump => 0x0D,
            Instr::JumpI => 0x0E,
            Instr::Dup => 0x0F,
            Instr::Swap => 0x10,
            Instr::Sload => 0x11,
            Instr::Sstore => 0x12,
            Instr::Caller => 0x13,
            Instr::Input => 0x14,
            Instr::Stop => 0x00,
            // Push/PushLabel/Label/Revert are handled before opcode() is called.
            Instr::Push(_) | Instr::PushLabel(_) | Instr::Label(_) | Instr::Revert => {
                unreachable!("multi-byte instruction routed to opcode()")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOBODY: [u8; 32] = [0u8; 32];

    fn run(code: &[u8]) -> (Result<(), VmError>, Storage) {
        let mut s = Storage::new();
        let r = execute(code, &mut s, &NOBODY, 0, DEFAULT_GAS);
        (r, s)
    }

    /// storage[0] = 6 * 7 = 42.
    #[test]
    fn multiplies_and_stores() {
        let mut code = asm::push(0); // key
        code.extend(asm::push(6));
        code.extend(asm::push(7));
        code.push(asm::MUL);
        code.push(asm::SSTORE);
        code.push(asm::STOP);
        let (r, s) = run(&code);
        assert_eq!(r, Ok(()));
        assert_eq!(s.get(&0), Some(&42));
    }

    /// A counter: each call does storage[0] += 1.
    #[test]
    fn counter_increments_across_calls() {
        // key key SLOAD 1 ADD SSTORE STOP
        let mut code = asm::push(0);
        code.extend(asm::push(0));
        code.push(asm::SLOAD);
        code.extend(asm::push(1));
        code.push(asm::ADD);
        code.push(asm::SSTORE);
        code.push(asm::STOP);

        let mut s = Storage::new();
        for _ in 0..3 {
            execute(&code, &mut s, &NOBODY, 0, DEFAULT_GAS).unwrap();
        }
        assert_eq!(s.get(&0), Some(&3));
    }

    #[test]
    fn infinite_loop_runs_out_of_gas() {
        // PUSH 0; JUMP  -> jumps to pc 0 forever.
        let mut code = asm::push(0);
        code.push(0x0D); // JUMP
        let mut s = Storage::new();
        assert_eq!(execute(&code, &mut s, &NOBODY, 0, 10_000), Err(VmError::OutOfGas));
    }

    #[test]
    fn div_by_zero_errors() {
        let mut code = asm::push(1);
        code.extend(asm::push(0));
        code.push(0x06); // DIV
        assert_eq!(run(&code).0, Err(VmError::DivByZero));
    }

    #[test]
    fn bad_opcode_errors() {
        assert_eq!(run(&[0xFF]).0, Err(VmError::BadOpcode(0xFF)));
    }

    #[test]
    fn input_is_available() {
        // store the call input at storage[0]: PUSH 0(key) INPUT SSTORE STOP
        let mut code = asm::push(0);
        code.push(0x14); // INPUT
        code.push(asm::SSTORE);
        code.push(asm::STOP);
        let mut s = Storage::new();
        execute(&code, &mut s, &NOBODY, 99, DEFAULT_GAS).unwrap();
        assert_eq!(s.get(&0), Some(&99));
    }

    mod assembler_tests {
        use super::super::assembler::{Asm, AsmError, Instr::*};
        use super::super::{execute, Storage, VmError, DEFAULT_GAS};

        const NOBODY: [u8; 32] = [0u8; 32];

        /// A forward branch: `if input != 0 { storage[0]=111 } else { storage[0]=222 }`.
        /// Exercises PushLabel resolving a target that appears later in the program.
        #[test]
        fn conditional_branch_resolves_forward_label() {
            // cond = input; if cond jump to SET111 else fall through to SET222.
            let code = Asm::new()
                .ins(Input) // cond
                .ins(PushLabel("set111")) // dest
                .ins(JumpI) // pops dest, cond; jump if cond!=0
                // else branch: storage[0] = 222
                .ins(Push(0)).ins(Push(222)).ins(Sstore)
                .ins(PushLabel("end")).ins(Jump)
                .ins(Label("set111"))
                .ins(Push(0)).ins(Push(111)).ins(Sstore)
                .ins(Label("end"))
                .ins(Stop)
                .assemble()
                .unwrap();

            let mut s = Storage::new();
            execute(&code, &mut s, &NOBODY, 1, DEFAULT_GAS).unwrap();
            assert_eq!(s.get(&0), Some(&111), "input!=0 takes the labelled branch");

            let mut s = Storage::new();
            execute(&code, &mut s, &NOBODY, 0, DEFAULT_GAS).unwrap();
            assert_eq!(s.get(&0), Some(&222), "input==0 falls through");
        }

        /// A backward branch (loop): sum 1..=input into storage[0].
        #[test]
        fn backward_label_forms_a_loop() {
            // storage[0]=0; i=input; while i>0 { s0+=i; i-=1 }
            let code = Asm::new()
                .ins(Push(0)).ins(Push(0)).ins(Sstore) // storage[0]=0
                .ins(Input) // i on stack (loop carries i on the stack top)
                .ins(Label("loop"))
                .ins(Dup).ins(Push(0)).ins(Gt) // cond: i>0  (dup i, push 0, GT)
                .ins(PushLabel("body")).ins(JumpI)
                .ins(PushLabel("done")).ins(Jump)
                .ins(Label("body"))
                // storage[0] += i, leaving i on the stack for the decrement.
                // stack: [i]
                .ins(Dup) // [i, i]
                .ins(Push(0)).ins(Sload) // [i, i, s0]
                .ins(Add) // [i, i+s0]
                .ins(Push(0)) // [i, i+s0, key=0]
                .ins(Swap) // [i, key=0, i+s0]
                .ins(Sstore) // storage[0]=i+s0 ; [i]
                // i -= 1
                .ins(Push(1)).ins(Sub)
                .ins(PushLabel("loop")).ins(Jump)
                .ins(Label("done"))
                .ins(Stop)
                .assemble()
                .unwrap();

            let mut s = Storage::new();
            execute(&code, &mut s, &NOBODY, 5, DEFAULT_GAS).unwrap();
            assert_eq!(s.get(&0), Some(&15), "1+2+3+4+5");
        }

        #[test]
        fn revert_discards_via_vm_error() {
            let code = Asm::new().ins(Revert).ins(Stop).assemble().unwrap();
            let mut s = Storage::new();
            assert_eq!(execute(&code, &mut s, &NOBODY, 0, DEFAULT_GAS), Err(VmError::DivByZero));
        }

        #[test]
        fn undefined_and_duplicate_labels_are_caught() {
            assert_eq!(
                Asm::new().ins(PushLabel("nope")).ins(Jump).assemble(),
                Err(AsmError::UndefinedLabel("nope"))
            );
            assert_eq!(
                Asm::new().ins(Label("x")).ins(Label("x")).assemble(),
                Err(AsmError::DuplicateLabel("x"))
            );
        }
    }
}
