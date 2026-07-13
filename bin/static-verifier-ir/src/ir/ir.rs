//! Straight-line SSA IR. Instruction outputs occupy consecutive witness
//! slots in program order; `Opcode::out_count` + [`walk`] are the single
//! source of truth for the slot layout.

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    Input = 0,
    Const,
    Add,
    Sub,
    Mul,
    Neg,
    MulAdd,
    SubMul,
    Select,
    IsZero,
    DivModU32,
    Decompose,
    BnToBb5,
    Poseidon2T3,
    Poseidon2T2,
    BbAdd,
    BbSub,
    BbNeg,
    BbMul,
    BbMulAdd,
    BbReduce,
    BbDiv,
    Ext4Add,
    Ext4Sub,
    Ext4Neg,
    Ext4ScalarMul,
    Ext4ScalarMulAdd,
    Ext4Mul,
    Ext4Reduce,
    Ext4Div,
}

pub const NUM_OPCODES: usize = 30;

pub const ALL_OPCODES: [Opcode; NUM_OPCODES] = [
    Opcode::Input,
    Opcode::Const,
    Opcode::Add,
    Opcode::Sub,
    Opcode::Mul,
    Opcode::Neg,
    Opcode::MulAdd,
    Opcode::SubMul,
    Opcode::Select,
    Opcode::IsZero,
    Opcode::DivModU32,
    Opcode::Decompose,
    Opcode::BnToBb5,
    Opcode::Poseidon2T3,
    Opcode::Poseidon2T2,
    Opcode::BbAdd,
    Opcode::BbSub,
    Opcode::BbNeg,
    Opcode::BbMul,
    Opcode::BbMulAdd,
    Opcode::BbReduce,
    Opcode::BbDiv,
    Opcode::Ext4Add,
    Opcode::Ext4Sub,
    Opcode::Ext4Neg,
    Opcode::Ext4ScalarMul,
    Opcode::Ext4ScalarMulAdd,
    Opcode::Ext4Mul,
    Opcode::Ext4Reduce,
    Opcode::Ext4Div,
];

impl Opcode {
    pub fn from_u8(op: u8) -> Self {
        assert!((op as usize) < NUM_OPCODES, "invalid opcode {op}");
        ALL_OPCODES[op as usize]
    }

    /// Number of input slot ids.
    pub fn arg_count(self) -> usize {
        use Opcode::*;
        match self {
            Input | Const => 0,
            Neg | IsZero | DivModU32 | Decompose | BnToBb5 | BbNeg | BbReduce => 1,
            Add | Sub | Mul | Poseidon2T2 | BbAdd | BbSub | BbMul | BbDiv => 2,
            MulAdd | SubMul | Select | Poseidon2T3 | BbMulAdd => 3,
            Ext4Neg | Ext4Reduce => 4,
            Ext4ScalarMul => 5,
            Ext4Add | Ext4Sub | Ext4Mul | Ext4Div => 8,
            Ext4ScalarMulAdd => 9,
        }
    }

    /// Args live in `Program::spill` (aux = spill offset) instead of inline.
    pub fn uses_spill(self) -> bool {
        self.arg_count() > 3
    }

    /// Number of consecutive output slots.
    pub fn out_count(self, aux: u32) -> usize {
        use Opcode::*;
        match self {
            Decompose => (aux >> 8) as usize,
            IsZero | DivModU32 | Poseidon2T2 => 2,
            Poseidon2T3 => 3,
            Ext4Add | Ext4Sub | Ext4Neg | Ext4ScalarMul | Ext4ScalarMulAdd | Ext4Mul |
            Ext4Reduce | Ext4Div => 4,
            BnToBb5 => 6,
            _ => 1,
        }
    }

    pub fn name(self) -> &'static str {
        use Opcode::*;
        match self {
            Input => "Input",
            Const => "Const",
            Add => "Add",
            Sub => "Sub",
            Mul => "Mul",
            Neg => "Neg",
            MulAdd => "MulAdd",
            SubMul => "SubMul",
            Select => "Select",
            IsZero => "IsZero",
            DivModU32 => "DivModU32",
            Decompose => "Decompose",
            BnToBb5 => "BnToBb5",
            Poseidon2T3 => "Poseidon2T3",
            Poseidon2T2 => "Poseidon2T2",
            BbAdd => "BbAdd",
            BbSub => "BbSub",
            BbNeg => "BbNeg",
            BbMul => "BbMul",
            BbMulAdd => "BbMulAdd",
            BbReduce => "BbReduce",
            BbDiv => "BbDiv",
            Ext4Add => "Ext4Add",
            Ext4Sub => "Ext4Sub",
            Ext4Neg => "Ext4Neg",
            Ext4ScalarMul => "Ext4ScalarMul",
            Ext4ScalarMulAdd => "Ext4ScalarMulAdd",
            Ext4Mul => "Ext4Mul",
            Ext4Reduce => "Ext4Reduce",
            Ext4Div => "Ext4Div",
        }
    }
}

/// `aux`: Input → input index; Const → consts index; DivModU32 → divisor;
/// Decompose → `num_limbs << 8 | limb_bits`; spilled ops → spill offset.
#[derive(Copy, Clone, Debug)]
pub struct Inst {
    pub op: u8,
    pub aux: u32,
    pub args: [u32; 3],
}

#[derive(Default)]
pub struct Program {
    pub insts: Vec<Inst>,
    pub spill: Vec<u32>,
    pub consts: Vec<Fr>,
    pub num_inputs: u32,
    pub num_slots: u32,
}

impl Program {
    #[inline]
    pub fn args_of<'a>(&'a self, inst: &'a Inst) -> &'a [u32] {
        let op = Opcode::from_u8(inst.op);
        let n = op.arg_count();
        if op.uses_spill() {
            &self.spill[inst.aux as usize..inst.aux as usize + n]
        } else {
            &inst.args[..n]
        }
    }
}

/// Visit every instruction with its opcode, args and output slot base.
pub fn walk(prog: &Program, mut f: impl FnMut(usize, Opcode, &Inst, &[u32], u32)) {
    let mut out_base = 0u32;
    for (idx, inst) in prog.insts.iter().enumerate() {
        let op = Opcode::from_u8(inst.op);
        f(idx, op, inst, prog.args_of(inst), out_base);
        out_base += op.out_count(inst.aux) as u32;
    }
    assert_eq!(out_base, prog.num_slots);
}
