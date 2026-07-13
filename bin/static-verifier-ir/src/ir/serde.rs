//! Custom LE binary serialization of a [`Program`] plus its captured inputs.

use std::io::{self, Read, Write};

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use super::ir::{Inst, Program, NUM_OPCODES};

const MAGIC: &[u8; 4] = b"SVIR";
const VERSION: u32 = 1;

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn write_fr_slice(w: &mut impl Write, frs: &[Fr]) -> io::Result<()> {
    write_u64(w, frs.len() as u64)?;
    for f in frs {
        w.write_all(&f.to_bytes())?;
    }
    Ok(())
}

fn read_fr_vec(r: &mut impl Read) -> io::Result<Vec<Fr>> {
    let n = read_u64(r)? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        let f = Option::<Fr>::from(Fr::from_bytes(&buf))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-canonical Fr"))?;
        out.push(f);
    }
    Ok(out)
}

pub fn write_program(w: &mut impl Write, prog: &Program, inputs: &[Fr]) -> io::Result<()> {
    w.write_all(MAGIC)?;
    write_u32(w, VERSION)?;
    write_u32(w, prog.num_inputs)?;
    write_u32(w, prog.num_slots)?;
    write_u64(w, prog.insts.len() as u64)?;
    for inst in &prog.insts {
        w.write_all(&[inst.op])?;
        write_u32(w, inst.aux)?;
        for a in inst.args {
            write_u32(w, a)?;
        }
    }
    write_u64(w, prog.spill.len() as u64)?;
    for &s in &prog.spill {
        write_u32(w, s)?;
    }
    write_fr_slice(w, &prog.consts)?;
    write_fr_slice(w, inputs)
}

pub fn read_program(r: &mut impl Read) -> io::Result<(Program, Vec<Fr>)> {
    let bad = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(bad("bad magic"));
    }
    if read_u32(r)? != VERSION {
        return Err(bad("unsupported version"));
    }
    let num_inputs = read_u32(r)?;
    let num_slots = read_u32(r)?;
    let n_insts = read_u64(r)? as usize;
    let mut insts = Vec::with_capacity(n_insts);
    for _ in 0..n_insts {
        let mut op = [0u8; 1];
        r.read_exact(&mut op)?;
        if op[0] as usize >= NUM_OPCODES {
            return Err(bad("invalid opcode"));
        }
        let aux = read_u32(r)?;
        let args = [read_u32(r)?, read_u32(r)?, read_u32(r)?];
        insts.push(Inst { op: op[0], aux, args });
    }
    let n_spill = read_u64(r)? as usize;
    let mut spill = Vec::with_capacity(n_spill);
    for _ in 0..n_spill {
        spill.push(read_u32(r)?);
    }
    let consts = read_fr_vec(r)?;
    let inputs = read_fr_vec(r)?;
    if inputs.len() != num_inputs as usize {
        return Err(bad("input count mismatch"));
    }
    Ok((Program { insts, spill, consts, num_inputs, num_slots }, inputs))
}
