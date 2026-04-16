//! Trace line representation + mnemonic classification.

use crate::reg::{RegId, REG_INVALID};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InsnCategory {
    DataMove,      // mov, mvn, neg
    ImmLoad,       // movz, movn, adr, adrp
    PartialModify, // movk
    Arithmetic,    // add, sub, mul, ...
    Logic,         // and, orr, eor, ...
    ShiftExt,      // lsl, lsr, asr, ror, sxt*, uxt*
    Bitfield,      // ubfm, sbfm, bfm, bfi, bfxil, extr
    Load,          // ldr*, ldp, ldur, ...
    Store,         // str*, stp, stur, ...
    Compare,       // cmp, cmn, tst
    CondSelect,    // csel, csinc, csinv, csneg
    Branch,        // b, bl, blr, br, ret, cbz, ...
    /// 外部函数调用(未 trace 内部)。由 parser 从 `-> libc.so!malloc(...)`
    /// 这类行合成。ARM64 调用约定下 x0-x18 + NZCV 全部被调用方覆盖,
    /// engine 据此切断 taint 传播链。
    ExternalCall,
    Other,
}

#[derive(Clone, Debug)]
pub struct TraceLine {
    pub line_number: u32,
    pub category: InsnCategory,

    pub num_dst: u8,
    pub num_src: u8,
    pub dst_regs: [RegId; 4],
    pub src_regs: [RegId; 8],

    pub mem_read_addr: u64,
    pub mem_write_addr: u64,
    pub mem_write_addr2: u64, // STP second write
    pub mem_read_addr2: u64,  // LDP second read
    pub mem_read_val: u64,
    pub mem_write_val: u64,
    pub mem_read_val2: u64,
    pub mem_write_val2: u64,
    pub rel_addr: u64,
    pub has_mem_read: bool,
    pub has_mem_write: bool,
    pub has_mem_write2: bool,
    pub has_mem_read2: bool,
    pub sets_flags: bool, // adds, subs, ands, ... implicitly write NZCV

    pub file_offset: u64,
    pub line_len: u32,

    /// If non-zero, this is an STP/LDP-family paired memory access and the
    /// *second* memory address should be inferred as `first_addr + pair_reg_size`
    /// when only one `MEM R/W` line was attached (xgtrace sometimes truncates)
    /// or when the trace format never provides the second address (GumTrace
    /// native). Units: bytes. Zero = not a pair instruction.
    pub pair_reg_size: u8,
}

impl Default for TraceLine {
    fn default() -> Self {
        Self {
            line_number: 0,
            category: InsnCategory::Other,
            num_dst: 0,
            num_src: 0,
            dst_regs: [REG_INVALID; 4],
            src_regs: [REG_INVALID; 8],
            mem_read_addr: 0,
            mem_write_addr: 0,
            mem_write_addr2: 0,
            mem_read_addr2: 0,
            mem_read_val: 0,
            mem_write_val: 0,
            mem_read_val2: 0,
            mem_write_val2: 0,
            rel_addr: 0,
            has_mem_read: false,
            has_mem_write: false,
            has_mem_write2: false,
            has_mem_read2: false,
            sets_flags: false,
            file_offset: 0,
            line_len: 0,
            pair_reg_size: 0,
        }
    }
}

/// Direct port of TraceParser::classify_mnemonic.
pub fn classify_mnemonic(m: &[u8]) -> InsnCategory {
    if m.is_empty() {
        return InsnCategory::Other;
    }
    use InsnCategory::*;
    match m[0] {
        b'm' => match m {
            b"mov" | b"mvn" => DataMove,
            b"movz" | b"movn" => ImmLoad,
            b"movk" => PartialModify,
            b"mul" | b"madd" | b"msub" | b"mneg" => Arithmetic,
            _ => Other,
        },
        b'n' => match m {
            b"neg" | b"negs" | b"ngc" | b"ngcs" => DataMove,
            b"nop" => Branch,
            _ => Other,
        },
        b'c' => match m {
            b"cls" | b"clz" => DataMove,
            b"cmp" | b"cmn" | b"ccmp" | b"ccmn" => Compare,
            b"csel" | b"csinc" | b"csinv" | b"csneg" | b"cset" | b"csetm" | b"cinc" | b"cinv"
            | b"cneg" => CondSelect,
            b"cbz" | b"cbnz" => Branch,
            _ => Other,
        },
        b'a' => match m {
            b"add" | b"adds" | b"adc" | b"adcs" => Arithmetic,
            b"and" | b"ands" => Logic,
            b"adr" | b"adrp" => ImmLoad,
            b"asr" => ShiftExt,
            // PAC auth: autiasp, autibsp, autia, autib, autda, autdb
            _ if m.len() >= 5 && m.starts_with(b"aut") => Branch,
            _ => Other,
        },
        b's' => match m {
            b"sub" | b"subs" | b"sbc" | b"sbcs" | b"sdiv" | b"smull" | b"smulh" | b"smaddl"
            | b"smsubl" => Arithmetic,
            b"str" | b"strb" | b"strh" | b"stur" | b"sturb" | b"sturh" | b"stp" | b"stlr"
            | b"stlrb" | b"stlrh" | b"stxr" | b"stlxr" | b"stxrb" | b"stlxrb" | b"stxrh"
            | b"stlxrh" | b"stxp" | b"stlxp" => Store,
            b"sbfm" | b"sbfx" => Bitfield,
            b"sxtb" | b"sxth" | b"sxtw" => ShiftExt,
            b"scvtf" => DataMove,
            b"svc" => Branch,
            _ => Other,
        },
        b'l' => match m {
            b"ldr" | b"ldrb" | b"ldrh" | b"ldrsw" | b"ldrsb" | b"ldrsh" | b"ldur" | b"ldurb"
            | b"ldurh" | b"ldursw" | b"ldursb" | b"ldursh" | b"ldp" | b"ldpsw" | b"ldar"
            | b"ldarb" | b"ldarh" | b"ldxr" | b"ldaxr" | b"ldxrb" | b"ldaxrb" | b"ldxrh"
            | b"ldaxrh" | b"ldxp" | b"ldaxp" | b"ldnp" | b"ldtr" | b"ldtrb" | b"ldtrh"
            | b"ldtrsw" | b"ldtrsb" | b"ldtrsh" => Load,
            b"lsl" | b"lsr" => ShiftExt,
            _ => Other,
        },
        b'd' => match m {
            b"dmb" | b"dsb" | b"dc" => Branch,
            _ => Other,
        },
        b'o' => match m {
            b"orr" | b"orn" => Logic,
            _ => Other,
        },
        b'e' => match m {
            b"eor" | b"eon" => Logic,
            b"extr" => Bitfield,
            _ => Other,
        },
        b'f' => match m {
            b"fmov" => DataMove,
            b"fadd" | b"fsub" | b"fmul" | b"fdiv" | b"fneg" | b"fabs" | b"fsqrt" | b"fmadd"
            | b"fmsub" | b"fnmadd" | b"fnmsub" | b"fmin" | b"fmax" | b"fnmul" => Arithmetic,
            b"fcmp" | b"fccmp" | b"fcmpe" | b"fccmpe" => Compare,
            b"fcsel" => CondSelect,
            _ if m.len() >= 4 && m.starts_with(b"fcvt") => DataMove,
            _ if m.len() >= 5 && m.starts_with(b"frint") => DataMove,
            _ => Other,
        },
        b'i' => match m {
            b"isb" | b"ic" => Branch,
            _ => Other,
        },
        b'b' => match m {
            b"bic" | b"bics" => Logic,
            b"bfm" | b"bfi" | b"bfxil" => Bitfield,
            b"b" | b"bl" | b"br" | b"blr" | b"bti" => Branch,
            // b.eq, b.ne, ...
            _ if m.len() >= 2 && m[1] == b'.' => Branch,
            _ => Other,
        },
        b'r' => match m {
            b"ret" | b"retaa" | b"retab" => Branch,
            b"rbit" | b"rev" | b"rev16" | b"rev32" | b"rev64" => DataMove,
            b"ror" => ShiftExt,
            _ => Other,
        },
        b'u' => match m {
            b"udiv" | b"umull" | b"umulh" | b"umaddl" | b"umsubl" => Arithmetic,
            b"ubfm" | b"ubfx" => Bitfield,
            b"uxtb" | b"uxth" => ShiftExt,
            b"ucvtf" => DataMove,
            _ => Other,
        },
        b't' => match m {
            b"tst" => Compare,
            b"tbz" | b"tbnz" => Branch,
            _ => Other,
        },
        b'p' => match m {
            // PAC sign / prefetch: do not touch data flow.
            b"paciasp" | b"pacibsp" | b"pacia" | b"pacib" | b"pacda" | b"pacdb" => Branch,
            b"prfm" | b"prfum" => Branch,
            _ => Other,
        },
        _ => Other,
    }
}
