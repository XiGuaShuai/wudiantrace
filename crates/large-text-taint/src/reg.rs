//! Register identifiers — direct port of TraceParser.{h,cpp} register tables.

#![allow(non_camel_case_types)]

pub type RegId = u8;

// General-purpose 64-bit (X0..X28 + FP/LR/SP/XZR/NZCV)
pub const REG_X0: RegId = 0;
pub const REG_X28: RegId = 28;
pub const REG_FP: RegId = 29; // x29
pub const REG_LR: RegId = 30; // x30
pub const REG_SP: RegId = 31;
pub const REG_XZR: RegId = 32;
pub const REG_NZCV: RegId = 33;

// SIMD (taint propagation does not specially handle these; they exist so the
// parser can still recognise them as register operands).
pub const REG_Q0: RegId = 34;
pub const REG_Q31: RegId = REG_Q0 + 31;
pub const REG_D0: RegId = REG_Q31 + 1;
pub const REG_D31: RegId = REG_D0 + 31;
pub const REG_S0: RegId = REG_D31 + 1;
pub const REG_S31: RegId = REG_S0 + 31;

pub const REG_INVALID: RegId = 255;

const REG_NAMES: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp", "xzr", "nzcv", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8",
    "q9", "q10", "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19", "q20", "q21",
    "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31", "d0", "d1", "d2", "d3",
    "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17",
    "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30",
    "d31", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13",
    "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26",
    "s27", "s28", "s29", "s30", "s31",
];

pub fn reg_name(id: RegId) -> &'static str {
    if id == REG_INVALID {
        return "?";
    }
    REG_NAMES.get(id as usize).copied().unwrap_or("?")
}

/// Normalise w→x, fp→x29, lr→x30, d/s→q so propagation treats aliases identically.
#[inline]
pub fn normalize(id: RegId) -> RegId {
    if id == REG_FP {
        return REG_X0 + 29;
    }
    if id == REG_LR {
        return REG_X0 + 30;
    }
    if (REG_D0..=REG_D31).contains(&id) {
        return REG_Q0 + (id - REG_D0);
    }
    if (REG_S0..=REG_S31).contains(&id) {
        return REG_Q0 + (id - REG_S0);
    }
    id
}

/// Parse a register token (e.g. `x0`, `w12`, `sp`, `q3`, `nzcv`).
/// Width-aliased names (`w0`→`x0`, `h0`/`b0`/`v0`→`q0`) are returned as the
/// canonical 64-bit form.
pub fn parse_reg_name(s: &[u8]) -> RegId {
    if s.is_empty() {
        return REG_INVALID;
    }
    match s[0] {
        b'x' | b'X' => parse_x_or_w(s),
        b'w' | b'W' => parse_x_or_w(s),
        b's' | b'S' => {
            if s.eq_ignore_ascii_case(b"sp") {
                return REG_SP;
            }
            parse_indexed(s, REG_S0, 31)
        }
        b'f' | b'F' => {
            if s.eq_ignore_ascii_case(b"fp") {
                return REG_FP;
            }
            if s.eq_ignore_ascii_case(b"flags") {
                return REG_NZCV;
            }
            REG_INVALID
        }
        b'l' | b'L' => {
            if s.eq_ignore_ascii_case(b"lr") {
                return REG_LR;
            }
            REG_INVALID
        }
        b'q' | b'Q' => parse_indexed(s, REG_Q0, 31),
        b'd' | b'D' => parse_indexed(s, REG_D0, 31),
        // h/b/v alias to q-series (vector regs of various widths).
        b'h' | b'H' | b'b' | b'B' | b'v' | b'V' => parse_indexed(s, REG_Q0, 31),
        b'n' | b'N' => {
            if s.eq_ignore_ascii_case(b"nzcv") {
                return REG_NZCV;
            }
            REG_INVALID
        }
        _ => REG_INVALID,
    }
}

#[inline]
fn parse_x_or_w(s: &[u8]) -> RegId {
    // x0..x9 / w0..w9
    if s.len() == 2 && s[1].is_ascii_digit() {
        return REG_X0 + (s[1] - b'0');
    }
    // x10..x30 / w10..w30
    if s.len() == 3
        && (b'0'..=b'3').contains(&s[1])
        && s[1].is_ascii_digit()
        && s[2].is_ascii_digit()
    {
        let n = (s[1] - b'0') * 10 + (s[2] - b'0');
        if n <= 30 {
            return REG_X0 + n;
        }
    }
    if s.len() == 3 && s[1] == b'z' && s[2] == b'r' {
        return REG_XZR;
    }
    REG_INVALID
}

#[inline]
fn parse_indexed(s: &[u8], base: RegId, max_n: u8) -> RegId {
    if s.len() < 2 || !s[1].is_ascii_digit() {
        return REG_INVALID;
    }
    let mut n = s[1] - b'0';
    if s.len() == 3 && s[2].is_ascii_digit() {
        n = n * 10 + (s[2] - b'0');
    } else if s.len() > 3 {
        return REG_INVALID;
    }
    if n <= max_n {
        return base + n;
    }
    REG_INVALID
}
