use std::io::{Read, Write};

const BUDGET: u64 = 8000;
const MAX_PROG: usize = 4096;
const WIN_BASE: u64 = 0x4baac0;
const CONFESS: u64 = 0x403019;
const WIN_LEN: u64 = 0x1000;
const CORE: usize = 16;
const DEFAULT_BEST_KNOWN: u64 = 170;
const STEP_LIMIT: u64 = 5_000_000;

#[allow(non_camel_case_types)]
type c_int = i32;
extern "C" {
    fn fork() -> c_int;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn ptrace(request: c_int, pid: c_int, addr: u64, data: u64) -> i64;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
}
const TRACEME: c_int = 0;
const PEEKDATA: c_int = 2;
const POKEDATA: c_int = 5;
const CONT: c_int = 7;
const SINGLESTEP: c_int = 9;
const GETREGS: c_int = 12;
const SETREGS: c_int = 13;
const SIGTRAP: c_int = 5;
const SIGKILL: c_int = 9;

const R_RAX: usize = 10;
const R_RCX: usize = 11;
const R_RDX: usize = 12;
const R_RSI: usize = 13;
const R_RDI: usize = 14;
const R_RIP: usize = 16;

fn regid_to_idx(id: u8) -> Option<usize> {
    Some(match id {
        0 => R_RAX,
        1 => R_RCX,
        2 => R_RDX,
        6 => R_RSI,
        7 => R_RDI,
        16 => R_RIP,
        _ => return None,
    })
}

fn errno() -> i32 { unsafe { *__errno_location() } }
fn set_errno(v: i32) { unsafe { *__errno_location() = v } }

struct Child {
    pid: c_int,
    alive: bool,
}
impl Child {
    fn getregs(&self) -> [u64; 27] {
        let mut r = [0u64; 27];
        unsafe { ptrace(GETREGS, self.pid, 0, r.as_mut_ptr() as u64) };
        r
    }
    fn setregs(&self, r: &[u64; 27]) {
        unsafe { ptrace(SETREGS, self.pid, 0, r.as_ptr() as u64) };
    }
    fn peek(&self, addr: u64) -> u64 {
        set_errno(0);
        let v = unsafe { ptrace(PEEKDATA, self.pid, addr, 0) };
        let _ = errno();
        v as u64
    }
    fn poke(&self, addr: u64, val: u64) {
        unsafe { ptrace(POKEDATA, self.pid, addr, val) };
    }
    fn kill_now(&mut self) {
        if self.alive {
            unsafe {
                kill(self.pid, SIGKILL);
                let mut st = 0;
                waitpid(self.pid, &mut st, 0);
            }
            self.alive = false;
        }
    }
}

fn wexited(st: c_int) -> bool { (st & 0x7f) == 0 }
fn wstopped(st: c_int) -> bool { (st & 0xff) == 0x7f }
fn wstopsig(st: c_int) -> c_int { (st >> 8) & 0xff }

fn spawn_sealer(flag_core: &[u8], seed_env: Option<&str>) -> Child {
    let path_s = std::env::var("TQ_SEALER").unwrap_or_else(|_| "/tq/sealer".into());
    let mut path = path_s.into_bytes();
    path.push(0);
    let argv: [*const u8; 2] = [path.as_ptr(), std::ptr::null()];
    let flags = {
        let mut v = Vec::new();
        v.extend_from_slice(b"FLAG=H7CTF{");
        v.extend_from_slice(flag_core);
        v.extend_from_slice(b"}\0");
        v
    };
    let seed = seed_env.map(|s| {
        let mut v = Vec::new();
        v.extend_from_slice(b"TQ_SEED=");
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    });
    let pid = unsafe { fork() };
    if pid == 0 {
        unsafe {
            ptrace(TRACEME, 0, 0, 0);
            let mut envp: Vec<*const u8> = vec![flags.as_ptr()];
            if let Some(ref s) = seed {
                envp.push(s.as_ptr());
            }
            envp.push(std::ptr::null());
            execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            std::process::exit(127);
        }
    }
    let mut st = 0;
    unsafe { waitpid(pid, &mut st, 0) };
    Child { pid, alive: true }
}

struct Bp {
    addr: u64,
    orig: u8,
    active: bool,
}

fn set_bp(c: &Child, addr: u64) -> u8 {
    let w = c.peek(addr);
    let orig = (w & 0xff) as u8;
    c.poke(addr, (w & !0xff) | 0xcc);
    orig
}
fn clear_bp(c: &Child, addr: u64, orig: u8) {
    let w = c.peek(addr);
    c.poke(addr, (w & !0xff) | (orig as u64));
}

fn cont_to_bp(c: &mut Child, bps: &mut [Option<Bp>]) -> Option<u64> {
    loop {
        unsafe { ptrace(CONT, c.pid, 0, 0) };
        let mut st = 0;
        let w = unsafe { waitpid(c.pid, &mut st, 0) };
        if w < 0 {
            c.alive = false;
            return None;
        }
        if wexited(st) {
            c.alive = false;
            return None;
        }
        if wstopped(st) && wstopsig(st) == SIGTRAP {
            let mut regs = c.getregs();
            let rip = regs[R_RIP];
            let mut hit = None;
            for b in bps.iter().flatten() {
                if b.active && b.addr == rip - 1 {
                    hit = Some(b.addr);
                    break;
                }
            }
            if let Some(addr) = hit {
                let orig = bps.iter().flatten().find(|b| b.addr == addr).unwrap().orig;
                regs[R_RIP] = addr;
                c.setregs(&regs);
                clear_bp(c, addr, orig);
                unsafe { ptrace(SINGLESTEP, c.pid, 0, 0) };
                let mut s2 = 0;
                unsafe { waitpid(c.pid, &mut s2, 0) };
                if wexited(s2) {
                    c.alive = false;
                    return None;
                }
                let _ = set_bp(c, addr);
                return Some(addr);
            }
            continue;
        }
    }
}

struct Vm {
    r: [u64; 8],
    scratch: [u8; 512],
    zf: bool,
    lt: bool,
    pc: usize,
    gas: u64,
    prog: Vec<u8>,
}

#[derive(Debug)]
enum RunErr {
    Gas,
    BadOp,
    OobPoke,
    OobPeek,
    BadReg,
    Truncated,
    NoSubmit,
    StepLimit,
}

impl Vm {
    fn new(prog: Vec<u8>) -> Vm {
        Vm { r: [0; 8], scratch: [0; 512], zf: false, lt: false, pc: 0, gas: 0, prog }
    }
    fn u8(&mut self) -> Result<u8, RunErr> {
        let v = *self.prog.get(self.pc).ok_or(RunErr::Truncated)?;
        self.pc += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, RunErr> {
        let a = self.u8()? as u16;
        let b = self.u8()? as u16;
        Ok(a | (b << 8))
    }
    fn u64v(&mut self) -> Result<u64, RunErr> {
        let mut v = 0u64;
        for i in 0..8 {
            v |= (self.u8()? as u64) << (i * 8);
        }
        Ok(v)
    }
    fn charge(&mut self, g: u64) -> Result<(), RunErr> {
        self.gas += g;
        if self.gas > BUDGET {
            return Err(RunErr::Gas);
        }
        Ok(())
    }
    fn reg(&self, i: u8) -> Result<u64, RunErr> {
        self.r.get(i as usize).copied().ok_or(RunErr::BadReg)
    }
    fn regmut(&mut self, i: u8) -> Result<&mut u64, RunErr> {
        self.r.get_mut(i as usize).ok_or(RunErr::BadReg)
    }
}

struct RunOut {
    solved: bool,
    gas: u64,
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|s| {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { s.parse().ok() }
    }).unwrap_or(default)
}

fn run(prog: Vec<u8>, flag_core: &[u8], seed_env: Option<&str>) -> Result<RunOut, RunErr> {
    let win_base = env_u64("TQ_WIN_BASE", WIN_BASE);
    let _confess = env_u64("TQ_CONFESS", CONFESS);
    let mut vm = Vm::new(prog);
    let mut child = spawn_sealer(flag_core, seed_env);
    let mut bps: Vec<Option<Bp>> = (0..8).map(|_| None).collect();
    let mut submitted: Option<Vec<u8>> = None;
    let mut steps: u64 = 0;

    let res = (|| -> Result<(), RunErr> {
        loop {
            steps += 1;
            if steps > STEP_LIMIT {
                return Err(RunErr::StepLimit);
            }
            if vm.pc >= vm.prog.len() {
                return Ok(());
            }
            let op = vm.u8()?;
            match op {
                0x01 => {
                    vm.charge(0)?;
                    let d = vm.u8()?;
                    let imm = vm.u64v()?;
                    *vm.regmut(d)? = imm;
                }
                0x02 => {
                    vm.charge(0)?;
                    let d = vm.u8()?;
                    let s = vm.u8()?;
                    let sv = vm.reg(s)?;
                    *vm.regmut(d)? = sv;
                }
                0x03 => {
                    vm.charge(0)?;
                    let sub = vm.u8()?;
                    let d = vm.u8()?;
                    let s = vm.u8()?;
                    let a = vm.reg(d)?;
                    let b = vm.reg(s)?;
                    let out = match sub {
                        0 => a.wrapping_add(b),
                        1 => a.wrapping_sub(b),
                        2 => a ^ b,
                        3 => a & b,
                        4 => a | b,
                        5 => a.wrapping_shl(b as u32),
                        6 => a.wrapping_shr(b as u32),
                        7 => {
                            vm.zf = a == b;
                            vm.lt = a < b;
                            a
                        }
                        _ => return Err(RunErr::BadOp),
                    };
                    if sub != 7 {
                        *vm.regmut(d)? = out;
                    }
                }
                0x04 => {
                    vm.charge(10)?;
                    let slot = vm.u8()? as usize;
                    let addr = vm.u64v()?;
                    if slot >= 8 {
                        return Err(RunErr::BadReg);
                    }
                    if let Some(b) = bps[slot].take() {
                        if child.alive {
                            clear_bp(&child, b.addr, b.orig);
                        }
                    }
                    let orig = set_bp(&child, addr);
                    bps[slot] = Some(Bp { addr, orig, active: true });
                }
                0x05 => {
                    vm.charge(20)?;
                    let _slot = vm.u8()?;
                    let _off = vm.u16()?;
                    let _len = vm.u8()?;
                }
                0x06 => {
                    vm.charge(5)?;
                    let hit = cont_to_bp(&mut child, &mut bps);
                    vm.zf = hit.is_some();
                }
                0x07 => {
                    vm.charge(50)?;
                    if child.alive {
                        unsafe { ptrace(SINGLESTEP, child.pid, 0, 0) };
                        let mut st = 0;
                        unsafe { waitpid(child.pid, &mut st, 0) };
                        if wexited(st) {
                            child.alive = false;
                            vm.zf = false;
                        } else {
                            vm.zf = true;
                        }
                    } else {
                        vm.zf = false;
                    }
                }
                0x08 => {
                    vm.charge(1)?;
                    let d = vm.u8()?;
                    let id = vm.u8()?;
                    let idx = regid_to_idx(id).ok_or(RunErr::BadReg)?;
                    let val = if child.alive { child.getregs()[idx] } else { 0 };
                    *vm.regmut(d)? = val;
                }
                0x09 => {
                    vm.charge(2)?;
                    let d = vm.u8()?;
                    let off = vm.u16()? as u64;
                    if off + 8 > WIN_LEN {
                        return Err(RunErr::OobPeek);
                    }
                    let val = if child.alive { child.peek(win_base + off) } else { 0 };
                    *vm.regmut(d)? = val;
                }
                0x0a => {
                    let off = vm.u16()? as u64;
                    let s = vm.u8()?;
                    if off + 8 > WIN_LEN {
                        vm.charge(100)?;
                        return Err(RunErr::OobPoke);
                    }
                    vm.charge(4)?;
                    let val = vm.reg(s)?;
                    if child.alive {
                        child.poke(win_base + off, val);
                    }
                }
                0x0b => {
                    vm.charge(0)?;
                    let t = vm.u16()? as usize;
                    vm.pc = t;
                }
                0x0c => {
                    vm.charge(0)?;
                    let t = vm.u16()? as usize;
                    if vm.zf {
                        vm.pc = t;
                    }
                }
                0x0d => {
                    vm.charge(0)?;
                    let t = vm.u16()? as usize;
                    if !vm.zf {
                        vm.pc = t;
                    }
                }
                0x0e => {
                    vm.charge(0)?;
                    let t = vm.u16()? as usize;
                    if vm.lt {
                        vm.pc = t;
                    }
                }
                0x0f => {
                    vm.charge(0)?;
                    let off = vm.u16()? as usize;
                    let len = vm.u8()? as usize;
                    if off + len > vm.scratch.len() {
                        return Err(RunErr::OobPeek);
                    }
                    submitted = Some(vm.scratch[off..off + len].to_vec());
                    return Ok(());
                }
                0x10 => {
                    return Ok(());
                }
                0x11 => {
                    vm.charge(0)?;
                    let off = vm.u16()? as usize;
                    let s = vm.u8()?;
                    let v = vm.reg(s)? as u8;
                    if off < vm.scratch.len() {
                        vm.scratch[off] = v;
                    }
                }
                0x12 => {
                    vm.charge(0)?;
                    let idx = vm.u8()?;
                    let s = vm.u8()?;
                    let i = (vm.reg(idx)? as usize) & 511;
                    let v = vm.reg(s)? as u8;
                    vm.scratch[i] = v;
                }
                0x13 => {
                    vm.charge(0)?;
                    let d = vm.u8()?;
                    let off = vm.u16()? as usize;
                    let v = if off < vm.scratch.len() { vm.scratch[off] as u64 } else { 0 };
                    *vm.regmut(d)? = v;
                }
                0x14 => {
                    vm.charge(2)?;
                    let d = vm.u8()?;
                    let ro = vm.u8()?;
                    let off = vm.reg(ro)?;
                    if off + 8 > WIN_LEN {
                        return Err(RunErr::OobPeek);
                    }
                    let val = if child.alive { child.peek(win_base + off) } else { 0 };
                    *vm.regmut(d)? = val;
                }
                0x15 => {
                    let ro = vm.u8()?;
                    let s = vm.u8()?;
                    let off = vm.reg(ro)?;
                    if off + 8 > WIN_LEN {
                        vm.charge(100)?;
                        return Err(RunErr::OobPoke);
                    }
                    vm.charge(4)?;
                    let val = vm.reg(s)?;
                    if child.alive {
                        child.poke(win_base + off, val);
                    }
                }
                _ => return Err(RunErr::BadOp),
            }
        }
    })();

    child.kill_now();
    res?;
    let sub = submitted.ok_or(RunErr::NoSubmit)?;
    let solved = sub.len() == CORE && sub.as_slice() == flag_core;
    Ok(RunOut { solved, gas: vm.gas })
}

fn score(gas: u64, best_known: u64) -> f64 {
    let lb = (BUDGET as f64).ln();
    let lg = (gas.max(1) as f64).ln();
    let lo = (best_known.max(1) as f64).ln();
    let eff = ((lb - lg) / (lb - lo)).clamp(0.0, 1.0);
    0.25 + 0.75 * eff
}

fn main() {
    let mode = std::env::var("TQ_MODE").unwrap_or_else(|_| "sim".into());
    let best_known: u64 = std::env::var("TQ_BEST_KNOWN").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_BEST_KNOWN);
    let (flag_core, seed): (Vec<u8>, Option<String>) = if mode == "live" {
        let f = std::env::var("FLAG").unwrap_or_default();
        let core: Vec<u8> = {
            let inner = f.split('{').nth(1).unwrap_or("").trim_end_matches('}');
            inner.bytes().take(CORE).collect()
        };
        (if core.len() == CORE { core } else { b"AAAAAAAAAAAAAAAA".to_vec() }, None)
    } else {
        (b"simsimsimsimsimx".to_vec(), Some(std::env::var("TQ_SEED").unwrap_or_else(|_| "tqsim".into())))
    };

    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).ok();
    let prog: Vec<u8> = if buf.len() >= 4 {
        let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if n <= buf.len() - 4 && n <= MAX_PROG {
            buf[4..4 + n].to_vec()
        } else {
            buf
        }
    } else {
        buf
    };

    let out = match run(prog, &flag_core, seed.as_deref()) {
        Ok(o) => {
            let sc = if o.solved { score(o.gas, best_known) } else { 0.0 };
            let flag = if o.solved {
                let s = String::from_utf8_lossy(&flag_core);
                format!("H7CTF{{{}}}", s)
            } else {
                String::new()
            };
            format!(
                "{{\"solved\":{},\"gas\":{},\"score\":{:.4},\"flag\":\"{}\",\"err\":null}}",
                o.solved, o.gas, sc, flag
            )
        }
        Err(e) => format!(
            "{{\"solved\":false,\"gas\":0,\"score\":0,\"flag\":\"\",\"err\":\"{:?}\"}}",
            e
        ),
    };
    let mut so = std::io::stdout();
    so.write_all(out.as_bytes()).ok();
    so.write_all(b"\n").ok();
}
