//! Performance benchmark harness — IGNORED by default; run explicitly.
//!
//! ```text
//! cargo test --release --test perf_harness -- --ignored --nocapture
//! ```
//!
//! Two self-contained tiers. The inputs are generated in-process, so only this
//! generator is committed — never the (hundreds-of-KB) generated source:
//!
//!   Tier 1  Full compile of a large synthetic C translation unit
//!           (lex + preprocess + parse + codegen + object emit). Tracks the
//!           per-TU compile cost that the codegen / emit findings target.
//!   Tier 2  Preprocess of a TU that `#include`s one large *guarded* header,
//!           served from memory and re-included several times. Today every
//!           `#include` re-tokenizes the header from scratch (the include guard
//!           only skips re-*expansion*, not re-*lexing*, and there is no
//!           tokenize-once cache), so this isolates the header re-lexing cost —
//!           the lever a build-wide header cache would remove.
//!
//! The tests assert only that compilation SUCCEEDS; they never assert on
//! absolute timing (machine-dependent), so they are safe to keep in-tree as a
//! manual regression-tracking tool. Build `--release` for meaningful numbers
//! (the debug binary is ~4x slower). For a per-phase breakdown, run the `bcc`
//! binary with `MDBCC_TIME=1`.
//!
//! Sizes are overridable via env: MDBCC_BENCH_FUNCS, MDBCC_BENCH_HDR_MACROS,
//! MDBCC_BENCH_HDR_DECLS, MDBCC_BENCH_INCLUDES.

use std::hint::black_box;
use std::time::{Duration, Instant};

use mdbcc::codegen::target::TargetKind;
use mdbcc::compile::{compile_to_object_with_target, preprocess_to_tokens};
use mdbcc::pp::{DefaultResolver, IncludeResolver};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Self-contained C TU: `n_funcs` small arithmetic functions plus a `main`
/// that calls them all. No `#include`s, so it stresses parse + codegen + emit
/// without touching the preprocessor.
fn gen_c_tu(n_funcs: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n_funcs * 110 + 64);
    for i in 0..n_funcs {
        s.push_str(&format!(
            "int f{i}(int a,int b){{int x=a+b;int y=x*3-b;int z=(x^y)+(a<<2);\
             for(int k=0;k<4;k++){{z+=x*k-y;}}return z+{i};}}\n"
        ));
    }
    s.push_str("int main(void){int s=0;\n");
    for i in 0..n_funcs {
        s.push_str(&format!("s+=f{i}(s,{i});\n"));
    }
    s.push_str("return s&127;}\n");
    s.into_bytes()
}

/// Large *guarded* C header: `n_macros` object macros + `n_decls` function
/// declarations. Preprocesses cleanly (object macros only expand if used).
fn gen_big_header(n_macros: usize, n_decls: usize) -> Vec<u8> {
    let mut s = String::with_capacity((n_macros + n_decls) * 28 + 64);
    s.push_str("#ifndef BIGHDR_H\n#define BIGHDR_H\n");
    for i in 0..n_macros {
        s.push_str(&format!("#define BH_MACRO_{i} ({i} + 1)\n"));
    }
    for i in 0..n_decls {
        s.push_str(&format!("int bh_decl_{i}(int a, int b, int c);\n"));
    }
    s.push_str("#endif\n");
    s.into_bytes()
}

/// A TU that includes `bighdr.h` `n_includes` times (re-lexed each time today).
fn gen_includer(n_includes: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n_includes * 20 + 32);
    for _ in 0..n_includes {
        s.push_str("#include \"bighdr.h\"\n");
    }
    s.push_str("int main(void){return 0;}\n");
    s.into_bytes()
}

/// In-memory include resolver serving one header by name — isolates header
/// re-tokenization CPU from disk I/O variance.
struct MemResolver {
    name: String,
    body: Vec<u8>,
}

impl IncludeResolver for MemResolver {
    fn resolve(&self, name: &str, _system: bool) -> Option<Vec<u8>> {
        (name == self.name).then(|| self.body.clone())
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// min / median / max over a sorted copy of the samples.
fn stats(samples: &[Duration]) -> (Duration, Duration, Duration) {
    let mut v = samples.to_vec();
    v.sort();
    (v[0], v[v.len() / 2], v[v.len() - 1])
}

/// One untimed warmup, then `iters` timed iterations.
fn bench<F: FnMut()>(iters: usize, mut f: F) -> Vec<Duration> {
    f(); // warmup (fills caches / branch predictors; excluded from samples)
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed());
    }
    samples
}

fn report(label: &str, work: &str, samples: &[Duration]) {
    let (lo, med, hi) = stats(samples);
    println!(
        "[perf] {label:<30} {work:<14} min {:>9.3} ms  median {:>9.3} ms  max {:>9.3} ms  (n={})",
        ms(lo),
        ms(med),
        ms(hi),
        samples.len()
    );
}

#[test]
#[ignore = "perf benchmark; run with --release --ignored --nocapture"]
fn tier1_full_compile_synthetic_c() {
    let n_funcs = env_usize("MDBCC_BENCH_FUNCS", 2000);
    let src = gen_c_tu(n_funcs);
    let resolver = DefaultResolver {
        base_dir: ".".into(),
    };
    println!(
        "[perf] tier1 input: {n_funcs} functions, {} bytes",
        src.len()
    );
    let samples = bench(5, || {
        let obj = compile_to_object_with_target(&src, "bench.c", &resolver, TargetKind::Win64)
            .expect("tier1 synthetic TU must compile");
        black_box(&obj);
    });
    report("tier1 full compile (x64)", &format!("{n_funcs} fns"), &samples);
}

#[test]
#[ignore = "perf benchmark; run with --release --ignored --nocapture"]
fn tier2_preprocess_header_reinclude() {
    let n_macros = env_usize("MDBCC_BENCH_HDR_MACROS", 2000);
    let n_decls = env_usize("MDBCC_BENCH_HDR_DECLS", 2000);
    let n_includes = env_usize("MDBCC_BENCH_INCLUDES", 5);
    let header = gen_big_header(n_macros, n_decls);
    let resolver = MemResolver {
        name: "bighdr.h".into(),
        body: header.clone(),
    };
    let tu = gen_includer(n_includes);

    let mut tok_count = 0usize;
    let samples = bench(10, || {
        let toks = preprocess_to_tokens(&tu, "bench.c", &resolver, false)
            .expect("tier2 header TU must preprocess");
        tok_count = toks.len();
    });
    println!(
        "[perf] tier2 input: header {} bytes ({n_macros} macros + {n_decls} decls), {n_includes} includes/TU -> {tok_count} tokens/TU",
        header.len()
    );
    report("tier2 preprocess (re-lex hdr)", &format!("{n_includes}x incl"), &samples);
}
