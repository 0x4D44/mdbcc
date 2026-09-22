//! Q0/Q1 compiler quality-map seed.
//!
//! This is deliberately a cheap, deterministic test-side report. It does not
//! run proprietary or GUI oracles; it records their current contract, skip
//! semantics, and reproduction commands so the expensive suites can feed one
//! ranked backlog instead of scattered one-off notes.

use std::cmp::Reverse;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuiteMode {
    AlwaysOn,
    SelfSkipping,
    IgnoredManual,
    Mixed,
}

impl SuiteMode {
    fn label(self) -> &'static str {
        match self {
            SuiteMode::AlwaysOn => "always-on",
            SuiteMode::SelfSkipping => "self-skipping",
            SuiteMode::IgnoredManual => "ignored/manual",
            SuiteMode::Mixed => "mixed",
        }
    }
}

#[derive(Clone, Copy)]
struct OracleInventory {
    oracle: &'static str,
    file: &'static str,
    prerequisites: &'static str,
    current_floor: &'static str,
    current_known_gaps: &'static str,
    mode: SuiteMode,
    skip_contract: &'static str,
}

const ORACLE_INVENTORY: &[OracleInventory] = &[
    OracleInventory {
        oracle: "O1 executable and byte-identity stripes",
        file: "tests/end_to_end.rs, tests/o1_byte_identity.rs, tests/o1_x86_byte_identity.rs",
        prerequisites: "none",
        current_floor: "authoritative hand-expected runtime plus byte baselines",
        current_known_gaps: "scope is curated; not a real-program corpus",
        mode: SuiteMode::AlwaysOn,
        skip_contract: "no skip contract; failures are regressions",
    },
    OracleInventory {
        oracle: "O2/O3 differential corpus",
        file: "tests/differential.rs",
        prerequisites: "MSVC cl and/or Borland bcc32 5.5.1 on Windows",
        current_floor: "zero external active is a hard oracle-health halt",
        current_known_gaps: "portable/dialect skip directives are fixture-boundary filters",
        mode: SuiteMode::Mixed,
        skip_contract: "tool absence is environment state, not success",
    },
    OracleInventory {
        oracle: "external GCC torture pilot",
        file: "tests/external_corpus_adapter.rs",
        prerequisites: "local llvm-test-suite checkout; optional MSVC cl reference",
        current_floor: "20 curated LLVM/GCC torture execute fixtures; ignored runner compares 19 UTF-8 fixtures, with hand oracle fallback",
        current_known_gaps: "temp-checkout probe: 15 pass, 1 non-UTF8 boundary exclude, 4 mdbcc no-runnable reds; implicit-int reduction is committed ignored",
        mode: SuiteMode::IgnoredManual,
        skip_contract: "missing checkout/toolchain is environment state, not external corpus success",
    },
    OracleInventory {
        oracle: "deterministic fuzz/reduction pilot",
        file: "tests/fuzz_reduction_path.rs",
        prerequisites: "none for seed/reducer determinism; ignored red-path uses current mdbcc against a C89 hand oracle",
        current_floor: "one recorded mini-fuzzer seed generates a C89 candidate, detects the implicit-int divergence, and reduces it to `main(){return 0;}`",
        current_known_gaps: "process proof only; Csmith/YARPGen and external differential references are not wired yet",
        mode: SuiteMode::Mixed,
        skip_contract: "ignored red-path/manual fuzz runs are environment state, not broad fuzz coverage success",
    },
    OracleInventory {
        oracle: "generated ABI/calling-convention torture",
        file: "tests/abi_torture.rs",
        prerequisites: "Windows runtime; WOW64 for i386 arm",
        current_floor: "10 deterministic Win64/i386 hand-expected cases over historical ABI bug classes",
        current_known_gaps: "no MSVC/BCC differential arm yet; no reducer-fed generated regressions yet",
        mode: SuiteMode::Mixed,
        skip_contract: "WOW64 spawn refusal is environment state, not i386 ABI success",
    },
    OracleInventory {
        oracle: "O12 i386 portable corpus",
        file: "tests/oracle_o12_x86_corpus.rs",
        prerequisites: "BC4.52 BCC32/TLINK oracle",
        current_floor: "MATCH >= 20 over tests/corpus/portable",
        current_known_gaps: "ratchet prints COMPILE-GAP/MISMATCH/RUN-SKIP/REF-GAP table",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "BC4.52 absence is environment state, not success",
    },
    OracleInventory {
        oracle: "O12 i386 88-program e2e",
        file: "tests/oracle_o12_x86_e2e.rs",
        prerequisites: "BC4.52 BCC32/TLINK oracle",
        current_floor: "MATCH >= 83 / 88; 5 remaining are reference gaps",
        current_known_gaps: "inline asm/tasm32, C89 mid-block decl, private base-member access are REF-GAP",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "BC4.52 absence is environment state, not success",
    },
    OracleInventory {
        oracle: "O13 COFF/OMF structural parity",
        file: "tests/oracle_o13_coff_parity.rs",
        prerequisites: "BC4.52 BCC32 oracle",
        current_floor: "13 fixture symbol-parity checks",
        current_known_gaps: "section-size and COMDEF deltas are advisory, not gate failures",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "BC4.52 absence is environment state, not success",
    },
    OracleInventory {
        oracle: "generated structural invariants",
        file: "tests/structural_invariants.rs",
        prerequisites: "none",
        current_floor: "relocation bounds, section references, strong symbol uniqueness, alignment flags, section aux records, vtable/typeinfo layout, Win64/i386 call-frame shape, Win64 unwind shape",
        current_known_gaps: "linked PE layout invariants remain in separate tests",
        mode: SuiteMode::AlwaysOn,
        skip_contract: "no skip contract; failures are regressions",
    },
    OracleInventory {
        oracle: "O14 OMF decode/link wiring",
        file: "tests/oracle_o14_omf_link.rs",
        prerequisites: "BC4.52 BCC32 oracle",
        current_floor: "5 OMF decode fixtures plus OMF input wiring sentinel",
        current_known_gaps: "full runnable PE oracle waits on i386 PE writer",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "BC4.52 absence is environment state, not success",
    },
    OracleInventory {
        oracle: "O15 header preprocess acceptance",
        file: "tests/oracle_o15_header_acceptance.rs",
        prerequisites: "BC4.52 INCLUDE tree",
        current_floor: "ACCEPT >= 241 / 246",
        current_known_gaps: "5 remaining standalone header-context/reference guards",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "INCLUDE absence is environment state, not success",
    },
    OracleInventory {
        oracle: "real-header compile/parse ratchets",
        file: "tests/oracle_real_headers.rs",
        prerequisites: "BC4.52 INCLUDE tree; optional BCC32 diff arm",
        current_floor: "C parse >= 112 / 246; C++ parse >= 126 / 246",
        current_known_gaps: "many standalone rejects need windows.h context; genuine gaps include signal/function-pointer declarators and C++ forms",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "INCLUDE/BCC absence is environment state, not full differential success",
    },
    OracleInventory {
        oracle: "S4 ClassLib and MI/RTTI",
        file: "tests/oracle_s4_classlib.rs",
        prerequisites: "BC4.52 INCLUDE tree; optional BCC32 diff arm",
        current_floor: "TArrayAsVector<long> runs 18; MI+RTTI fixture runs 20; date overload compile pin",
        current_known_gaps: "TArrayAsVector<int> is a pinned bcc32 reference ambiguity",
        mode: SuiteMode::SelfSkipping,
        skip_contract: "INCLUDE/BCC absence is environment state, not full differential success",
    },
    OracleInventory {
        oracle: "stock OWL product matrix",
        file: "tests/owl_examples_product.rs",
        prerequisites: "BC4.52 source tree, Win64 BC45 libs, interactive desktop",
        current_floor: "11 stock entries; BUTTON and INSTANCE are green baselines",
        current_known_gaps: "STATIC close heap corruption; HELLO/POPUP launch crash; GROUPBOX launch exception; EDIT/GAUGE/LISTBOX/COMBOBOX/SLIDER link helpers",
        mode: SuiteMode::IgnoredManual,
        skip_contract: "missing fixtures/libs/desktop are environment state, not product success",
    },
    OracleInventory {
        oracle: "RailC source and Win64 OWL smoke",
        file: "tests/railc_source_slice.rs",
        prerequisites: "Arthur's RailC corpus, release tools, BC45 libs, optional GUI golden",
        current_floor: "manifest, compile, Win64 link, runtime/dialog/KINGSX parity gates",
        current_known_gaps: "ignored due local corpus; KINGSX parity has explicit oracle-skip when golden fixtures are absent",
        mode: SuiteMode::IgnoredManual,
        skip_contract: "missing corpus/golden is environment state, not parity success",
    },
    OracleInventory {
        oracle: "resource compiler byte oracles",
        file: "tests/rc_res.rs, tests/rc_railc.rs, tests/pe_rsrc.rs",
        prerequisites: "BRC32 for differential arm; optional railc golden .res",
        current_floor: "BRC/resource byte-differentials plus hand-golden fallback and RailC .res parity",
        current_known_gaps: "external BRC absence weakens differential arm; RailC golden absence self-skips",
        mode: SuiteMode::Mixed,
        skip_contract: "external/golden absence is environment state, not byte-parity success",
    },
];

#[derive(Clone, Copy)]
struct BacklogItem {
    title: &'static str,
    area: &'static str,
    phase_reached: &'static str,
    oracle_strength: &'static str,
    unlock_value: &'static str,
    risk: &'static str,
    source: &'static str,
    repro: &'static str,
    reference_gap: bool,
    score: u32,
}

const BACKLOG: &[BacklogItem] = &[
    BacklogItem {
        title: "Root-cause GROUPBOX unhandled class exception before first window",
        area: "runtime / GUI/OWL",
        phase_reached: "launch",
        oracle_strength: "product-path",
        unlock_value: "stock OWL control runtime breadth",
        risk: "unhandled class exception",
        source: "tests/owl_examples_product.rs",
        repro: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
        reference_gap: false,
        score: 940,
    },
    BacklogItem {
        title: "Resolve OWL/common-dialog/GDI helper link gaps for EDIT/GAUGE/LISTBOX/COMBOBOX/SLIDER",
        area: "linker / runtime libraries",
        phase_reached: "link",
        oracle_strength: "product-path",
        unlock_value: "stock OWL control matrix",
        risk: "real-program link blocker",
        source: "tests/owl_examples_product.rs",
        repro: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
        reference_gap: false,
        score: 930,
    },
    BacklogItem {
        title: "Root-cause STATIC close-time heap corruption",
        area: "runtime / GUI/OWL",
        phase_reached: "close",
        oracle_strength: "product-path window smoke",
        unlock_value: "stock OWL runtime stability",
        risk: "crash/corruption",
        source: "scratchpad.md; tests/owl_examples_product.rs",
        repro: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
        reference_gap: false,
        score: 920,
    },
    BacklogItem {
        title: "Root-cause HELLO/POPUP launch crash before first window",
        area: "ABI / runtime / GUI/OWL",
        phase_reached: "launch",
        oracle_strength: "product-path launch smoke",
        unlock_value: "stock OWL app breadth",
        risk: "crash/corruption",
        source: "scratchpad.md; tests/owl_examples_product.rs",
        repro: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
        reference_gap: false,
        score: 910,
    },
    BacklogItem {
        title: "Extend generated ABI torture with external differentials and reducer-fed cases",
        area: "ABI",
        phase_reached: "compile/link/run",
        oracle_strength: "generated hand checksum; needs differential arm",
        unlock_value: "Win64 OWL and i386 parity",
        risk: "miscompile/corruption",
        source: "tests/abi_torture.rs; wrk_docs/2026.06.19 - GOAL - compiler quality and oracle expansion.md",
        repro: "mdtimeout 120 -- cargo test -q --test abi_torture -- --nocapture",
        reference_gap: false,
        score: 780,
    },
    BacklogItem {
        title: "Extend structural invariants to linked PE layout",
        area: "object writer / ABI",
        phase_reached: "object",
        oracle_strength: "structural invariant; object checks active",
        unlock_value: "narrows ABI/link root causes before runtime",
        risk: "miscompile/maintainability",
        source: "tests/structural_invariants.rs; tests/oracle_o13_coff_parity.rs; tests/oracle_o14_omf_link.rs",
        repro: "mdtimeout 120 -- cargo test -q --test structural_invariants -- --nocapture",
        reference_gap: false,
        score: 740,
    },
    BacklogItem {
        title: "Lift real-header C++ parse acceptance beyond 126 with context-aware gap split",
        area: "parser / template dialect",
        phase_reached: "parse",
        oracle_strength: "real-header ratchet",
        unlock_value: "ClassLib and OWL header breadth",
        risk: "unsupported syntax",
        source: "tests/oracle_real_headers.rs",
        repro: "cargo test -q --test oracle_real_headers o15_parse_acceptance_cxx_mode_ratchet -- --nocapture",
        reference_gap: false,
        score: 760,
    },
    BacklogItem {
        title: "Triage GCC torture pilot reds and decide C89 implicit-int support",
        area: "parser / C dialect",
        phase_reached: "compile/run differential",
        oracle_strength: "external runnable corpus plus reduced regression",
        unlock_value: "portable C behaviour beyond hand corpus",
        risk: "unsupported syntax / false corpus boundary",
        source: "tests/external_corpus_adapter.rs",
        repro: "MDBCC_LLVM_TEST_SUITE=<checkout> mdtimeout 120 -- cargo test -q --test external_corpus_adapter llvm_gcc_torture_external_corpus_pilot_msvc -- --ignored --nocapture",
        reference_gap: false,
        score: 720,
    },
    BacklogItem {
        title: "Promote deterministic fuzz pilot to Csmith/YARPGen differentials",
        area: "test infrastructure",
        phase_reached: "reduced regression",
        oracle_strength: "fuzz-reduced C89 hand oracle; external differential pending",
        unlock_value: "unknown codegen/parser gaps",
        risk: "crash/miscompile",
        source: "tests/fuzz_reduction_path.rs; tests/external_corpus_adapter.rs",
        repro: "mdtimeout 120 -- cargo test -q --test fuzz_reduction_path fuzz_generate_diff_reduce_regresses_c89_implicit_int_main -- --ignored --nocapture",
        reference_gap: false,
        score: 660,
    },
    BacklogItem {
        title: "Complete O14 runnable i386 OMF-to-PE oracle",
        area: "linker / PE writer",
        phase_reached: "object/link",
        oracle_strength: "structural now; runnable differential target",
        unlock_value: "Borland OMF compatibility",
        risk: "link failure",
        source: "tests/oracle_o14_omf_link.rs",
        repro: "cargo test -q --test oracle_o14_omf_link -- --nocapture",
        reference_gap: false,
        score: 620,
    },
    BacklogItem {
        title: "Keep O12 REF-GAPs out of mdbcc backlog",
        area: "reference hygiene",
        phase_reached: "run differential",
        oracle_strength: "differential",
        unlock_value: "i386 parity clarity",
        risk: "false backlog item",
        source: "tests/oracle_o12_x86_e2e.rs",
        repro: "cargo test -q --test oracle_o12_x86_e2e -- --nocapture",
        reference_gap: true,
        score: 200,
    },
];

const DUPLICATED_CLASSIFICATIONS: &[&str] = &[
    "O12 corpus and O12 e2e duplicate MATCH/MISMATCH/COMPILE-GAP/RUN-SKIP/REF-GAP status logic.",
    "BC4.52 absent self-skip strings recur across O13/O14/O15/real-header/S4 suites.",
    "Stock OWL failures were duplicated between scratchpad prose and the two-entry product test; the OWL matrix is now the canonical test-side list.",
];

const SOFT_SKIP_AUDIT: &[&str] = &[
    "oracle_real_headers can run mdbcc-only when BCC32 is absent; quality map must label that as partial differential evidence.",
    "railc_source_slice O6 KINGSX parity skips when golden fixtures or pwsh are absent; quality map must label that as environment state.",
    "owl_examples_product can build-only when no interactive desktop is present; quality map must not call that full window-smoke success.",
];

#[derive(Clone, Copy)]
struct MapDrivenOutcome {
    decision: &'static str,
    before: &'static str,
    after: &'static str,
    evidence: &'static str,
}

const MAP_DRIVEN_OUTCOMES: &[MapDrivenOutcome] = &[
    MapDrivenOutcome {
        decision: "Q5 fix: add generated ABI torture instead of leaving ABI risk as prose",
        before: "quality map had ABI risk but no generated Win64/i386 matrix",
        after: "tests/abi_torture.rs pins 10 historical calling-convention classes",
        evidence: "mdtimeout 120 -- cargo test -q --test abi_torture -- --nocapture",
    },
    MapDrivenOutcome {
        decision: "Q6 fix: add always-on object structural invariants",
        before: "O13/O14 parity existed but no generated invariant gate for fresh objects",
        after: "tests/structural_invariants.rs gates relocation, symbol, section, RTTI, call-frame, and unwind shapes",
        evidence: "mdtimeout 120 -- cargo test -q --test structural_invariants -- --nocapture",
    },
    MapDrivenOutcome {
        decision: "Q3 deferral: classify external C reds and commit a reduced implicit-int regression",
        before: "external runnable C corpus was not wired into the map",
        after: "tests/external_corpus_adapter.rs records 15 pass / 1 boundary exclude / 4 mdbcc reds on the pilot checkout",
        evidence: "MDBCC_LLVM_TEST_SUITE=<checkout> mdtimeout 120 -- cargo test -q --test external_corpus_adapter llvm_gcc_torture_external_corpus_pilot_msvc -- --ignored --nocapture",
    },
    MapDrivenOutcome {
        decision: "Q4 deferral: prove the fuzz path on the same reduced C89 bug before scaling generators",
        before: "fuzzing was a process requirement with no seed, reducer, or regression handoff",
        after: "tests/fuzz_reduction_path.rs records seed 0x4d42cc0000000001 and reduces to `main(){return 0;}`",
        evidence: "mdtimeout 120 -- cargo test -q --test fuzz_reduction_path fuzz_generate_diff_reduce_regresses_c89_implicit_int_main -- --ignored --nocapture",
    },
    MapDrivenOutcome {
        decision: "GROUPBOX/EDIT overload fix: preserve promoted constructor defaults",
        before: "GROUPBOX/EDIT failed with constructor overload/default diagnostics in the OWL product matrix",
        after: "GROUPBOX builds and reaches launch exception 0xE0000002; EDIT reaches TExampleEdit::EditTextLen member lookup",
        evidence: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
    },
    MapDrivenOutcome {
        decision: "EDIT static default fix: qualify later-declared class static members in defaults",
        before: "EDIT failed codegen on TExampleEdit::EditTextLen after constructor defaults were preserved",
        after: "EDIT reaches link, blocked by GetFileTitleA/GetSaveFileNameA/GetWindowDC/TDC::GetTextExtent/TTinyCaption::DoNCActivate; GROUPBOX remains launch exception 0xE0000002",
        evidence: "mdtimeout 900 -- cargo test --release --test owl_examples_product owl_stock_product_matrix_win64 -- --ignored --nocapture --test-threads=1",
    },
];

#[test]
fn quality_map_prints_ranked_compiler_backlog() {
    assert!(
        ORACLE_INVENTORY.len() >= 10,
        "Q0 inventory should cover the major oracle families"
    );
    assert!(
        BACKLOG.iter().filter(|item| !item.reference_gap).count() >= 10,
        "Q1 needs at least ten mdbcc work items before reference gaps"
    );
    for entry in ORACLE_INVENTORY {
        if matches!(
            entry.mode,
            SuiteMode::SelfSkipping | SuiteMode::IgnoredManual | SuiteMode::Mixed
        ) {
            assert!(
                entry.skip_contract.contains("environment state"),
                "{} must not treat skipped prerequisites as success",
                entry.oracle
            );
        }
    }

    println!("\n=== Q0 oracle signal inventory ===");
    println!("oracle | mode | prerequisites | floor | known gaps | skip contract | file");
    for entry in ORACLE_INVENTORY {
        println!(
            "{} | {} | {} | {} | {} | {} | {}",
            entry.oracle,
            entry.mode.label(),
            entry.prerequisites,
            entry.current_floor,
            entry.current_known_gaps,
            entry.skip_contract,
            entry.file
        );
    }

    println!("\n=== duplicated classifications to unify ===");
    for item in DUPLICATED_CLASSIFICATIONS {
        println!("- {item}");
    }

    println!("\n=== soft/partial skip audit ===");
    for item in SOFT_SKIP_AUDIT {
        println!("- {item}");
    }

    assert!(
        MAP_DRIVEN_OUTCOMES.len() >= 3,
        "first quality map must drive at least three concrete fixes or deliberate deferrals"
    );
    println!("\n=== map-driven outcomes ===");
    for item in MAP_DRIVEN_OUTCOMES {
        println!(
            "- decision: {} | before: {} | after: {} | evidence: {}",
            item.decision, item.before, item.after, item.evidence
        );
    }

    let mut ranked: Vec<BacklogItem> = BACKLOG
        .iter()
        .copied()
        .filter(|item| !item.reference_gap)
        .collect();
    ranked.sort_by_key(|item| (Reverse(item.score), item.title));
    let top_ten = &ranked[..10.min(ranked.len())];

    println!(
        "\n=== Q1 ranked compiler backlog: top {} ===",
        top_ten.len()
    );
    println!("rank | score | title | area | phase | oracle | unlock | risk | source | repro");
    for (ix, item) in top_ten.iter().enumerate() {
        println!(
            "{} | {} | {} | {} | {} | {} | {} | {} | {} | {}",
            ix + 1,
            item.score,
            item.title,
            item.area,
            item.phase_reached,
            item.oracle_strength,
            item.unlock_value,
            item.risk,
            item.source,
            item.repro
        );
    }

    println!("\n=== known reference gaps, not mdbcc work items ===");
    for item in BACKLOG.iter().filter(|item| item.reference_gap) {
        println!("- {} ({}) [{}]", item.title, item.source, item.repro);
    }

    assert!(
        top_ten
            .iter()
            .any(|item| item.source.contains("tests/owl_examples_product.rs")),
        "stock OWL product failures should feed the first map"
    );
    assert!(
        BACKLOG
            .iter()
            .any(|item| item.reference_gap && item.source.contains("oracle_o12_x86_e2e")),
        "known reference gaps must be represented separately from mdbcc gaps"
    );
}
