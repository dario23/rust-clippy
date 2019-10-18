use if_chain::if_chain;
use rustc::hir::{Expr, ExprKind, QPath};
use rustc::lint::{LateContext, LateLintPass, LintPass};
use rustc::{declare_lint_pass, declare_tool_lint};
use rustc::lint::LintArray;
use crate::utils::{match_path, span_lint};

declare_clippy_lint! {
    /// **What it does:** Checks for calls to intrinsics that have stable counterparts.
    ///
    /// **Why is this bad?** The stabilized variants often avoid raw pointer types and similar and
    /// often embed the provided functionality into a safer abstraction.
    ///
    /// **Known problems:** None.
    ///
    /// **Example:**
    /// ```rust
    /// // Bad
    /// let s = core::intrinsics::size_of::<String>();
    ///
    /// // Good
    /// let s = std::mem::size_of::<String>();
    /// ```
    pub STABILIZED_INTRINSICS,
    style,
    "checks for calls to intrinsics with stable counterparts"
}

declare_lint_pass!(StabilizedIntrinsics => [STABILIZED_INTRINSICS]);

const STABILIZED_INTRINSIC_NAMES : &[(&str, &str)] = &[
    ("add_with_oveflow", "`overflowing_add` on integer types"),

    ("atomic_and", "`fetch_and` on std::sync::atomic types"),
    ("atomic_and_acq", "`fetch_and` on std::sync::atomic types"),
    ("atomic_and_acqrel", "`fetch_and` on std::sync::atomic types"),
    ("atomic_and_rel", "`fetch_and` on std::sync::atomic types"),
    ("atomic_and_relaxed", "`fetch_and` on std::sync::atomic types"),

    ("atomic_cxchg", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_acq", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_acqrel", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_acqrel_failrelaxed", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_failacq", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_failrelaxed", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_rel", "`compare_exchange` on std::sync::atomic types"),
    ("atomic_cxchg_relaxed", "`compare_exchange` on std::sync::atomic types"),

    ("atomic_cxchgweak", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_acq", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_acq_failrelaxed", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_acqrel", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_acqrel_failrelaxed", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_failacq", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_failrelaxed", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_rel", "`compare_exchange_weak` on std::sync::atomic types"),
    ("atomic_cxchgweak_relaxed", "`compare_exchange_weak` on std::sync::atomic types"),


    ("atomic_load", "`load` on std::sync::atomic types"),
    ("atomic_load_acq", "`load` on std::sync::atomic types"),
    ("atomic_load_relaxed", "`load` on std::sync::atomic types"),

    ("atomic_nand", "`fetch_nand` on std::sync::atomic::AtomicBool"),
    ("atomic_nand_acq", "`fetch_nand` on std::sync::atomic::AtomicBool"),
    ("atomic_nand_acqrel", "`fetch_nand` on std::sync::atomic::AtomicBool"),
    ("atomic_nand_rel", "`fetch_nand` on std::sync::atomic::AtomicBool"),
    ("atomic_nand_relaxed", "`fetch_nand` on std::sync::atomic::AtomicBool"),

    ("atomic_or", "`fetch_or` on std::sync::atomic types"),
    ("atomic_or_acq", "`fetch_or` on std::sync::atomic types"),
    ("atomic_or_acqrel", "`fetch_or` on std::sync::atomic types"),
    ("atomic_or_rel", "`fetch_or` on std::sync::atomic types"),
    ("atomic_or_relaxed", "`fetch_or` on std::sync::atomic types"),

    ("atomic_store", "`store` on std::sync::atomic types"),
    ("atomic_store_rel", "`store` on std::sync::atomic types"),
    ("atomic_store_relaxed", "`store` on std::sync::atomic types"),

    ("atomic_xadd", "`fetch_add` on std::sync::atomic::AtomicBool"),
    ("atomic_xadd_acq", "`fetch_add` on std::sync::atomic::AtomicBool"),
    ("atomic_xadd_acqrel", "`fetch_add` on std::sync::atomic::AtomicBool"),
    ("atomic_xadd_rel", "`fetch_add` on std::sync::atomic::AtomicBool"),
    ("atomic_xadd_relaxed", "`fetch_add` on std::sync::atomic::AtomicBool"),

    ("atomic_xchg", "`swap` on std::sync::atomic::AtomicBool"),
    ("atomic_xchg_acq", "`swap` on std::sync::atomic::AtomicBool"),
    ("atomic_xchg_acqrel", "`swap` on std::sync::atomic::AtomicBool"),
    ("atomic_xchg_rel", "`swap` on std::sync::atomic::AtomicBool"),
    ("atomic_xchg_relaxed", "`swap` on std::sync::atomic::AtomicBool"),

    ("atomic_xor", "`fetch_xor` on std::sync::atomic::AtomicBool"),
    ("atomic_xor_acq", "`fetch_xor` on std::sync::atomic::AtomicBool"),
    ("atomic_xor_acqrel", "`fetch_xor` on std::sync::atomic::AtomicBool"),
    ("atomic_xor_rel", "`fetch_xor` on std::sync::atomic::AtomicBool"),
    ("atomic_xor_relaxed", "`fetch_xor` on std::sync::atomic::AtomicBool"),

    ("atomic_xsub", "`fetch_sub` on std::sync::atomic::AtomicBool"),
    ("atomic_xsub_acq", "`fetch_sub` on std::sync::atomic::AtomicBool"),
    ("atomic_xsub_acqrel", "`fetch_sub` on std::sync::atomic::AtomicBool"),
    ("atomic_xsub_rel", "`fetch_sub` on std::sync::atomic::AtomicBool"),
    ("atomic_xsub_relaxed", "`fetch_sub` on std::sync::atomic::AtomicBool"),

    ("mul_with_overflow", "`overflowing_mul` on integer types"),

    ("overflowing_add", "`wrapping_add` on integer types"),
    ("overflowing_mul", "`wrapping_mul` on integer types"),

    ("rotate_left", "`rotate_left` on integer types"),
    ("rotate_right", "`rotate_right` on integer types"),

    ("saturating_add", "`saturating_add` on integer types"),
    ("saturating_sub", "`saturating_sub` on integer types"),

    ("sub_with_overflow", "`overflowing_sub` on integer types"),

    ("volatile_load", "`std::ptr::read_volatile`"),
    ("volatile_store", "`std::ptr::store_volatile`"),

    // TODO: these didn't have comments in the overview, maybe others don't as well?
    ("size_of", "`std::mem::size_of`"),
    ("transmute", "`std::mem::transmute`"),
];

impl<'a, 'tcx> LateLintPass<'a, 'tcx> for StabilizedIntrinsics {
    fn check_expr(&mut self, cx: &LateContext<'a, 'tcx>, expr: &'tcx Expr) {
        if_chain! {
            if let ExprKind::Call(ref path, ..) = expr.kind;
            if let ExprKind::Path(ref qpath) = path.kind;
            if let QPath::Resolved(_, ref rpath) = qpath; // TODO: non-resolved missing here, hopefully not neccessary..
            then {
                for &(ipath, stabilized_msg) in STABILIZED_INTRINSIC_NAMES {
                    if match_path(rpath, &["intrinsics", ipath]) {
                        span_lint(
                            cx,
                            STABILIZED_INTRINSICS,
                            expr.span,
                            &format!("`{}` is stabilized as {}", ipath, stabilized_msg));
                    }
                }
            }
        }
    }
}
