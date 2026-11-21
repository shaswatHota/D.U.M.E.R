//! Core coordinator daemon binary entrypoint for D.U.M.E.R (`dumerd`).
#![forbid(unsafe_code)]

fn main() {
    let exit_code = dumerd::run_with_args(std::env::args());
    std::process::exit(exit_code);
}
