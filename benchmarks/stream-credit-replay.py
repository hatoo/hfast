#!/usr/bin/env python3
"""Build a replay of the actual credit/frame/wire modules from either source tree.

First cargo build --release --locked in that tree. Output files must not exist.
Uses the production modules and substitutes only Connection::LOSS_THRESHOLD.
"""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--deps", type=Path, help="release/deps from a matching production build")
args = parser.parse_args()
source = args.source.resolve()
output = args.output.resolve()
deps = (args.deps or source / "target/release/deps").resolve()
rustls = list(deps.glob("librustls-*.rlib"))
assert len(rustls) == 1, "use a separate production target with exactly one rustls build"
assert not output.exists()
harness = Path(__file__).with_suffix(".rs").read_text()
prefix, appendix = harness.split(
    "// Appended inside the production stream_credit module by stream-credit-replay.py.")
credit = (source / "src/quic/conn/stream_credit.rs").read_text()
credit = "\n".join(line for line in credit.splitlines() if not line.startswith("//!"))
text = prefix + f'''
#[path = "{source}/src/quic/wire.rs"] mod wire;
#[path = "{source}/src/quic/frame.rs"] mod frame;
use wire::{{put_varint, varint_len}};
struct Connection;
impl Connection {{ const LOSS_THRESHOLD: u64 = 3; }}
mod stream_credit {{
{credit}
{appendix}
pub fn run(mode: &str, n: usize, iterations: usize) {{ replay::run(mode, n, iterations); }}
}}
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    stream_credit::run(&args[1], args[2].parse().unwrap(), args[3].parse().unwrap());
}}
'''
generated = output.with_suffix(".rs")
generated.open("x").write(text)
subprocess.run([
    "rustc", "--edition=2024", "-C", "opt-level=3", "-C", "lto=fat",
    "-C", "codegen-units=1", "-A", "dead_code", "-L", f"dependency={deps}",
    "--extern", f"rustls={rustls[0]}", str(generated), "-o", str(output),
], check=True)
