#!/usr/bin/env python3
"""Generate a test-only H2 peer; production checkout files are never patched."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

REVISION = "d66a790f895f80c76ea8c1cedadb84dd7958fde5"


def replace(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"source anchor changed: {old!r}")
    return source.replace(old, new, 1)


def generate(repo, output):
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    archive = subprocess.check_output(["git", "-C", str(repo), "archive", REVISION])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source, filter="data")
    original_dir = output / "original-source"
    original_dir.mkdir()
    shutil.copy2(source / "src/h2.rs", original_dir / "h2.rs")
    shutil.copytree(source / "src/h2", original_dir / "h2")
    (original_dir / "main.rs").write_text("mod h2;\n")
    here = Path(__file__).resolve().parent
    path = source / "src/h2.rs"
    code = path.read_text()
    code = replace(code, "pub struct Conn {", "pub struct Conn {\n    gate: Option<DrainGate>,")
    code = replace(code, "        Conn {", """        Conn {
            // Existing production unit tests retain their ordinary workload.
            // Dedicated gate tests below explicitly install the fixture state.
            #[cfg(test)]
            gate: None,
            #[cfg(not(test))]
            gate: Some(DrainGate::new()),""")
    code = replace(code, "    fn respond(&mut self, out: &mut Vec<u8>, stream: u32) {",
                   "    fn respond_ordinary(&mut self, out: &mut Vec<u8>, stream: u32) {")
    code = replace(code, "                                    for response in &mut self.pending {", """                                    if let Some(held) = self.gate.as_mut().and_then(|g| g.held.as_mut()) {
                                        let Some(window) = held.window.checked_add(delta) else {
                                            return self.fail(out, buf.len(), FLOW_CONTROL_ERROR);
                                        };
                                        held.window = window;
                                    }
                                    for response in &mut self.pending {""")
    code = replace(code, """                        self.resume(out);
                    }
                }
                WINDOW_UPDATE""", """                        self.resume(out);
                    } else if !self.drain_settings_ack() {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                }
                WINDOW_UPDATE""")
    code = replace(code, "                        if let Some(index) = self.pending_index(stream) {", """                        if !self.drain_credit(out, stream, increment)
                            && let Some(index) = self.pending_index(stream) {""")
    code = replace(code, "                    if let Some(index) = self.pending_index(stream) {", """                    self.drain_cancel(stream);
                    if let Some(index) = self.pending_index(stream) {""")
    code = replace(code, "                PING => {", """                PING => {
                    if self.gate.is_some() && (stream != 0 || len != 8) {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                    if flags & FLAG_ACK_OR_END_STREAM != 0 {
                        self.drain_ping(payload, out);
                    }""")
    code = replace(code, "            at += end;", """            self.drain_advance(out);
            if self.closing {
                return Some(buf.len());
            }
            at += end;""")
    code = replace(code, "        self.pending.clear();", "        self.gate = None;\n        self.pending.clear();")
    code += "\n" + (here / "h2-drain-gate.rs").read_text()
    code += '\n#[cfg(test)]\nmod drain_tests;\n'
    path.write_text(code)
    shutil.copy2(here / "h2-drain-tests.rs", source / "src/h2/drain_tests.rs")
    # The fixture deliberately adds one 32-byte bounded state object. Keep the
    # original 72-byte production-layout contract in an independent test below;
    # the generated copy must instead check the fixture's exact 104-byte layout.
    layout = source / "src/h2/receive_credit_tests.rs"
    layout.write_text(replace(layout.read_text(),
                              "assert_eq!(std::mem::size_of::<Conn>(), 72);",
                              "assert_eq!(std::mem::size_of::<Conn>(), 104);"))
    subprocess.run(["cargo", "fmt"], cwd=source, check=True)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--generate-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    source = generate(args.repo.resolve(), output)
    if args.generate_only:
        return
    original = output / "original-source/main.rs"
    subprocess.run(["rustc", "--test", "--edition=2024", str(original), "-o", str(output / "original-layout")], check=True)
    subprocess.run([str(output / "original-layout"), "receive_accounting_fits_existing_connection_padding"], check=True)
    env = os.environ | {"CARGO_TARGET_DIR": str(output / "target"), "CARGO_INCREMENTAL": "0"}
    commands = [["cargo", "fmt", "--check"],
                ["cargo", "test", "--locked"],
                ["cargo", "test", "--release", "--locked"],
                ["cargo", "clippy", "--locked", "--bin", "hfast", "--", "-D", "warnings"],
                ["cargo", "build", "--release", "--locked"]]
    for i, command in enumerate(commands):
        print(" ".join(command), flush=True)
        with (output / f"check-{i}.log").open("x") as log:
            subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = output / "h2-drain-peer"
    shutil.copy2(output / "target/release/hfast", binary)
    binary.chmod(0o555)
    (output / "manifest.json").write_text(json.dumps(dict(
        revision=REVISION, commands=commands, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        compiler=subprocess.check_output(["rustc", "-Vv"], text=True),
        sources={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(source.rglob("*.rs"))},
        inputs={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                [Path(__file__), here_file("h2-drain-gate.rs"), here_file("h2-drain-tests.rs")]},
    ), indent=2) + "\n")
    print(binary)


def here_file(name):
    return Path(__file__).resolve().parent / name


if __name__ == "__main__":
    main()
