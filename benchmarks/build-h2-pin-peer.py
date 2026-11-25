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


def generate(repo, output, trace=False):
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
    code = replace(code, "pub struct Conn {", "pub struct Conn {\n    gate: Option<PinGate>,")
    code = replace(code, "        Conn {", """        Conn {
            // Existing production unit tests retain their ordinary workload.
            // Dedicated gate tests below explicitly install the fixture state.
            #[cfg(test)]
            gate: None,
            #[cfg(not(test))]
            gate: Some(PinGate::new()),""")
    code = replace(code, "    fn respond(&mut self, out: &mut Vec<u8>, stream: u32) {",
                   "    fn respond_ordinary(&mut self, out: &mut Vec<u8>, stream: u32) {")
    code = replace(code, "                                    for response in &mut self.pending {", """                                    for held in self.gate.iter_mut().flat_map(|g| g.held.iter_mut().flatten()) {
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
                    } else if !self.pin_settings_ack() {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                }
                WINDOW_UPDATE""")
    code = replace(code, "                        if let Some(index) = self.pending_index(stream) {", """                        if !self.pin_credit(out, stream, increment)
                            && let Some(index) = self.pending_index(stream) {""")
    code = replace(code, "                    if let Some(index) = self.pending_index(stream) {", """                    self.pin_cancel(stream);
                    if let Some(index) = self.pending_index(stream) {""")
    code = replace(code, "                PING => {", """                PING => {
                    if self.gate.is_some() && (stream != 0 || len != 8) {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                    if flags & FLAG_ACK_OR_END_STREAM != 0 {
                        self.pin_ping(payload, out);
                    }""")
    code = replace(code, "            at += end;", """            self.pin_advance(out);
            if self.closing {
                return Some(buf.len());
            }
            at += end;""")
    code = replace(code, "        self.pending.clear();", "        self.gate = None;\n        self.pending.clear();")
    code += "\n" + (here / "h2-pin-gate.rs").read_text()
    if trace:
        code = replace(code, "            pin_limit(out, 0);", """            eprintln!("C455 pause nonce={} oldest={} newest={} pins={}",
                u64::from_be_bytes(gate.nonce),
                gate.held.iter().flatten().map(|p| p.stream).min().unwrap_or(0),
                self.last_stream, gate.held.iter().flatten().count());
            pin_limit(out, 0);""")
        code = replace(code, "            pin_limit(out, MAX_WINDOW);", """            eprintln!("C455 drained nonce={} newest={} pending={}",
                u64::from_be_bytes(gate.nonce), self.last_stream, self.pending.len());
            pin_limit(out, MAX_WINDOW);""")
        code += """
impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            eprintln!("C455 close accepted={} newest={} pins={} pending={} phase={:?}",
                self.last_stream.div_ceil(2), self.last_stream,
                gate.held.iter().flatten().count(), self.pending.len(), gate.phase);
        }
    }
}
"""
    code += '\n#[cfg(test)]\nmod pin_tests;\n'
    path.write_text(code)
    shutil.copy2(here / "h2-pin-tests.rs", source / "src/h2/pin_tests.rs")
    layout = source / "src/h2/receive_credit_tests.rs"
    layout.write_text(replace(layout.read_text(),
                              "assert_eq!(std::mem::size_of::<Conn>(), 72);",
                              "assert_eq!(std::mem::size_of::<Conn>(), 144);"))
    # Only generated source receives timer integration. The fixture requires
    # the multishot worker so an unavailable capability fails visibly.
    multirecv = source / "src/tcp/multirecv.rs"
    code = multirecv.read_text()
    code = replace(code, "struct Worker {", "struct Worker {\n    pin_ticker: Option<PinTicker>,")
    code = replace(code, "impl Worker {\n    fn new(io: ReceiveRing) -> Self {\n        Self {", """impl Worker {
    fn new(io: ReceiveRing) -> Self {
        let mut worker = Self {
            pin_ticker: None,""")
    code = replace(code, """            receives: Vec::new(),
        }
    }""", """            receives: Vec::new(),
        };
        if !cfg!(test) {
            worker.start_pin_ticker();
        }
        worker
    }""")
    code = replace(code, """            } else {
                self.event(event);""", """            } else if event.token == PIN_TIMER {
                assert!(event.result >= 0, "pin timer poll: {}", event.result);
                self.pin_timer_event();
            } else {
                self.event(event);""")
    code = replace(code, "Err(ring) => return *ring,", "Err(_) => panic!(\"pin fixture requires provided buffers\"),")
    code = replace(code, "return io.fallback();", "drop(io.fallback());\n        panic!(\"pin fixture requires multishot receive\");")
    code += "\n" + (here / "h2-pin-timer.rs").read_text()
    multirecv.write_text(code)
    slots = source / "src/tcp/multirecv/slots.rs"
    slots.write_text(replace(slots.read_text(), "    pub(super) fn remove(", """    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut T)> {
        self.entries.iter_mut().filter_map(|s| s.value.as_mut().map(|v| (s.key, v)))
    }

    pub(super) fn remove("""))
    subprocess.run(["cargo", "fmt"], cwd=source, check=True)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--trace", action="store_true", help="Diagnostic peer only; never use for timing")
    args = parser.parse_args()
    output = args.output.resolve()
    source = generate(args.repo.resolve(), output, args.trace)
    if args.generate_only:
        return
    original = output / "original-source/main.rs"
    subprocess.run(["rustc", "--test", "--edition=2024", str(original), "-o", str(output / "original-layout")], check=True)
    subprocess.run([str(output / "original-layout")], check=True)
    env = os.environ | {"CARGO_TARGET_DIR": str(Path(os.environ.get("C455_TARGET", output / "target")).resolve()), "CARGO_INCREMENTAL": "0"}
    commands = [["cargo", "fmt", "--check"],
                ["cargo", "test", "--locked"],
                ["cargo", "test", "--release", "--locked"],
                ["cargo", "clippy", "--locked", "--bin", "hfast", "--", "-D", "warnings"],
                ["cargo", "build", "--release", "--locked"]]
    for i, command in enumerate(commands):
        print(" ".join(command), flush=True)
        with (output / f"check-{i}.log").open("x") as log:
            subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = output / "h2-pin-peer"
    shutil.copy2(Path(env["CARGO_TARGET_DIR"]) / "release/hfast", binary)
    binary.chmod(0o555)
    (output / "manifest.json").write_text(json.dumps(dict(
        revision=REVISION, trace=args.trace, commands=commands, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        compiler=subprocess.check_output(["rustc", "-Vv"], text=True),
        sources={str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(source.rglob("*.rs"))},
        inputs={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                [Path(__file__), here_file("h2-pin-gate.rs"), here_file("h2-pin-tests.rs"), here_file("h2-pin-timer.rs")]},
    ), indent=2) + "\n")
    print(binary)


def here_file(name):
    return Path(__file__).resolve().parent / name


if __name__ == "__main__":
    main()
