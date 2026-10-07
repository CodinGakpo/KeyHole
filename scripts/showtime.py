"""Interview-paced live demo of Keyhole: real `sbx` commands, one big visual per step.

Every command shown is actually executed (nothing is mocked); the script only adds pacing,
captions and a visual for each result. State lives in a throwaway KEYHOLE_HOME that is wiped on
start, so the drip budget and the dashboard history begin clean every time.

    make showtime                 # pauses for Enter between steps (you control the pace)
    make showtime ARGS=--auto     # no pauses (rehearsal / recording)
    make showtime-dashboard       # the dashboard for the same state, in a second terminal
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHOW_HOME = Path.home() / ".keyhole-showtime"
DATA = "customers.csv=examples/customers.csv"
AUTO = "--auto" in sys.argv

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[36m"


def runs_to_steal() -> int:
    """Runs needed to drain the whole file through a 3-way enum exit."""
    return math.ceil((ROOT / "examples/customers.csv").stat().st_size * 8 / math.log2(3))


def width() -> int:
    return min(shutil.get_terminal_size((100, 30)).columns - 4, 96)


def say(text: str = "", style: str = "") -> None:
    print(f"  {style}{text}{RESET}")


def pause(label: str = "next") -> None:
    if AUTO:
        time.sleep(0.6)
        return
    input(f"\n  {DIM}⏎ {label}{RESET}")


def header(n: int, title: str, caption: str) -> None:
    print("\n" * 2 + f"  {CYAN}{BOLD}{n}  {title.upper()}{RESET}")
    say("─" * width(), DIM)
    for line in caption.splitlines():
        say(line)
    print()


def stamp(ok: bool, text: str) -> None:
    color, icon = (GREEN, "✔") if ok else (RED, "✖")
    inner = f"  {icon}  {text}  "
    print()
    say(f"╔{'═' * len(inner)}╗", color + BOLD)
    say(f"║{inner}║", color + BOLD)
    say(f"╚{'═' * len(inner)}╝", color + BOLD)


def sbx(*args: str) -> tuple[int, str]:
    """Type the command, run the real CLI, show its real output (dimmed)."""
    shown = "sbx " + " ".join(args)
    print(f"  {BOLD}$ {RESET}", end="", flush=True)
    for ch in shown:
        print(ch, end="", flush=True)
        time.sleep(0 if AUTO else 0.012)
    print()
    proc = subprocess.run(
        [sys.executable, "-m", "keyhole.cli.main", *args],
        cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, "KEYHOLE_HOME": str(SHOW_HOME)},
    )
    out = proc.stdout + proc.stderr
    for line in out.rstrip().splitlines():
        say(f"  {line}", DIM)
    return proc.returncode, out


def field(out: str, name: str) -> str:
    m = re.search(rf"^{name}:\s*(\S+)", out, re.M)
    assert m, f"no '{name}' in sbx output:\n{out}"
    return m.group(1)


def show_code(path: str) -> None:
    src = (ROOT / path).read_text()
    body = src.split('"""', 2)[2].strip() if src.startswith('"""') else src
    say(f"┌─ {path}", DIM)
    for line in body.splitlines():
        say(f"│ {line}", YELLOW)
    say("└─", DIM)


# ── steps ────────────────────────────────────────────────────────────────────────────────


def step_problem() -> None:
    header(1, "The data vs. the exit",
           "Your private file goes INTO the sandbox in full. The code can read every byte.\n"
           "What can come OUT is fixed in advance by a schema, here one of three words.")
    csv = (ROOT / "examples/customers.csv").read_text()
    for line in csv.splitlines()[:4]:
        say(f"  {line}", YELLOW)
    say(f"  … {len(csv.splitlines()) - 4} more rows  (names, emails, SSNs, balances)", DIM)
    print()
    say('exit schema:  {"type": "enum", "choices": ["spam", "ham", "other"]}', BOLD)
    pause("compare the sizes")

    data_bits = len(csv.encode()) * 8
    exit_bits = math.log2(3)
    w = width() - 22
    print()
    say(f"{'data in':>10}  {RED}{'█' * w}{RESET}  {data_bits:,} bits")
    say(f"{'exit':>10}  {GREEN}▏{RESET}{' ' * (w - 1)}  {exit_bits:.2f} bits")
    pause("so how many runs to steal it?")

    runs = runs_to_steal()
    print()
    say(f"Each ▪ is one run's worth of exit. Stealing the file needs {BOLD}{runs:,}{RESET}"
        " perfect runs:")
    print()
    cols = width() - 2
    cells = [f"{RESET}{GREEN}▪{RESET}{DIM}"] + ["▪"] * (runs - 1)
    for row in range(0, runs, cols):
        say(DIM + "".join(cells[row:row + cols]))
        time.sleep(0 if AUTO else 0.03)
    say(f"{GREEN}▪{RESET} {DIM}← one run. Keep this number in mind for step 4.{RESET}")
    pause()


def step_honest() -> None:
    header(2, "Honest code",
           "A classifier reads all the customers and answers one word.")
    show_code("examples/classify.py")
    pause("run it")
    rc, out = sbx("run", "examples/classify.py", "--data", DATA,
                  "--schema", "schemas/label.json", "--local")
    stamp(rc == 0, f"RELEASED   output = {field(out, 'output')}")
    say("The exit gate checked: fits the schema? no secrets? no PII? then signed and released it.",
        DIM)
    pause()


def step_malicious() -> None:
    header(3, "Malicious code",
           "Same data, same schema. This program tries to return the entire file.")
    show_code("examples/exfil.py")
    pause("run it")
    rc, out = sbx("run", "examples/exfil.py", "--data", DATA,
                  "--schema", "schemas/label.json", "--local")
    stamp(rc == 0, "RELEASED" if rc == 0 else "WITHHELD   nothing left the box")
    size = (ROOT / "examples/customers.csv").stat().st_size
    say(f"Not caught by scanning for leaks: a {size}-byte file can't fit through a 1.58-bit exit.",
        DIM)
    say(f"The failed attempt is still signed and logged (exit code {rc}).", DIM)
    pause()


def step_drip() -> None:
    cap = 8.0
    header(4, "The drip attack",
           "Smarter attacker: stay inside the schema and leak ~1.58 bits per run, many runs.\n"
           f"Defense: a cumulative budget per caller. Mallory gets {cap:g} bits, total.")
    pause("start dripping")
    w = width() - 30
    used, released = 0.0, 0
    for i in range(1, 7):
        rc, out = sbx("run", "examples/classify.py", "--data", DATA, "--schema",
                      "schemas/label.json", "--local", "--principal", "mallory",
                      "--budget-bits", f"{cap:g}")
        if rc == 0:
            used = float(re.search(r"budget:\s*([\d.]+)/", out).group(1))
            released += 1
            fill = round(w * used / cap)
            say(f"run {i}  [{GREEN}{'█' * fill}{RESET}{DIM}{'░' * (w - fill)}{RESET}]"
                f"  {used:.2f}/{cap:g} bits", BOLD)
        else:
            say(f"run {i}  [{RED}{'█' * w}{RESET}]  would exceed {cap:g} bits", BOLD)
            stamp(False, "WITHHELD   budget exhausted")
        print()
        time.sleep(0 if AUTO else 0.4)
    say(f"Mallory got {released} answers, {used:.2f} bits in total. Stealing the file takes "
        f"{runs_to_steal():,} runs.", DIM)
    pause()


def step_cleanroom() -> None:
    header(5, "The clean room",
           "Two companies. acme owns the data. partner-ai owns the code.\n"
           "The partner runs its code on acme's data and never receives the file.")
    _, out = sbx("dataset", "add", DATA, "--owner", "acme")
    ds = field(out, "dataset")
    pause("acme grants partner-ai")
    _, out = sbx("dataset", "grant", ds, "--to", "partner-ai")
    grant = field(out, "grant token")
    pause("partner-ai runs by dataset id; no file path anywhere")
    rc, out = sbx("run", "examples/classify.py", "--dataset", ds, "--grant", grant,
                  "--principal", "partner-ai", "--schema", "schemas/label.json",
                  "--save-attestation", str(SHOW_HOME / "att.json"))
    stamp(rc == 0, f"RELEASED to partner-ai   output = {field(out, 'output')}")
    pause("now an intruder with a stolen grant token")
    rc, _ = sbx("run", "examples/classify.py", "--dataset", ds, "--grant", grant,
                "--principal", "intruder", "--schema", "schemas/label.json")
    stamp(False, "REFUSED   before any code ran" if rc == 4 else f"UNEXPECTED exit {rc}")
    say("The grant is bound to an identity. The token alone is worthless.", DIM)
    pause()


def step_proof() -> None:
    header(6, "The proof",
           "Every run produces a signed attestation: hashes of the code, data and schema, the\n"
           "output, and who was involved. Anyone can check it offline with the public key.")
    att_path = SHOW_HOME / "att.json"
    att = json.loads(att_path.read_text())
    for k in ("code_sha256", "data_sha256", "schema_sha256", "output", "data_owner",
              "code_provider", "dataset_id", "signature"):
        v = str(att[k])
        say(f"  {k:<14} {v[:56]}{'…' if len(v) > 56 else ''}", YELLOW)
    print()
    rc, _ = sbx("verify", str(att_path))
    stamp(rc == 0, "VALID")
    pause("tamper with one field")

    tampered = SHOW_HOME / "att-tampered.json"
    original = att["data_owner"]
    att["data_owner"] = "evil"
    tampered.write_text(json.dumps(att, indent=2))
    print()
    say(f'  {RED}-  "data_owner": "{original}"{RESET}')
    say(f'  {GREEN}+  "data_owner": "evil"{RESET}')
    print()
    rc, _ = sbx("verify", str(tampered))
    stamp(rc == 0, "VALID" if rc == 0 else "INVALID   signature no longer matches")
    pause()


def finale() -> None:
    print("\n")
    say("WHAT YOU JUST SAW", CYAN + BOLD)
    say("─" * width(), DIM)
    for ok, line in [
        (True, "Honest code got its answer out"),
        (False, "Malicious code got nothing out: no room in the exit"),
        (False, "Drip attack capped by a per-caller bit budget"),
        (True, "Clean room: partner computed on data it never received"),
        (False, "Intruder refused before anything ran"),
        (True, "Every run signed; one changed field breaks the proof"),
    ]:
        say(f"{GREEN + '✔' if ok else RED + '✖'}{RESET}  {line}")
    print()
    say(f"Dashboard for these runs:  {BOLD}make showtime-dashboard{RESET}  → http://127.0.0.1:8787")
    print()


def main() -> int:
    shutil.rmtree(SHOW_HOME, ignore_errors=True)
    print("\033[2J\033[H" if not AUTO else "")
    say("KEYHOLE", CYAN + BOLD)
    say("Run untrusted code on private data. Only a bounded, signed answer gets out.", BOLD)
    pause("begin")
    for step in (step_problem, step_honest, step_malicious, step_drip, step_cleanroom,
                 step_proof):
        step()
    finale()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(RESET)
        raise SystemExit(130) from None
