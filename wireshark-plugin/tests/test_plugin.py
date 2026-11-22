import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile

from make_fixture import build

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["frame.number", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "ip.dst",
          "ipv6.dst", "tcp.dstport", "frame.len", "frame.time_relative", "tcp.flags.syn",
          "tcp.flags.fin", "tcp.flags.reset", "tcp.analysis.retransmission",
          "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
          "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order", "tcp.analysis.zero_window",
          "http.request", "dns.flags.response"]


def normalize(text):
    return text.replace("\r\r\n", "\n").replace("\r\n", "\n")


def is_true(value):
    return value.lower() in ("true", "1")


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def native_summary(text):
    rows = {}
    for packet in csv.DictReader(io.StringIO(text)):
        if not packet["tcp.stream"]:
            continue
        stream = int(packet["tcp.stream"])
        a = endpoint(packet["ip.src"] or packet["ipv6.src"], packet["tcp.srcport"])
        b = endpoint(packet["ip.dst"] or packet["ipv6.dst"], packet["tcp.dstport"])
        a, b = sorted((a, b))
        row = rows.setdefault(stream, dict(stream=stream, endpoint_a=a, endpoint_b=b,
            packets=0, bytes=0, syn=0, fin=0, rst=0, retransmissions=0, duplicate_ack=0,
            out_of_order=0, zero_window=0, http_requests=0, dns_queries=0,
            start_s=float(packet["frame.time_relative"]), end_s=float(packet["frame.time_relative"])))
        row["packets"] += 1
        row["bytes"] += int(packet["frame.len"])
        for key, field in (("syn", "tcp.flags.syn"), ("fin", "tcp.flags.fin"), ("rst", "tcp.flags.reset")):
            row[key] += any(is_true(v) for v in packet[field].split("|"))
        row["retransmissions"] += any(packet[f"tcp.analysis.{key}"] for key in (
            "retransmission", "fast_retransmission", "spurious_retransmission"))
        for key in ("duplicate_ack", "out_of_order", "zero_window"):
            row[key] += bool(packet[f"tcp.analysis.{key}"])
        row["http_requests"] += sum(is_true(v) for v in packet["http.request"].split("|"))
        row["dns_queries"] += sum(v.lower() in ("false", "0") for v in packet["dns.flags.response"].split("|"))
        time = float(packet["frame.time_relative"])
        row["start_s"] = min(row["start_s"], time)
        row["end_s"] = max(row["end_s"], time)
    for row in rows.values():
        row["score"] = 4 * row["retransmissions"] + 2 * row["duplicate_ack"] + 3 * row["rst"] + 4 * row["zero_window"] + row["out_of_order"]
        row["risk"] = "HIGH" if row["score"] >= 12 else "WATCH" if row["score"] >= 4 else "LOW"
        row["score_partial"] = "false"
    return sorted(rows.values(), key=lambda row: (-row["score"], row["stream"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tshark", required=True, type=Path)
    parser.add_argument("--tag", default="4.6.9")
    options = parser.parse_args()
    directory = ROOT / "evidence" / options.tag
    directory.mkdir(parents=True, exist_ok=True)
    scratch = ROOT / "tests" / ".scratch" / options.tag
    scratch.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["WIRESHARK_CONFIG_DIR"] = str(scratch / "profile")
    (scratch / "profile").mkdir(exist_ok=True)
    plugin_directory = scratch / "profile" / "plugins"
    plugin_directory.mkdir(exist_ok=True)
    (plugin_directory / "flowlens_companion.lua").write_bytes((ROOT / "flowlens_companion.lua").read_bytes())
    # ASCII temp CSV also permits old Windows Lua runtimes without UTF-8 fopen.
    with tempfile.TemporaryDirectory(prefix="flowlens-") as temp:
        temp = Path(temp)
        test_source = temp / "flowlens_companion.lua"
        test_source.write_bytes((ROOT / "flowlens_companion.lua").read_bytes())
        environment["FLOWLENS_TEST_SOURCE"] = str(test_source)
        def run(name, args, allow_error=False):
            command = [str(options.tshark)] + args
            result = subprocess.run(command, env=environment, capture_output=True, timeout=60)
            out = normalize(result.stdout.decode("utf-8", "replace"))
            err = normalize(result.stderr.decode("utf-8", "replace"))
            (directory / (name + ".txt")).write_text(
                "Command: " + subprocess.list2cmdline(command) + "\nExit: " + str(result.returncode)
                + "\nSTDOUT:\n" + out + "\nSTDERR:\n" + err, encoding="utf-8")
            if not allow_error:
                assert result.returncode == 0 and not err, (name, result.returncode, err)
            return out, err

        run("version", ["-v"])
        sample = ROOT.parent / "samples" / "showcase.pcap"
        original_sha = hashlib.sha256(sample.read_bytes()).hexdigest()
        fixture = ROOT / "samples" / "anomalies_dns.pcap"
        build(fixture)
        results = []
        autoload, _ = run("personal-plugin-autoload", ["-n", "-r", str(sample), "-q", "-z", "flowlens"])
        assert autoload.count("FlowLens Companion for Wireshark 1.0.0") == 1
        assert "TCP streams: 4 | packets: 16 | wire bytes: 1299" in autoload
        results.append(dict(case="personal-plugin-autoload", result="PASS"))
        no_stat, _ = run("autoload-without-stat-option", ["-n", "-r", str(sample), "-q"])
        assert no_stat == ""
        results.append(dict(case="autoload-without-stat-option", result="PASS"))
        cases = [
            ("showcase-default", sample, [], []),
            ("showcase-http-reassembly", sample,
             ["-d", "tcp.port==18080,http", "-o", "tcp.reassemble_out_of_order:TRUE"], []),
            ("showcase-two-pass", sample, ["-2"], []),
            ("showcase-display-filter", sample, [], ["-Y", "tcp.stream == 1"]),
            ("anomalies-dns", fixture, [], []),
        ]
        for name, capture, preferences, display in cases:
            common = ["-n", "-r", str(capture)] + preferences
            native_args = common + ["-T", "fields", "-E", "header=y", "-E", "separator=,",
                                    "-E", "quote=d", "-E", "aggregator=|"]
            for field in FIELDS:
                native_args += ["-e", field]
            native, _ = run(name + "-native", native_args)
            expected = native_summary(native)
            (directory / (name + "-expected.json")).write_text(
                json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
            destination = temp / (name + ".csv")
            plugin_args = common + display + ["-q", "-X", "lua_script:" + str(ROOT / "flowlens_companion.lua"),
                                              "-z", "flowlens,csv=" + str(destination)]
            out, _ = run(name + "-plugin", plugin_args)
            actual_text = destination.read_text(encoding="utf-8")
            (directory / (name + ".csv")).write_text(actual_text, encoding="utf-8", newline="")
            actual = list(csv.DictReader(io.StringIO(actual_text)))
            assert len(actual) == len(expected), (name, actual, expected)
            for got, want in zip(actual, expected):
                for key, value in want.items():
                    if key in ("start_s", "end_s"):
                        assert abs(float(got[key]) - value) < 1e-9, (name, key, got[key], value)
                    else:
                        assert got[key] == str(value), (name, key, got[key], value)
            if name == "showcase-default":
                assert sum(int(row["packets"]) for row in actual) == 16
                assert sum(int(row["bytes"]) for row in actual) == 1299
                assert actual[0]["stream"] == "0" and int(actual[0]["retransmissions"]) > 0
                assert all(row["dns_queries"] == "0" for row in actual)
            if name == "anomalies-dns":
                assert actual[0]["risk"] == "HIGH"
                assert int(actual[0]["zero_window"]) > 0 and int(actual[0]["rst"]) > 0
                assert int(actual[0]["duplicate_ack"]) > 0 and int(actual[0]["out_of_order"]) > 0
                assert sum(int(row["dns_queries"]) for row in actual) == 1
            # Export must refuse existing paths without altering the original CSV.
            before = destination.read_bytes()
            _, err = run(name + "-overwrite-refused", plugin_args, allow_error=True)
            assert "Destination already exists" in err and before == destination.read_bytes()
            results.append(dict(case=name, streams=len(actual), result="PASS"))
            print("PASS", name, flush=True)

        disabled_csv = temp / "disabled.csv"
        _, _ = run("sequence-analysis-disabled", ["-n", "-r", str(sample), "-q",
            "-o", "tcp.analyze_sequence_numbers:FALSE", "-X", "lua_script:" + str(ROOT / "flowlens_companion.lua"),
            "-z", "flowlens,csv=" + str(disabled_csv)])
        disabled = list(csv.DictReader(io.StringIO(disabled_csv.read_text(encoding="utf-8"))))
        assert all(row["retransmissions"] == "N/A" and row["risk"] == "UNKNOWN" for row in disabled)
        results.append(dict(case="sequence-analysis-disabled", result="PASS"))
        empty_capture = temp / "empty.pcap"
        empty_capture.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        empty_csv = temp / "empty.csv"
        empty, _ = run("empty-capture", ["-n", "-r", str(empty_capture), "-q", "-z", "flowlens,csv=" + str(empty_csv)])
        assert "TCP streams: 0 | packets: 0 | wire bytes: 0" in empty
        assert list(csv.DictReader(io.StringIO(empty_csv.read_text(encoding="utf-8")))) == []
        results.append(dict(case="empty-capture", result="PASS"))
        failed_csv = temp / "missing-directory" / "result.csv"
        _, failed = run("csv-write-error", ["-n", "-r", str(sample), "-q", "-z", "flowlens,csv=" + str(failed_csv)], allow_error=True)
        assert "FlowLens CSV export failed" in failed and not failed_csv.exists()
        results.append(dict(case="csv-write-error", result="PASS"))
        run("mock-unit-tests", ["-n", "-r", str(sample), "-q", "-X", "lua_script:" + str(ROOT / "tests" / "unit.lua")])
        results.append(dict(case="mock-unit-tests", result="PASS"))
        assert original_sha == hashlib.sha256(sample.read_bytes()).hexdigest()
        metadata = dict(tshark=str(options.tshark), sample_sha256=original_sha,
                        source_sha256=hashlib.sha256((ROOT / "flowlens_companion.lua").read_bytes()).hexdigest(),
                        results=results, status="PASS")
        (directory / "validation.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        print("PASS all checks; original showcase.pcap unchanged", flush=True)


if __name__ == "__main__":
    main()
