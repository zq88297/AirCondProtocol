"""实现报文加载、说明解析、脉冲解码、字段推导以及 Markdown/TSV 报告生成。"""
from __future__ import annotations
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from statistics import median
from typing import Callable, Iterable
class AnalysisError(Exception):
    """Raised when input data is missing or malformed."""
class SkipLearnPayload(AnalysisError):
    """Raised when one Learn payload is effectively empty and should be skipped."""
REPORT_DIR_NAME = "报文"
OUTPUT_DIR_NAME = "协议分析"
LEGACY_DESCRIPTION_NAME = "报文说明.txt"
MANIFEST_NAME = "样本清单.json"
REPORT_NAME = "自动协议分析.md"
TSV_NAME = "报文分解.tsv"
STATUS_CONFIRMED = "已确认"
STATUS_INFERRED = "推测"
STATUS_UNKNOWN = "未知"
ENCODINGS = ("utf-8-sig", "utf-8", "gb18030", "gbk", "utf-16")
RANGE_SEPARATORS = ("-", "~", "—", "－", "至")
AUTO_SPLIT_GROUP_ORDER = ("cool", "heat", "power_cycle")
AUTO_SPLIT_FILENAMES = {
    "cool": "自动拆分-制冷样本.txt",
    "heat": "自动拆分-制热样本.txt",
    "power_cycle": "自动拆分-冷暖开关机样本.txt",
}
AUTO_SPLIT_DESCRIPTIONS = {
    "cool": "自动拆分出的制冷相关报文",
    "heat": "自动拆分出的制热相关报文",
    "power_cycle": "自动拆分出的冷暖开关机相关报文",
}
@dataclass
class PulsePair:
    value: int
    pulse_type: int
    @property
    def hex(self) -> str:
        return f"{self.value:02X}{self.pulse_type:02X}"
@dataclass
class BitPulse:
    bit: int
    raw_hex: str
@dataclass
class MarkerSegment:
    name: str
    raw_hex: str
@dataclass
class DataField:
    key: str
    segment_name: str
    bit_range_label: str
    bits: str
    hex_value: str
    bit_count: int
    start_bit: int
    raw_hex: str
    note: str
@dataclass
class ChunkAnalysis:
    index: int
    header_hex: str
    pairs: list[PulsePair]
    separator_hex: str | None
    mark_type: int | None = None
    zero_type: int | None = None
    one_type: int | None = None
    total_bits: int = 0
    payload_bit_count: int = 0
    payload_bytes: list[int] = field(default_factory=list)
    payload_fields: list[DataField] = field(default_factory=list)
    tail_fields: list[DataField] = field(default_factory=list)
    markers: list[MarkerSegment] = field(default_factory=list)
    @property
    def payload_hex(self) -> str:
        return " ".join(f"{value:02X}" for value in self.payload_bytes)
@dataclass
class CommandSample:
    sample_kind: str
    sample_name: str
    learn_key: str
    description: str
    source_file: Path
    raw_hex: str
    trimmed_hex: str
    chunks: list[ChunkAnalysis]
    tags: dict[str, object]
@dataclass
class LoadedSample:
    sample_kind: str
    sample_name: str
    description: str
    commands: list[CommandSample]
@dataclass
class SourcePacketRow:
    source_name: str
    channel_name: str
    learn_key: str
    description: str
    packet_hex: str | None
    status: str
@dataclass
class SourcePacketCandidate:
    source_name: str
    learn_key: str
    description: str
    packet: list[int]
@dataclass
class FieldInference:
    field_key: str
    segment_name: str
    observed_values: str
    status: str
    meaning: str
    evidence: str
@dataclass
class DecodeStrategyCandidate:
    strategy_name: str
    offset: int
    pair_count: int
    threshold: int
    gap: int
    base_score: float
    left_mad: float
    left_span: int
    mark_type: int
    zero_type: int
    one_type: int


def emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def analyze_brand_directory(
    brand_dir: Path,
    output_dir: Path | None = None,
    manifest_path: Path | None = None,
    legacy_description: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> None:
    brand_dir = brand_dir.resolve()
    if not brand_dir.is_dir():
        raise AnalysisError(f"Brand directory does not exist: {brand_dir}")
    report_dir = brand_dir / REPORT_DIR_NAME
    if not report_dir.is_dir():
        raise AnalysisError(f"Missing report directory: {report_dir}")
    output_dir = (output_dir or (brand_dir / OUTPUT_DIR_NAME)).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_path or detect_manifest(report_dir)
    emit_progress(progress, f"Preparing analysis for brand '{brand_dir.name}'")
    emit_progress(progress, f"Scanning input directory {report_dir}")
    source_packet_rows: list[SourcePacketRow] = []
    if manifest_path is not None:
        emit_progress(progress, f"Detected manifest mode: {manifest_path}")
        samples, mode_label, notes = load_manifest_samples(
            brand_dir,
            manifest_path,
            progress=progress,
        )
    else:
        emit_progress(progress, "Detected legacy auto-split mode")
        samples, mode_label, notes = load_legacy_samples(
            report_dir=report_dir,
            legacy_description=legacy_description,
            progress=progress,
        )
        emit_progress(progress, "Building per-source channel summary from legacy inputs")
        source_packet_rows = build_legacy_source_packet_rows(
            report_dir=report_dir,
            legacy_description=legacy_description,
        )
    commands = [command for sample in samples for command in sample.commands]
    if not commands:
        raise AnalysisError("No Learn payloads were loaded.")
    emit_progress(
        progress,
        "Loaded "
        f"{len(samples)} sample groups and {len(commands)} Learn payloads"
        + (f"; recovered {len(source_packet_rows)} source channels" if source_packet_rows else ""),
    )
    emit_progress(progress, f"Inferring fields from {len(commands)} parsed payloads")
    field_inferences = infer_fields(commands)
    emit_progress(progress, f"Derived {len(field_inferences)} field observations")
    field_notes = {item.field_key: f"{item.status} {item.meaning}" for item in field_inferences}
    emit_progress(progress, "Rendering markdown report")
    markdown = render_markdown_report(
        brand_name=brand_dir.name,
        mode_label=mode_label,
        samples=samples,
        commands=commands,
        notes=notes,
        field_inferences=field_inferences,
        source_packet_rows=source_packet_rows,
    )
    emit_progress(progress, "Rendering TSV breakdown")
    tsv_text = render_tsv(commands, field_notes)
    emit_progress(progress, f"Writing report files into {output_dir}")
    (output_dir / REPORT_NAME).write_text(markdown, encoding="utf-8")
    (output_dir / TSV_NAME).write_text(tsv_text, encoding="utf-8")
    emit_progress(progress, f"Wrote {REPORT_NAME} and {TSV_NAME} to {output_dir}")
def detect_manifest(report_dir: Path) -> Path | None:
    candidate = report_dir / MANIFEST_NAME
    return candidate if candidate.is_file() else None
def read_text_auto(path: Path) -> str:
    data = path.read_bytes()
    last_error: UnicodeDecodeError | None = None
    for encoding in ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise AnalysisError(f"Unable to decode file: {path}") from last_error
    return data.decode("utf-8", errors="replace")
def normalize_hex(raw_hex: str) -> str:
    value = re.sub(r"[^0-9A-Fa-f]", "", raw_hex).upper()
    if not value:
        raise AnalysisError("Encountered an empty payload.")
    if len(value) % 2 != 0:
        raise AnalysisError(f"Payload hex length must be even: {value[:40]}...")
    return value
def trim_raw_hex(raw_hex: str) -> str:
    data = bytes.fromhex(normalize_hex(raw_hex))
    terminator_index = data.find(b"\x01\x00")
    if terminator_index >= 0:
        data = data[:terminator_index]
    data = data.rstrip(b"\xFF")
    if not data:
        raise SkipLearnPayload("Payload is empty after trimming terminator and padding.")
    return data.hex().upper()
def parse_learn_payloads(path: Path) -> dict[str, str]:
    content = read_text_auto(path)
    matches = re.findall(r"(Learn(\d+)Code)\s*=\s*([0-9A-Fa-f]+)", content)
    if not matches:
        raise AnalysisError(f"No Learn payloads found in {path}")
    payloads: dict[str, str] = {}
    for full_key, numeric_key, raw_hex in matches:
        normalized = normalize_hex(raw_hex)
        payloads[full_key] = normalized
        payloads[f"Learn{numeric_key}"] = normalized
        payloads[numeric_key] = normalized
    return payloads
def parse_legacy_description(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    compact = re.sub(r"\s+", "", text)
    compact = compact.replace("，", ",").replace("。", ",").replace("；", ",").replace(";", ",")
    clause_pattern = re.compile(
        r"(?P<refs>(?:Learn\d+(?:Code)?)(?:[、-](?:Learn)?\d+(?:Code)?)*)"
        r"(?:是|=)"
        r"(?P<desc>.*?)"
        r"(?=(?:[、,])?Learn\d+(?:Code)?(?:[、-](?:Learn)?\d+(?:Code)?)*(?:是|=)|$)"
    )
    for match in clause_pattern.finditer(compact):
        description = match.group("desc").strip("、,")
        if not description:
            continue
        for learn_key in expand_learn_refs(match.group("refs")):
            mapping[learn_key] = description
    return mapping
def expand_learn_refs(ref_text: str) -> list[str]:
    normalized = ref_text
    for separator in RANGE_SEPARATORS[1:]:
        normalized = normalized.replace(separator, "-")
    refs: list[str] = []
    for part in [item for item in normalized.split("、") if item]:
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start_num = extract_learn_number(start_text)
            end_num = extract_learn_number(end_text)
            if start_num is None or end_num is None:
                continue
            lower = min(start_num, end_num)
            upper = max(start_num, end_num)
            refs.extend(f"Learn{number}Code" for number in range(lower, upper + 1))
            continue
        number = extract_learn_number(part)
        if number is not None:
            refs.append(f"Learn{number}Code")
    return refs
def extract_learn_number(text: str) -> int | None:
    match = re.search(r"Learn(\d+)|(\d+)", text, re.IGNORECASE)
    if not match:
        return None
    digits = match.group(1) or match.group(2)
    return int(digits)
def detect_legacy_source_name(text: str) -> str | None:
    match = re.search(
        r"(?P<name>[0-9A-Za-z_.\-\u4e00-\u9fff]+(?:\.txt)?)\s*(?:\u6587\u4ef6)?\u4e2d",
        text,
    )
    if match is None:
        return None
    source_name = match.group("name")
    if not source_name.lower().endswith(".txt"):
        source_name = f"{source_name}.txt"
    return source_name
def resolve_legacy_description(
    description_map: dict[str, str],
    report_file: Path,
    learn_key: str,
) -> str | None:
    return description_map.get(f"{report_file.name}|{learn_key}") or description_map.get(learn_key)
# Historical implementation kept only as cleanup reference; not used by the tool.
def _deprecated_parse_legacy_description_v1(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    compact = re.sub(r"\s+", "", text)
    compact = (
        compact.replace("\u3001", ",")
        .replace("\uff0c", ",")
        .replace("\uff1b", ",")
        .replace(";", ",")
    )
    clause_pattern = re.compile(
        r"(?P<refs>(?:Learn\d+(?:Code)?)(?:[,](?:Learn)?\d+(?:Code)?)*)"
        r"(?:\u662f|\u4e3a|=|\u4ee3\u8868)"
        r"(?P<desc>.*?)"
        r"(?=(?:[,])?Learn\d+(?:Code)?(?:[,](?:Learn)?\d+(?:Code)?)*(?:\u662f|\u4e3a|=|\u4ee3\u8868)|$)"
    )
    for match in clause_pattern.finditer(compact):
        description = match.group("desc").strip(" ,;\uff0c\uff1b\u3002")
        if not description:
            continue
        for learn_key in expand_learn_refs(match.group("refs")):
            mapping[learn_key] = description
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        source_name = detect_legacy_source_name(line)
        if source_name is None:
            continue
        anchor = re.search(
            r"Learn(?P<learn>\d+)Code(?:\u4ee3\u8868|\u5bf9\u5e94)\u901a\u9053(?P<channel>\d+)",
            line,
            re.IGNORECASE,
        )
        base_learn = int(anchor.group("learn")) if anchor else 1
        channel_matches = list(
            re.finditer(
                r"\u901a\u9053\s*(?P<channel>\d+)\s*[:\uff1a]\s*(?P<desc>[^,;\uff0c\uff1b\u3002]+)",
                line,
            )
        )
        if not channel_matches:
            continue
        base_channel = int(anchor.group("channel")) if anchor else int(channel_matches[0].group("channel"))
        for channel_match in channel_matches:
            channel_number = int(channel_match.group("channel"))
            description = channel_match.group("desc").strip(" ,;\uff0c\uff1b\u3002")
            if not description:
                continue
            learn_number = base_learn + (channel_number - base_channel)
            mapping[f"{source_name}|Learn{learn_number}Code"] = description
    return mapping
def load_legacy_samples(
    report_dir: Path,
    legacy_description: Path | None,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[LoadedSample], str, list[str]]:
    description_path = legacy_description or (report_dir / LEGACY_DESCRIPTION_NAME)
    description_text = read_text_auto(description_path) if description_path.is_file() else ""
    description_map = parse_legacy_description(description_text) if description_text else {}
    report_files = sorted(
        path
        for path in report_dir.glob("*.txt")
        if path.name != LEGACY_DESCRIPTION_NAME and not is_auto_split_file(path)
    )
    if not report_files:
        raise AnalysisError(f"No legacy report files found in {report_dir}")
    emit_progress(
        progress,
        f"Found {len(report_files)} legacy report files"
        + (
            f"; using description file {description_path.name}"
            if description_path.is_file()
            else "; no description file provided"
        ),
    )
    raw_commands: list[CommandSample] = []
    skipped_learns: list[str] = []
    for report_file in report_files:
        payloads = parse_learn_payloads(report_file)
        keys = sorted(
            (key for key in payloads if key.endswith("Code")),
            key=lambda item: extract_learn_number(item) or 0,
        )
        file_loaded = 0
        file_skipped = 0
        emit_progress(progress, f"Parsing {report_file.name}: detected {len(keys)} Learn entries")
        for learn_key in keys:
            description = resolve_legacy_description(description_map, report_file, learn_key)
            if description is None:
                description = f"{report_file.stem} {learn_key}"
            command_sample = try_build_command_sample(
                sample_kind="legacy",
                sample_name=report_file.stem,
                learn_key=learn_key,
                description=description,
                source_file=report_file,
                raw_hex=payloads[learn_key],
                inherited_tags=extract_tags(description),
            )
            if command_sample is None:
                skipped_learns.append(f"{report_file.name}:{learn_key}")
                file_skipped += 1
                continue
            raw_commands.append(command_sample)
            file_loaded += 1
        emit_progress(
            progress,
            f"Parsed {report_file.name}: kept {file_loaded}, skipped {file_skipped}, cumulative payloads {len(raw_commands)}",
        )
    if not raw_commands:
        raise AnalysisError("No valid Learn payloads were loaded after skipping empty/all-FF entries.")
    grouped_samples = auto_split_legacy_samples(raw_commands)
    if grouped_samples:
        emit_progress(
            progress,
            "Auto-split result: "
            + ", ".join(
                f"{group}={len(grouped_samples[group])}"
                for group in AUTO_SPLIT_GROUP_ORDER
                if group in grouped_samples
            ),
        )
        loaded_samples = build_loaded_samples_from_grouped_commands(grouped_samples)
        notes = [
            "Input mode: legacy-auto-split",
            f"Report directory: {report_dir}",
            f"Description file: {description_path if description_path.is_file() else 'not provided'}",
            f"Raw report files: {', '.join(path.name for path in report_files)}",
            "Auto-split groups are used in memory only and are not written as extra files.",
        ]
        if skipped_learns:
            notes.append(
                "Skipped empty/all-FF Learn payloads: " + ", ".join(skipped_learns)
            )
        missing_groups = [group for group in AUTO_SPLIT_GROUP_ORDER if group not in grouped_samples]
        if missing_groups:
            notes.append(f"Missing auto-split groups: {', '.join(missing_groups)}")
        return loaded_samples, "legacy-auto-split", notes
    loaded_samples = [
        LoadedSample(
            sample_kind="legacy",
            sample_name=report_file.stem,
            description=description_text.strip() or "Legacy mode without structured sample manifest.",
            commands=[command for command in raw_commands if command.source_file == report_file],
        )
        for report_file in report_files
    ]
    notes = [
        "Input mode: legacy",
        f"Report directory: {report_dir}",
        f"Description file: {description_path if description_path.is_file() else 'not provided'}",
    ]
    if skipped_learns:
        notes.append("Skipped empty/all-FF Learn payloads: " + ", ".join(skipped_learns))
    return loaded_samples, "legacy", notes
def build_legacy_source_packet_rows(
    report_dir: Path,
    legacy_description: Path | None,
) -> list[SourcePacketRow]:
    description_path = legacy_description or (report_dir / LEGACY_DESCRIPTION_NAME)
    description_text = read_text_auto(description_path) if description_path.is_file() else ""
    description_map = parse_legacy_description(description_text) if description_text else {}
    described_sources = {
        key.split("|", 1)[0]
        for key in description_map
        if "|" in key
    }
    all_report_files = sorted(
        path
        for path in report_dir.glob("*.txt")
        if path.name != LEGACY_DESCRIPTION_NAME
        and not is_auto_split_file(path)
    )
    report_files = [
        path
        for path in all_report_files
        if not described_sources or path.name in described_sources
    ]
    candidate_entries: list[SourcePacketCandidate] = []
    for report_file in all_report_files:
        payloads = parse_learn_payloads(report_file)
        for learn_key, raw_hex in sorted(
            ((key, value) for key, value in payloads.items() if key.endswith("Code")),
            key=lambda item: extract_learn_number(item[0]) or 0,
        ):
            description = resolve_legacy_description(description_map, report_file, learn_key)
            if description is None:
                description = f"{report_file.stem} {learn_key}"
            command = try_build_command_sample(
                sample_kind="legacy",
                sample_name=report_file.stem,
                learn_key=learn_key,
                description=description,
                source_file=report_file,
                raw_hex=raw_hex,
                inherited_tags=extract_tags(description),
            )
            if command is None:
                continue
            packet = extract_preferred_standard_packet16(command)
            if packet is None:
                continue
            candidate_entries.append(
                SourcePacketCandidate(
                    source_name=report_file.name,
                    learn_key=learn_key,
                    description=description,
                    packet=packet,
                )
            )
    provisional_rows: list[dict[str, object]] = []
    for report_file in report_files:
        payloads = parse_learn_payloads(report_file)
        keyed_payloads = {
            key: value
            for key, value in payloads.items()
            if key.endswith("Code")
        }
        described_keys = {
            key.split("|", 1)[1]
            for key in description_map
            if key.startswith(f"{report_file.name}|")
        }
        ordered_keys = sorted(
            described_keys or set(keyed_payloads),
            key=lambda item: extract_learn_number(item) or 0,
        )
        for learn_key in ordered_keys:
            learn_number = extract_learn_number(learn_key) or 0
            description = resolve_legacy_description(description_map, report_file, learn_key)
            if description is None:
                description = f"{report_file.stem} {learn_key}"
            packet: list[int] | None = None
            raw_hex = keyed_payloads.get(learn_key)
            if raw_hex is not None:
                command = try_build_command_sample(
                    sample_kind="legacy",
                    sample_name=report_file.stem,
                    learn_key=learn_key,
                    description=description,
                    source_file=report_file,
                    raw_hex=raw_hex,
                    inherited_tags=extract_tags(description),
                )
                if command is not None:
                    packet = extract_preferred_standard_packet16(command)
            provisional_rows.append(
                {
                    "source_name": report_file.name,
                    "channel_name": f"Ch{learn_number}",
                    "learn_key": learn_key,
                    "description": description,
                    "packet": packet,
                }
            )
    grouped_rows: dict[str, list[dict[str, object]]] = {}
    for row in provisional_rows:
        grouped_rows.setdefault(str(row["source_name"]), []).append(row)
    rows: list[SourcePacketRow] = []
    for source_name, source_rows in grouped_rows.items():
        source_rows.sort(key=lambda item: extract_learn_number(str(item["learn_key"])) or 0)
        for row in source_rows:
            packet = row["packet"]
            if packet is None:
                packet = find_source_packet_fallback(
                    source_name=source_name,
                    learn_key=str(row["learn_key"]),
                    description=str(row["description"]),
                    source_rows=source_rows,
                    candidates=candidate_entries,
                )
            rows.append(
                SourcePacketRow(
                    source_name=source_name,
                    channel_name=str(row["channel_name"]),
                    learn_key=str(row["learn_key"]),
                    description=str(row["description"]),
                    packet_hex=format_packet_bytes(packet) if packet is not None else None,
                    status=STATUS_CONFIRMED if row["packet"] is not None else (STATUS_INFERRED if packet is not None else STATUS_UNKNOWN),
                )
            )
    return rows
def build_packet_semantic_tags(
    packet: list[int],
    description: str,
) -> dict[str, object]:
    tags = extract_tags(description)
    mode = decode_structured_packet16_mode(packet)
    if mode is not None:
        tags["mode"] = mode
    power = decode_structured_packet16_power(packet)
    if power is not None:
        tags["power"] = power
    temperature = decode_structured_packet16_temperature(packet)
    if temperature is not None:
        tags["temperature"] = temperature
    return tags
def is_plain_power_description(description: str) -> bool:
    tags = extract_tags(description)
    has_mode = tags.get("mode") in {"cool", "heat"}
    has_temp = isinstance(tags.get("temperature"), int)
    return not has_mode and not has_temp and re.search(r"\u5f00\u673a|\u5173\u673a", description) is not None
def packet_similarity_score(left: list[int], right: list[int]) -> int:
    return sum(12 for a, b in zip(left[:8], right[:8]) if a == b)
def score_source_packet_candidate(
    source_name: str,
    learn_key: str,
    target_tags: dict[str, object],
    description: str,
    candidate: SourcePacketCandidate,
    reference_packets: list[list[int]],
) -> int:
    candidate_tags = build_packet_semantic_tags(candidate.packet, candidate.description)
    score = 0
    target_power = target_tags.get("power")
    candidate_power = candidate_tags.get("power")
    if target_power is not None:
        score += 90 if target_power == candidate_power else -120
    target_mode = target_tags.get("mode")
    candidate_mode = candidate_tags.get("mode")
    if target_mode is not None:
        score += 70 if target_mode == candidate_mode else -90
    target_temp = target_tags.get("temperature")
    candidate_temp = candidate_tags.get("temperature")
    if isinstance(target_temp, int) and isinstance(candidate_temp, int):
        score += 60 if target_temp == candidate_temp else max(0, 30 - abs(target_temp - candidate_temp) * 10)
    if description == candidate.description:
        score += 30
    if learn_key == candidate.learn_key:
        score += 12
    if source_name == candidate.source_name:
        score += 8
    if is_plain_power_description(description):
        score += 50 if candidate.packet[12] == 0x05 else -35
    if reference_packets:
        score += max(packet_similarity_score(candidate.packet, packet) for packet in reference_packets)
    return score
def collect_neighbor_reference_packets(
    source_rows: list[dict[str, object]],
    learn_key: str,
) -> list[list[int]]:
    target_number = extract_learn_number(learn_key) or 0
    neighbors: list[tuple[int, list[int]]] = []
    for row in source_rows:
        packet = row.get("packet")
        if not isinstance(packet, list):
            continue
        row_number = extract_learn_number(str(row.get("learn_key"))) or 0
        distance = abs(row_number - target_number)
        if distance == 0:
            continue
        neighbors.append((distance, list(packet)))
    neighbors.sort(key=lambda item: item[0])
    return [packet for _distance, packet in neighbors[:3]]
def infer_target_tags_from_references(
    description: str,
    reference_packets: list[list[int]],
) -> dict[str, object]:
    tags = extract_tags(description)
    if is_plain_power_description(description):
        tags["mode"] = None
    if tags.get("mode") is None and reference_packets:
        modes = [
            mode
            for mode in (decode_structured_packet16_mode(packet) for packet in reference_packets)
            if mode is not None
        ]
        if modes:
            tags["mode"] = Counter(modes).most_common(1)[0][0]
    if tags.get("power") is None and reference_packets:
        powers = [
            power
            for power in (decode_structured_packet16_power(packet) for packet in reference_packets)
            if power is not None
        ]
        if powers:
            tags["power"] = Counter(powers).most_common(1)[0][0]
    return tags
def find_source_packet_fallback(
    source_name: str,
    learn_key: str,
    description: str,
    source_rows: list[dict[str, object]],
    candidates: list[SourcePacketCandidate],
) -> list[int] | None:
    reference_packets = collect_neighbor_reference_packets(source_rows, learn_key)
    target_tags = infer_target_tags_from_references(description, reference_packets)
    if not candidates:
        return None
    scored_candidates: list[tuple[int, SourcePacketCandidate]] = []
    for candidate in candidates:
        score = score_source_packet_candidate(
            source_name=source_name,
            learn_key=learn_key,
            target_tags=target_tags,
            description=description,
            candidate=candidate,
            reference_packets=reference_packets,
        )
        scored_candidates.append((score, candidate))
    best_score, best_candidate = max(scored_candidates, key=lambda item: item[0])
    if best_score < 90:
        return None
    return list(best_candidate.packet)
def is_auto_split_file(path: Path) -> bool:
    return path.name in AUTO_SPLIT_FILENAMES.values()
def auto_split_legacy_samples(
    commands: list[CommandSample],
) -> dict[str, list[CommandSample]]:
    grouped: dict[str, list[CommandSample]] = {group: [] for group in AUTO_SPLIT_GROUP_ORDER}
    for command in commands:
        mode = command.tags.get("mode")
        if mode == "cool":
            grouped["cool"].append(clone_command_for_group(command, "cool"))
        if mode == "heat":
            grouped["heat"].append(clone_command_for_group(command, "heat"))
        if is_power_cycle_command(command):
            grouped["power_cycle"].append(clone_command_for_group(command, "power_cycle"))
    return {
        group: dedupe_commands(group_commands)
        for group, group_commands in grouped.items()
        if group_commands
    }
def clone_command_for_group(command: CommandSample, group_name: str) -> CommandSample:
    return replace(command, sample_kind=group_name, sample_name=group_name)
def dedupe_commands(commands: list[CommandSample]) -> list[CommandSample]:
    seen: set[tuple[str, str]] = set()
    unique: list[CommandSample] = []
    for command in sorted(
        commands,
        key=lambda item: (str(item.source_file), extract_learn_number(item.learn_key) or 0),
    ):
        key = (str(command.source_file.resolve()), command.learn_key)
        if key in seen:
            continue
        seen.add(key)
        unique.append(command)
    return unique
def is_power_cycle_command(command: CommandSample) -> bool:
    if command.tags.get("mode") == "off":
        return True
    return re.search(r"\u5f00\u673a|\u5173\u673a|\bon\b|\boff\b", command.description, re.IGNORECASE) is not None
def build_loaded_samples_from_grouped_commands(
    grouped_samples: dict[str, list[CommandSample]],
) -> list[LoadedSample]:
    loaded_samples: list[LoadedSample] = []
    for group_name in AUTO_SPLIT_GROUP_ORDER:
        commands = grouped_samples.get(group_name)
        if not commands:
            continue
        loaded_samples.append(
            LoadedSample(
                sample_kind=group_name,
                sample_name=group_name,
                description=AUTO_SPLIT_DESCRIPTIONS[group_name],
                commands=commands,
            )
        )
    return loaded_samples
def loaded_samples_by_kind(samples: list[LoadedSample]) -> list[str]:
    return [sample.sample_kind for sample in samples]
def load_manifest_samples(
    brand_dir: Path,
    manifest_path: Path,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[LoadedSample], str, list[str]]:
    manifest_data = json.loads(read_text_auto(manifest_path))
    samples_node = manifest_data.get("samples")
    if not isinstance(samples_node, dict):
        raise AnalysisError("samples object is missing in manifest.")
    required = ("cool", "heat", "power_cycle")
    missing = [name for name in required if name not in samples_node]
    if missing:
        raise AnalysisError(f"Missing required samples in manifest: {', '.join(missing)}")
    emit_progress(progress, f"Loaded manifest with required groups: {', '.join(required)}")
    loaded_samples: list[LoadedSample] = []
    skipped_learns: list[str] = []
    for sample_kind in required:
        sample_node = samples_node[sample_kind]
        if not isinstance(sample_node, dict):
            raise AnalysisError(f"samples.{sample_kind} must be an object.")
        file_value = sample_node.get("file")
        if not file_value:
            raise AnalysisError(f"samples.{sample_kind}.file is required.")
        file_path = (brand_dir / str(file_value)).resolve()
        if not file_path.is_file():
            raise AnalysisError(f"Sample file does not exist: {file_path}")
        description = str(sample_node.get("description", sample_kind))
        payloads = parse_learn_payloads(file_path)
        selected = resolve_learn_selection(payloads, sample_node.get("learn_map"))
        emit_progress(
            progress,
            f"Manifest group {sample_kind}: source {file_path.name}, selected {len(selected)} of {len([key for key in payloads if key.endswith('Code')])} Learn entries",
        )
        if not selected:
            raise AnalysisError(f"No Learn payloads selected from {file_path}")
        commands: list[CommandSample] = []
        group_skipped = 0
        for alias, learn_key in selected:
            command_sample = try_build_command_sample(
                sample_kind=sample_kind,
                sample_name=sample_kind,
                learn_key=learn_key,
                description=f"{description} {alias}".strip(),
                source_file=file_path,
                raw_hex=payloads[learn_key],
                inherited_tags=extract_tags(f"{sample_kind} {description} {alias}"),
            )
            if command_sample is None:
                skipped_learns.append(f"{file_path.name}:{learn_key}")
                group_skipped += 1
                continue
            commands.append(command_sample)
        if not commands:
            raise AnalysisError(
                f"All selected Learn payloads in {file_path.name} were empty/all-FF after trimming."
            )
        emit_progress(
            progress,
            f"Manifest group {sample_kind}: kept {len(commands)}, skipped {group_skipped}",
        )
        loaded_samples.append(
            LoadedSample(
                sample_kind=sample_kind,
                sample_name=sample_kind,
                description=description,
                commands=commands,
            )
        )
    notes = [
        "Input mode: manifest",
        f"Manifest file: {manifest_path}",
        "Required groups: cool, heat, power_cycle",
    ]
    if skipped_learns:
        notes.append("Skipped empty/all-FF Learn payloads: " + ", ".join(skipped_learns))
    return loaded_samples, "manifest", notes
def resolve_learn_selection(
    payloads: dict[str, str],
    learn_map: object,
) -> list[tuple[str, str]]:
    if learn_map is None:
        keys = sorted(
            (key for key in payloads if key.endswith("Code")),
            key=lambda item: extract_learn_number(item) or 0,
        )
        return [(key, key) for key in keys]
    if not isinstance(learn_map, dict):
        raise AnalysisError("learn_map must be an object.")
    selections: list[tuple[str, str]] = []
    for alias, raw_ref in learn_map.items():
        normalized = normalize_learn_reference(str(raw_ref))
        if normalized not in payloads:
            raise AnalysisError(f"learn_map references missing Learn payload: {raw_ref}")
        selections.append((str(alias), normalized))
    return selections
def normalize_learn_reference(value: str) -> str:
    compact = value.strip()
    number = extract_learn_number(compact)
    if number is None:
        return compact
    if re.search(r"Code$", compact, re.IGNORECASE):
        return f"Learn{number}Code"
    if compact.lower().startswith("learn"):
        return f"Learn{number}"
    return str(number)
def build_command_sample(
    sample_kind: str,
    sample_name: str,
    learn_key: str,
    description: str,
    source_file: Path,
    raw_hex: str,
    inherited_tags: dict[str, object],
) -> CommandSample:
    trimmed_hex = trim_raw_hex(raw_hex)
    chunks = split_chunks(bytes.fromhex(trimmed_hex))
    analyzed_chunks = [analyze_chunk(chunk) for chunk in chunks]
    tags = enrich_tags_from_payload(inherited_tags, analyzed_chunks)
    return CommandSample(
        sample_kind=sample_kind,
        sample_name=sample_name,
        learn_key=learn_key,
        description=description,
        source_file=source_file,
        raw_hex=raw_hex,
        trimmed_hex=trimmed_hex,
        chunks=analyzed_chunks,
        tags=tags,
    )
def try_build_command_sample(
    sample_kind: str,
    sample_name: str,
    learn_key: str,
    description: str,
    source_file: Path,
    raw_hex: str,
    inherited_tags: dict[str, object],
) -> CommandSample | None:
    try:
        return build_command_sample(
            sample_kind=sample_kind,
            sample_name=sample_name,
            learn_key=learn_key,
            description=description,
            source_file=source_file,
            raw_hex=raw_hex,
            inherited_tags=inherited_tags,
        )
    except SkipLearnPayload:
        return None
def split_chunks(data: bytes) -> list[ChunkAnalysis]:
    if len(data) < 4:
        raise AnalysisError("Payload is too short to contain a chunk header.")
    chunks: list[ChunkAnalysis] = []
    cursor = 0
    chunk_index = 1
    while cursor + 4 <= len(data):
        header = data[cursor : cursor + 4]
        cursor += 4
        pairs: list[PulsePair] = []
        separator_hex: str | None = None
        while cursor + 2 <= len(data):
            pair = PulsePair(value=data[cursor], pulse_type=data[cursor + 1])
            cursor += 2
            if pair.pulse_type == 0x82:
                separator_hex = pair.hex
                break
            pairs.append(pair)
        chunks.append(
            ChunkAnalysis(
                index=chunk_index,
                header_hex=header.hex().upper(),
                pairs=pairs,
                separator_hex=separator_hex,
            )
        )
        chunk_index += 1
        if cursor >= len(data):
            break
    return chunks
def analyze_chunk(chunk: ChunkAnalysis) -> ChunkAnalysis:
    if not chunk.pairs:
        return chunk
    decoded_bits, markers, decode_meta = decode_chunk_bitstream(chunk.pairs)
    if decode_meta is None:
        return chunk
    chunk.mark_type = decode_meta["mark_type"]
    chunk.zero_type = decode_meta["zero_type"]
    chunk.one_type = decode_meta["one_type"]
    chunk.markers.extend(markers)
    chunk.total_bits = len(decoded_bits)
    chunk.payload_bit_count = determine_payload_bit_count(chunk.total_bits)
    payload_bits = decoded_bits[: chunk.payload_bit_count]
    chunk.payload_fields = bits_to_fields(
        chunk_index=chunk.index,
        bit_pulses=payload_bits,
        field_prefix="payload",
        note_prefix="payload byte",
    )
    chunk.payload_bytes = [
        int(field.hex_value, 16)
        for field in chunk.payload_fields
        if field.bit_count == 8 and len(field.hex_value) == 2
    ]
    tail_bits = decoded_bits[chunk.payload_bit_count :]
    chunk.tail_fields = bits_to_fields(
        chunk_index=chunk.index,
        bit_pulses=tail_bits,
        start_bit=chunk.payload_bit_count,
        field_prefix="tail",
        note_prefix="tail bits",
    )
    return chunk
def decode_chunk_bitstream(
    pairs: list[PulsePair],
) -> tuple[list[BitPulse], list[MarkerSegment], dict[str, int] | None]:
    candidates = collect_decode_candidates(pairs)
    if not candidates:
        return [], [], None
    best_strategy = select_best_decode_candidate(candidates, pairs)
    decoded, markers = decode_candidate_output(best_strategy, pairs)
    return decoded, markers, {
        "mark_type": best_strategy.mark_type,
        "zero_type": best_strategy.zero_type,
        "one_type": best_strategy.one_type,
    }
def collect_decode_candidates(pairs: list[PulsePair]) -> list[DecodeStrategyCandidate]:
    candidates: list[DecodeStrategyCandidate] = []
    max_offset = min(8, max(0, len(pairs) - 2))
    strategy_evaluators = (evaluate_pair_alignment, evaluate_type_pair_alignment)
    for offset in range(max_offset + 1):
        for evaluator in strategy_evaluators:
            candidate = evaluator(pairs, offset)
            if candidate is not None:
                candidates.append(candidate)
    return candidates
def select_best_decode_candidate(
    candidates: list[DecodeStrategyCandidate],
    pairs: list[PulsePair],
) -> DecodeStrategyCandidate:
    return max(candidates, key=lambda item: candidate_sort_key(item, pairs))
def decode_candidate_output(
    candidate: DecodeStrategyCandidate,
    pairs: list[PulsePair],
) -> tuple[list[BitPulse], list[MarkerSegment]]:
    decoded: list[BitPulse] = []
    markers: list[MarkerSegment] = []
    marker_index = 1
    for pair in pairs[: candidate.offset]:
        markers.append(MarkerSegment(name=f"marker{marker_index}", raw_hex=pair.hex))
        marker_index += 1
    cursor = candidate.offset
    for _ in range(candidate.pair_count):
        left = pairs[cursor]
        right = pairs[cursor + 1]
        bit_value = 0 if pair_word_value(right) <= candidate.threshold else 1
        decoded.append(BitPulse(bit=bit_value, raw_hex=f"{left.hex} {right.hex}"))
        cursor += 2
    for pair in pairs[cursor:]:
        markers.append(MarkerSegment(name=f"marker{marker_index}", raw_hex=pair.hex))
        marker_index += 1
    return decoded, markers
def evaluate_pair_alignment(pairs: list[PulsePair], offset: int) -> DecodeStrategyCandidate | None:
    left_words = pairs[offset::2]
    right_words = pairs[offset + 1 :: 2]
    pair_count = min(len(left_words), len(right_words))
    if pair_count < 8:
        return None
    left_words = left_words[:pair_count]
    right_words = right_words[:pair_count]
    right_values = [pair_word_value(pair) for pair in right_words]
    threshold, gap, low_count, high_count = split_value_clusters(right_values)
    if threshold is None or gap < 0x20 or low_count < 3 or high_count < 3:
        return None
    left_majority_type, left_majority_count = Counter(pair.pulse_type for pair in left_words).most_common(1)[0]
    majority_ratio = left_majority_count / pair_count
    if majority_ratio < 0.5:
        return None
    left_mad, left_span = measure_value_stability(left_words)
    low_group = [pair for pair in right_words if pair_word_value(pair) <= threshold]
    high_group = [pair for pair in right_words if pair_word_value(pair) > threshold]
    if not low_group or not high_group:
        return None
    zero_type = Counter(pair.pulse_type for pair in low_group).most_common(1)[0][0]
    one_type = Counter(pair.pulse_type for pair in high_group).most_common(1)[0][0]
    score = pair_count * gap * majority_ratio
    return DecodeStrategyCandidate(
        strategy_name="word-cluster",
        offset=offset,
        pair_count=pair_count,
        threshold=threshold,
        gap=gap,
        base_score=score,
        left_mad=left_mad,
        left_span=left_span,
        mark_type=left_majority_type,
        zero_type=zero_type,
        one_type=one_type,
    )
def evaluate_type_pair_alignment(pairs: list[PulsePair], offset: int) -> DecodeStrategyCandidate | None:
    left_words = pairs[offset::2]
    right_words = pairs[offset + 1 :: 2]
    pair_count = min(len(left_words), len(right_words))
    if pair_count < 8:
        return None
    left_words = left_words[:pair_count]
    right_words = right_words[:pair_count]
    left_majority_type, left_majority_count = Counter(pair.pulse_type for pair in left_words).most_common(1)[0]
    left_majority_ratio = left_majority_count / pair_count
    if left_majority_ratio < 0.5:
        return None
    left_mad, left_span = measure_value_stability(left_words)
    right_type_counts = Counter(pair.pulse_type for pair in right_words)
    dominant_right_types = right_type_counts.most_common(2)
    if len(dominant_right_types) < 2:
        return None
    zero_type, one_type = determine_space_types_by_value(right_words, dominant_right_types)
    if zero_type is None or one_type is None:
        return None
    covered_pairs = right_type_counts[zero_type] + right_type_counts[one_type]
    coverage_ratio = covered_pairs / pair_count
    if coverage_ratio < 0.75:
        return None
    zero_values = [pair_word_value(pair) for pair in right_words if pair.pulse_type == zero_type]
    one_values = [pair_word_value(pair) for pair in right_words if pair.pulse_type == one_type]
    if not zero_values or not one_values:
        return None
    gap = int(median(one_values) - median(zero_values))
    if gap < 0x20:
        return None
    zero_max = max(zero_values)
    one_min = min(one_values)
    threshold = (zero_max + one_min) // 2 if zero_max < one_min else int(median(zero_values))
    score = pair_count * gap * left_majority_ratio * coverage_ratio
    return DecodeStrategyCandidate(
        strategy_name="type-cluster",
        offset=offset,
        pair_count=pair_count,
        threshold=threshold,
        gap=gap,
        base_score=score,
        left_mad=left_mad,
        left_span=left_span,
        mark_type=left_majority_type,
        zero_type=zero_type,
        one_type=one_type,
    )
def split_value_clusters(values: list[int]) -> tuple[int | None, int, int, int]:
    if len(values) < 6:
        return None, 0, 0, 0
    sorted_values = sorted(values)
    best_gap = 0
    best_index: int | None = None
    for index, (left, right) in enumerate(zip(sorted_values, sorted_values[1:]), start=1):
        gap = right - left
        if gap > best_gap:
            best_gap = gap
            best_index = index
    if best_index is None:
        return None, 0, 0, 0
    low_count = best_index
    high_count = len(sorted_values) - best_index
    threshold = sorted_values[best_index - 1]
    return threshold, best_gap, low_count, high_count
def determine_space_types_by_value(
    right_words: list[PulsePair],
    dominant_right_types: list[tuple[int, int]],
) -> tuple[int | None, int | None]:
    medians_by_type: list[tuple[float, int]] = []
    for pulse_type, _count in dominant_right_types:
        values = [pair_word_value(pair) for pair in right_words if pair.pulse_type == pulse_type]
        if not values:
            continue
        medians_by_type.append((median(values), pulse_type))
    if len(medians_by_type) < 2:
        return None, None
    medians_by_type.sort(key=lambda item: item[0])
    return medians_by_type[0][1], medians_by_type[-1][1]
def measure_value_stability(words: list[PulsePair]) -> tuple[float, int]:
    values = [pair.value for pair in words]
    center = median(values)
    mad = float(median(abs(value - center) for value in values))
    span = max(values) - min(values)
    return mad, span
def candidate_sort_key(candidate: DecodeStrategyCandidate, pairs: list[PulsePair]) -> tuple[float, ...]:
    pair_count = candidate.pair_count
    offset = candidate.offset
    decoded_bits = decode_candidate_bits(candidate, pairs)
    payload_bit_count = determine_payload_bit_count(len(decoded_bits))
    tail_bits = len(decoded_bits) - payload_bit_count
    known_types = {candidate.mark_type, candidate.zero_type, candidate.one_type}
    prefix_pairs = pairs[:offset]
    suffix_pairs = pairs[offset + pair_count * 2 :]
    prefix_outliers = sum(1 for pair in prefix_pairs if pair.pulse_type not in known_types)
    suffix_outliers = sum(1 for pair in suffix_pairs if pair.pulse_type not in known_types)
    prefix_expected = len(prefix_pairs) - prefix_outliers
    suffix_expected = len(suffix_pairs) - suffix_outliers
    marker_bonus = (prefix_outliers + suffix_outliers) * 150000 - (prefix_expected + suffix_expected) * 150000
    offset_penalty = offset * 50000
    strategy_bonus = 256 if candidate.strategy_name == "type-cluster" else 0
    payload_penalty = assess_payload_penalty(decoded_bits[:payload_bit_count])
    return (
        candidate.base_score + marker_bonus - offset_penalty - payload_penalty + strategy_bonus,
        payload_bit_count,
        -tail_bits,
        offset,
    )
def decode_candidate_bits(candidate: DecodeStrategyCandidate, pairs: list[PulsePair]) -> list[int]:
    return [
        0 if pair_word_value(pairs[candidate.offset + index * 2 + 1]) <= candidate.threshold else 1
        for index in range(candidate.pair_count)
    ]
def assess_payload_penalty(payload_bits: list[int]) -> int:
    if not payload_bits:
        return 500000
    bit_sum = sum(payload_bits)
    if bit_sum == 0 or bit_sum == len(payload_bits):
        return 500000
    payload_bytes = [
        bits_to_lsb_int(payload_bits[index : index + 8])
        for index in range(0, len(payload_bits) - (len(payload_bits) % 8), 8)
    ]
    if len(payload_bytes) >= 4 and len(set(payload_bytes)) == 1:
        return 400000
    penalty = 0
    if len(payload_bytes) >= 16:
        reversed_head = [reverse_bits_in_byte(byte) for byte in payload_bytes[:16]]
        noisy_prefix = sum(1 for byte in reversed_head[:10] if byte >= 0xF0)
        ff_like_count = sum(1 for byte in reversed_head[:16] if byte >= 0xF0)
        if reversed_head[0] >= 0xF0 and noisy_prefix >= 6:
            penalty += 6500000
        elif ff_like_count >= 10:
            penalty += 3000000
    return penalty
def pair_word_value(pair: PulsePair) -> int:
    return (pair.value << 8) | pair.pulse_type
def determine_payload_bit_count(total_bits: int) -> int:
    if total_bits >= 64 and total_bits - 64 <= 8:
        return 64
    if total_bits >= 8:
        return total_bits - (total_bits % 8)
    return total_bits
def bits_to_fields(
    chunk_index: int,
    bit_pulses: list[BitPulse],
    field_prefix: str,
    note_prefix: str,
    start_bit: int = 0,
) -> list[DataField]:
    if not bit_pulses:
        return []
    fields: list[DataField] = []
    cursor = 0
    while cursor < len(bit_pulses):
        remaining = len(bit_pulses) - cursor
        group_size = 8 if remaining >= 8 else remaining
        group = bit_pulses[cursor : cursor + group_size]
        absolute_start = start_bit + cursor
        absolute_end = absolute_start + len(group) - 1
        bit_string = "".join(str(item.bit) for item in group)
        value = bits_to_lsb_int(item.bit for item in group)
        range_label = (
            f"{absolute_start}-{absolute_end}"
            if len(group) > 1
            else str(absolute_start)
        )
        note = f"{note_prefix} {absolute_start // 8}" if len(group) == 8 else note_prefix
        fields.append(
            DataField(
                key=f"chunk{chunk_index}.{field_prefix}{absolute_start}",
                segment_name=f"帧{chunk_index}-{range_label}",
                bit_range_label=range_label,
                bits=bit_string,
                hex_value=f"{value:02X}" if len(group) == 8 else f"{value:X}",
                bit_count=len(group),
                start_bit=absolute_start,
                raw_hex=" ".join(item.raw_hex for item in group),
                note=note,
            )
        )
        cursor += group_size
    return fields
def bits_to_lsb_int(bits: Iterable[int]) -> int:
    value = 0
    for index, bit in enumerate(bits):
        value |= (int(bit) & 1) << index
    return value
def extract_tags(text: str) -> dict[str, object]:
    tags: dict[str, object] = {
        "mode": None,
        "power": None,
        "temperature": None,
        "action": None,
    }
    has_cool = "制冷" in text or re.search(r"\bcool\b", text, re.IGNORECASE) is not None
    has_heat = "制热" in text or re.search(r"\bheat\b", text, re.IGNORECASE) is not None
    has_on = "开机" in text or re.search(r"\bon\b", text, re.IGNORECASE) is not None
    has_off = "关机" in text or re.search(r"\boff\b", text, re.IGNORECASE) is not None
    has_up = "升温" in text
    has_down = "降温" in text
    if has_cool and not has_heat:
        tags["mode"] = "cool"
    elif has_heat and not has_cool:
        tags["mode"] = "heat"
    elif has_off and not has_on:
        tags["mode"] = "off"
        tags["power"] = "off"
    if has_on and not has_off:
        tags["power"] = "on"
    elif has_off and not has_on:
        tags["power"] = "off"
    if has_up and not has_down:
        tags["action"] = "temp_up"
    elif has_down and not has_up:
        tags["action"] = "temp_down"
    match = re.search(r"\b(\d{1,2})\s*(?:度|deg\b|°?c\b)", text, re.IGNORECASE)
    if match:
        tags["temperature"] = int(match.group(1))
    return tags
def enrich_tags_from_payload(
    inherited_tags: dict[str, object],
    chunks: list[ChunkAnalysis],
) -> dict[str, object]:
    tags = dict(inherited_tags)
    first_payload = next((chunk.payload_bytes for chunk in chunks if len(chunk.payload_bytes) >= 2), None)
    if not first_payload:
        return tags
    mode = decode_mode(first_payload[0])
    if mode is not None:
        tags["mode"] = mode
        tags["power"] = "off" if mode == "off" else "on"
    if tags.get("temperature") is None:
        inferred_temperature = first_payload[1] + 16
        if 16 <= inferred_temperature <= 31:
            tags["temperature"] = inferred_temperature
    return tags
def decode_mode(byte_value: int) -> str | None:
    return {
        0x09: "cool",
        0x3C: "heat",
        0x34: "off",
        0x00: "auto",
        0x04: "fan",
    }.get(byte_value)
def infer_fields(commands: list[CommandSample]) -> list[FieldInference]:
    field_values: defaultdict[str, list[tuple[CommandSample, DataField]]] = defaultdict(list)
    for command in commands:
        for chunk in command.chunks:
            for field in chunk.payload_fields:
                field_values[field.key].append((command, field))
    inferences: list[FieldInference] = []
    for field_key, entries in sorted(field_values.items()):
        segment_name = entries[0][1].segment_name
        observed = ", ".join(
            f"{command.description}:{field.hex_value}" for command, field in entries[:8]
        )
        values = sorted({field.hex_value for _, field in entries})
        if len(entries) < len(commands):
            status = STATUS_UNKNOWN
            meaning = "field not present in all samples"
            evidence = f"present in {len(entries)}/{len(commands)} samples"
        elif len(values) == 1:
            status, meaning, evidence = infer_fixed_meaning(entries[0][1], values[0])
        else:
            meaning, status, evidence = infer_variable_meaning(entries)
        inferences.append(
            FieldInference(
                field_key=field_key,
                segment_name=segment_name,
                observed_values=observed,
                status=status,
                meaning=meaning,
                evidence=evidence,
            )
        )
    return inferences
def infer_fixed_meaning(field: DataField, hex_value: str) -> tuple[str, str, str]:
    if field.start_bit == 16 and hex_value == "00":
        return STATUS_CONFIRMED, "fixed byte", "all samples carry 00 in byte[2]"
    if field.start_bit == 24 and hex_value in {"50", "70"}:
        frame_index = "frame1" if hex_value == "50" else "frame2"
        return STATUS_CONFIRMED, "frame tag", f"all samples carry {hex_value} for {frame_index}"
    if field.start_bit == 32 and hex_value == "02":
        return STATUS_CONFIRMED, "fixed byte", "all samples carry 02 in byte[4]"
    if field.start_bit == 40 and hex_value == "00":
        return STATUS_CONFIRMED, "fixed byte", "all samples carry 00 in byte[5]"
    return STATUS_CONFIRMED, "fixed field", f"all samples carry {hex_value}"
def infer_variable_meaning(
    entries: list[tuple[CommandSample, DataField]],
) -> tuple[str, str, str]:
    mode_groups = group_by_tag(entries, "mode")
    power_groups = group_by_tag(entries, "power")
    temp_entries = [
        (int(command.tags["temperature"]), field.hex_value)
        for command, field in entries
        if isinstance(command.tags.get("temperature"), int)
    ]
    if is_clean_value_partition(mode_groups):
        return (
            "mode candidate",
            STATUS_INFERRED,
            f"mode groups map cleanly: {summarize_group_values(mode_groups)}",
        )
    if is_clean_value_partition(power_groups):
        return (
            "power candidate",
            STATUS_INFERRED,
            f"power groups map cleanly: {summarize_group_values(power_groups)}",
        )
    if len(temp_entries) >= 3 and has_monotonic_temperature_mapping(temp_entries):
        return (
            "temperature candidate",
            STATUS_CONFIRMED,
            "field value changes monotonically with temperature labels",
        )
    return (
        "variable field, meaning unresolved",
        STATUS_UNKNOWN,
        "multiple values observed without a stable label mapping",
    )
def group_by_tag(
    entries: list[tuple[CommandSample, DataField]],
    tag_name: str,
) -> dict[str, set[str]]:
    grouped: defaultdict[str, set[str]] = defaultdict(set)
    for command, field in entries:
        tag_value = command.tags.get(tag_name)
        if tag_value is not None:
            grouped[str(tag_value)].add(field.hex_value)
    return dict(grouped)
def is_clean_value_partition(grouped: dict[str, set[str]]) -> bool:
    if len(grouped) < 2:
        return False
    flattened: list[str] = []
    for values in grouped.values():
        if len(values) != 1:
            return False
        flattened.extend(values)
    return len(set(flattened)) == len(flattened)
def summarize_group_values(grouped: dict[str, set[str]]) -> str:
    return ", ".join(f"{key}={next(iter(values))}" for key, values in sorted(grouped.items()))
def has_monotonic_temperature_mapping(temp_entries: list[tuple[int, str]]) -> bool:
    sorted_entries = sorted(temp_entries, key=lambda item: item[0])
    values = [int(value, 16) for _, value in sorted_entries]
    return all(left <= right for left, right in zip(values, values[1:])) or all(
        left >= right for left, right in zip(values, values[1:])
    )
def format_consistent_count(values: list[int], unit: str, fallback: str) -> str:
    filtered = [value for value in values if value > 0]
    if not filtered:
        return fallback
    unique = sorted(set(filtered))
    if len(unique) == 1:
        return f"{unique[0]} {unit}"
    return "/".join(str(value) for value in unique) + f" {unit}"
def summarize_hex_values(values: Iterable[str | None], fallback: str = "未识别", limit: int = 8) -> str:
    normalized = [value for value in values if value]
    if not normalized:
        return fallback
    unique = sorted(set(normalized))
    rendered = ", ".join(f"`{value}`" for value in unique[:limit])
    if len(unique) > limit:
        rendered += f" 等 {len(unique)} 种"
    return rendered
def collect_valid_chunks(commands: list[CommandSample]) -> list[ChunkAnalysis]:
    return [
        chunk
        for command in commands
        for chunk in command.chunks
        if chunk.payload_bit_count > 0 or chunk.payload_bytes
    ]
def collect_frame_byte_stats(
    commands: list[CommandSample],
) -> dict[int, dict[int, list[DataField]]]:
    frame_stats: defaultdict[int, defaultdict[int, list[DataField]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for command in commands:
        for chunk in command.chunks:
            for field in chunk.payload_fields:
                if field.bit_count == 8:
                    frame_stats[chunk.index][field.start_bit // 8].append(field)
    return {
        frame_index: dict(byte_map)
        for frame_index, byte_map in frame_stats.items()
    }
def guess_field_label(byte_index: int, inference: FieldInference | None, observed_values: list[str]) -> str:
    if inference is not None:
        if inference.meaning == "mode candidate":
            return "模式"
        if inference.meaning == "temperature candidate":
            return "温度"
        if inference.meaning == "frame tag":
            return "帧标识"
        if inference.meaning == "power candidate":
            return "开关候选"
        if inference.meaning == "fixed byte":
            return "固定字节"
        if inference.meaning == "fixed field":
            return "固定字段"
    if byte_index == 6 and any(value == "80" for value in observed_values):
        return "状态/扩展字段候选"
    if byte_index == 7:
        return "校验/状态字段候选"
    return "未知字段"
def summarize_command_frames(command: CommandSample) -> list[str]:
    return [chunk.payload_hex or "-" for chunk in command.chunks]
def reverse_bits_in_byte(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)
def normalized_packet16_from_payload_bytes(payload_bytes: list[int]) -> list[int] | None:
    if len(payload_bytes) < 16:
        return None
    return [reverse_bits_in_byte(byte) for byte in payload_bytes[:16]]
def extract_normalized_packet16(command: CommandSample) -> list[int] | None:
    first_chunk = command.chunks[0] if command.chunks else None
    if first_chunk is None:
        return None
    return normalized_packet16_from_payload_bytes(first_chunk.payload_bytes)
def is_valid_standard_packet16(packet: list[int] | None) -> bool:
    if packet is None or len(packet) < 16 or packet[0] != 0xA6:
        return False
    return packet[5] in {0x60, 0xA0, 0xC0} and packet[7] in {0x20, 0x40, 0x60, 0x80, 0xC0}
def candidate_payload_bytes(
    candidate: DecodeStrategyCandidate,
    pairs: list[PulsePair],
) -> list[int]:
    bits = decode_candidate_bits(candidate, pairs)
    payload_bit_count = determine_payload_bit_count(len(bits))
    payload_bits = bits[:payload_bit_count]
    return [
        bits_to_lsb_int(payload_bits[index : index + 8])
        for index in range(0, len(payload_bits), 8)
    ]
def standard_packet16_quality(packet: list[int]) -> tuple[int, int, int]:
    trailing_special = 1 if packet[14] in {0xB7, 0x6E, 0xDC} else 0
    trailing_tail = 1 if packet[15] in {0x00, 0x01, 0x03} else 0
    control_bytes = sum(1 for value in packet[12:16] if value not in {0x00, 0xFF})
    return (trailing_special, trailing_tail, control_bytes)
def extract_preferred_standard_packet16(command: CommandSample) -> list[int] | None:
    first_chunk = command.chunks[0] if command.chunks else None
    if first_chunk is None:
        return None
    best_packet: list[int] | None = None
    best_key: tuple[tuple[int, int, int], tuple[float, ...]] | None = None
    candidates = collect_decode_candidates(first_chunk.pairs)
    for candidate in candidates:
        payload_bytes = candidate_payload_bytes(candidate, first_chunk.pairs)
        packet = normalized_packet16_from_payload_bytes(payload_bytes)
        if not is_valid_standard_packet16(packet):
            continue
        sort_key = candidate_sort_key(candidate, first_chunk.pairs)
        packet_key = (standard_packet16_quality(packet), sort_key)
        if best_key is None or packet_key > best_key:
            best_packet = packet
            best_key = packet_key
    if best_packet is not None:
        return repair_structured_packet16(best_packet, command)
    packet = extract_normalized_packet16(command)
    if not is_valid_standard_packet16(packet):
        return None
    return repair_structured_packet16(packet, command)
def format_packet_bytes(packet: list[int]) -> str:
    return " ".join(f"{byte:02X}" for byte in packet)
def decode_structured_packet16_mode(packet: list[int]) -> str | None:
    if len(packet) < 8 or packet[0] != 0xA6:
        return None
    return {
        0x20: "cool",
        0x80: "heat",
        0x40: "dry",
        0xC0: "auto",
        0x60: "fan",
    }.get(packet[7])
def decode_structured_packet16_temperature(packet: list[int]) -> int | None:
    if len(packet) < 2 or packet[0] != 0xA6:
        return None
    temperature = (packet[1] >> 4) + 16
    if 16 <= temperature <= 31:
        return temperature
    return None
def decode_structured_packet16_power(packet: list[int]) -> str | None:
    if len(packet) < 5 or packet[0] != 0xA6:
        return None
    return "on" if (packet[4] & 0x40) else "off"
def infer_structured_packet16_keycode(
    packet: list[int],
    command: CommandSample,
) -> int | None:
    if len(packet) < 16 or packet[0] != 0xA6:
        return None
    if packet[12] not in {0x00, 0xFF}:
        return packet[12]
    if packet[5] == 0xA0:
        return 0x01
    if packet[5] == 0x60 and is_power_cycle_command(command):
        return 0x05
    return None
def repair_structured_packet16(
    packet: list[int],
    command: CommandSample,
) -> list[int]:
    if len(packet) < 16 or packet[0] != 0xA6:
        return packet
    repaired = list(packet[:16])
    keycode = infer_structured_packet16_keycode(repaired, command)
    if keycode is not None and repaired[12] in {0x00, 0xFF}:
        repaired[12] = keycode
    weak_tail = (
        repaired[14] not in {0xB7, 0x6E, 0xDC}
        or repaired[15] not in {0x00, 0x01, 0x03}
        or all(value in {0x00, 0xFF} for value in repaired[12:16])
    )
    if weak_tail:
        repaired[14] = 0xB7
        repaired[15] = 0x00
        if repaired[12] not in {0x00, 0xFF}:
            repaired[13] = sum(repaired[:13]) & 0xFF
    elif repaired[14] == 0xB7 and repaired[15] == 0x00 and repaired[12] in {0x01, 0x05}:
        repaired[13] = sum(repaired[:13]) & 0xFF
    return repaired
def format_mode_tag(command: CommandSample) -> str:
    mapping = {
        "cool": "制冷",
        "heat": "制热",
        "off": "关机",
        "auto": "自动",
        "fan": "送风",
        "dry": "除湿",
    }
    normalized_packet = extract_preferred_standard_packet16(command)
    if normalized_packet is not None:
        normalized_mode = decode_structured_packet16_mode(normalized_packet)
        if normalized_mode is not None:
            return mapping.get(normalized_mode, "未知")
    mode = command.tags.get("mode")
    return mapping.get(str(mode), "未知")
def format_temperature_tag(command: CommandSample) -> str:
    normalized_packet = extract_preferred_standard_packet16(command)
    if normalized_packet is not None:
        normalized_temperature = decode_structured_packet16_temperature(normalized_packet)
        if normalized_temperature is not None:
            return f"{normalized_temperature}°C"
    temperature = command.tags.get("temperature")
    if isinstance(temperature, int):
        return f"{temperature}°C"
    return "未知"
def format_preferred_packet16_tag(command: CommandSample) -> str:
    normalized_packet = extract_preferred_standard_packet16(command)
    if normalized_packet is None:
        return "-"
    return format_packet_bytes(normalized_packet)
def find_example_command(commands: list[CommandSample]) -> CommandSample | None:
    scored = sorted(
        commands,
        key=lambda command: (
            sum(len(chunk.payload_bytes) for chunk in command.chunks),
            len(command.chunks),
        ),
        reverse=True,
    )
    return scored[0] if scored else None
# Historical implementation kept only as cleanup reference; not used by the tool.
def _deprecated_render_markdown_report_v1(
    brand_name: str,
    mode_label: str,
    samples: list[LoadedSample],
    commands: list[CommandSample],
    notes: list[str],
    field_inferences: list[FieldInference],
    source_packet_rows: list[SourcePacketRow] | None = None,
) -> str:
    valid_chunks = collect_valid_chunks(commands)
    frame_counts = [len(command.chunks) for command in commands]
    payload_byte_counts = [len(chunk.payload_bytes) for chunk in valid_chunks if chunk.payload_bytes]
    payload_bit_counts = [chunk.payload_bit_count for chunk in valid_chunks if chunk.payload_bit_count]
    field_inference_map = {item.field_key: item for item in field_inferences}
    frame_byte_stats = collect_frame_byte_stats(commands)
    example_command = find_example_command(commands)
    lines: list[str] = [
        f"# {brand_name}空调红外协议文档",
        "",
        "## 1. 协议概述",
        "",
        f"本文档由自动分析工具根据 `{len(commands)}` 条 Learn 报文生成，用于整理 `{brand_name}` 空调红外协议的当前观察结果。",
        "",
        "### 1.1 基本结论",
        "",
        "| 项目 | 观察结果 |",
        "|---|---|",
        f"| 输入模式 | `{mode_label}` |",
        f"| 样本分组 | `{len(samples)}` 组 |",
        f"| Learn 报文数 | `{len(commands)}` 条 |",
        f"| 可解码有效帧数 | `{len(valid_chunks)}` 帧 |",
        f"| 每条指令帧数 | {format_consistent_count(frame_counts, '帧', '未识别')} |",
        f"| 每帧有效载荷 | {format_consistent_count(payload_byte_counts, '字节', '未识别')} / {format_consistent_count(payload_bit_counts, 'bit', '未识别')} |",
        "| 位序假设 | `LSB-first`（当前字节重组使用该顺序） |",
    ]
    lines.extend(
        [
            "",
            "### 1.2 输入样本",
            "",
            "| 分组 | 说明 | Learn 数量 | 来源文件 |",
            "|---|---|---:|---|",
        ]
    )
    for sample in samples:
        source = sample.commands[0].source_file.name if sample.commands else "-"
        lines.append(
            f"| {sample.sample_name} | {escape_pipes(sample.description)} | {len(sample.commands)} | {source} |"
        )
    lines.extend(
        [
            "",
            "## 2. 帧格式",
            "",
            "以下内容按自动解码得到的有效 payload 字节整理；若某字段证据不足，会明确标记为 `推测` 或 `未知`。",
        ]
    )
    if not frame_byte_stats:
        lines.extend(
            [
                "",
                "当前样本中还没有稳定识别出可复用的 payload 字节结构。",
            ]
        )
    else:
        for frame_index in sorted(frame_byte_stats):
            lines.extend(
                [
                    "",
                    f"### 2.{frame_index} 帧 {frame_index} 字节布局",
                    "",
                    "| 字节 | 观测值 | 推导含义 | 状态 | 证据 |",
                    "|---|---|---|---|---|",
                ]
            )
            byte_map = frame_byte_stats[frame_index]
            for byte_index in sorted(byte_map):
                values = [field.hex_value for field in byte_map[byte_index]]
                inference = field_inference_map.get(f"chunk{frame_index}.payload{byte_index * 8}")
                meaning = guess_field_label(byte_index, inference, values)
                status = inference.status if inference is not None else STATUS_UNKNOWN
                evidence = inference.evidence if inference is not None else "当前样本不足以命名该字段"
                lines.append(
                    f"| `byte[{byte_index}]` | {summarize_hex_values(values)} | {escape_pipes(meaning)} | {status} | {escape_pipes(evidence)} |"
                )
    lines.extend(
        [
            "",
            "## 3. IR 编码特征",
            "",
            "| 项目 | 观察结果 |",
            "|---|---|",
            f"| Header 样本 | {summarize_hex_values(chunk.header_hex for chunk in valid_chunks)} |",
            f"| Mark 类型字节 | {summarize_hex_values(f'{chunk.mark_type:02X}' if chunk.mark_type is not None else None for chunk in valid_chunks)} |",
            f"| bit 0 类型字节 | {summarize_hex_values(f'{chunk.zero_type:02X}' if chunk.zero_type is not None else None for chunk in valid_chunks)} |",
            f"| bit 1 类型字节 | {summarize_hex_values(f'{chunk.one_type:02X}' if chunk.one_type is not None else None for chunk in valid_chunks)} |",
            f"| 帧间分隔 | {summarize_hex_values(chunk.separator_hex for chunk in valid_chunks)} |",
            f"| 尾部额外 bit 数 | {format_consistent_count([sum(field.bit_count for field in chunk.tail_fields) for chunk in valid_chunks], 'bit', '无')} |",
        ]
    )
    lines.extend(
        [
            "",
            "## 4. 解析过程",
            "",
            "### 4.1 自动解析流程",
            "",
            "1. 从原始 `LearnNCode=<HEX>` 中去掉 `0100` 终止符以及尾部 `FF` 填充。",
            "2. 将剩余原始数据拆成 header、脉冲对、帧间分隔和尾部标记。",
            "3. 根据主导类型字节推导 Mark、bit 0、bit 1 的编码关系，并重组为 bit 流。",
            "4. 按 `LSB-first` 将 bit 流重组成字节，再结合样本说明推导模式、温度、开关等候选字段。",
        ]
    )
    if example_command is not None:
        frame_hexes = summarize_command_frames(example_command)
        lines.extend(
            [
                "",
                "### 4.2 解析样例",
                "",
                f"以下样例取自 `{example_command.learn_key}`，说明为“{escape_pipes(example_command.description)}”。",
                "",
                "| 帧 | payload 字节 |",
                "|---|---|",
            ]
        )
        for index, frame_hex in enumerate(frame_hexes, start=1):
            lines.append(f"| 帧{index} | `{frame_hex}` |")
    lines.extend(
        [
            "",
            "## 5. 指令对照表",
            "",
            "| 分组 | Learn | 说明 | 模式 | 温度 | 帧1 | 帧2 |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for command in commands:
        frame_hexes = summarize_command_frames(command)
        frame1 = frame_hexes[0] if len(frame_hexes) >= 1 else "-"
        frame2 = frame_hexes[1] if len(frame_hexes) >= 2 else "-"
        lines.append(
            f"| {command.sample_name} | {command.learn_key} | {escape_pipes(command.description)} | {format_mode_tag(command)} | {format_temperature_tag(command)} | `{frame1}` | `{frame2}` |"
        )
    lines.extend(
        [
            "",
            "## 6. 字段推导表",
            "",
            "| 段名 | 状态 | 候选含义 | 观测值 | 证据 |",
            "|---|---|---|---|---|",
        ]
    )
    for item in field_inferences:
        lines.append(
            f"| {item.segment_name} | {item.status} | {escape_pipes(item.meaning)} | {escape_pipes(item.observed_values)} | {escape_pipes(item.evidence)} |"
        )
    lines.extend(
        [
            "",
            "## 7. 备注",
            "",
            f"- `{STATUS_CONFIRMED}` 表示当前样本已经能稳定支持该结论。",
            f"- `{STATUS_INFERRED}` 表示字段变化和标签关系明显，但还需要更多样本确认。",
            f"- `{STATUS_UNKNOWN}` 表示字段存在变化，但现有证据不足以安全命名。",
            "- 尾部多出的 bit 会单独保留，不会并入主要 payload 字节。",
        ]
    )
    lines.extend(f"- {escape_pipes(note)}" for note in notes)
    return "\n".join(lines) + "\n"
def _report_summarize_type_codes(values: Iterable[int | None]) -> str:
    normalized = sorted({f"{value:02X}" for value in values if value is not None})
    if not normalized:
        return "--"
    return "/".join(normalized)
def _report_build_pulse_pattern(mark_codes: str, space_codes: str) -> str:
    if mark_codes == "--" or space_codes == "--":
        return "\u672a\u8bc6\u522b"
    return f"`xx {mark_codes} xx {space_codes}`"
def _report_collect_group_representatives(
    samples: list[LoadedSample],
) -> dict[str, CommandSample]:
    representatives: dict[str, CommandSample] = {}
    for sample in samples:
        command = find_example_command(sample.commands)
        if command is not None:
            representatives[sample.sample_name] = command
    return representatives
def _report_describe_byte_role(
    byte_index: int,
    inference: FieldInference | None,
    observed_values: list[str],
) -> str:
    if inference is None:
        return "\u5f53\u524d\u6837\u672c\u4e0d\u8db3\u4ee5\u547d\u540d\u8be5\u5b57\u6bb5"
    if inference.meaning == "mode candidate":
        return "\u4e0e\u6a21\u5f0f\u6807\u7b7e\u5bf9\u5e94\u5173\u7cfb\u6700\u7a33\u5b9a\uff0c\u5f53\u524d\u6309\u6a21\u5f0f\u5b57\u6bb5\u5019\u9009\u5904\u7406"
    if inference.meaning == "temperature candidate":
        return "\u968f\u6e29\u5ea6\u6807\u7b7e\u5355\u8c03\u53d8\u5316\uff0c\u53ef\u4f5c\u4e3a\u6e29\u5ea6\u5b57\u6bb5\u5019\u9009"
    if inference.meaning == "power candidate":
        return "\u4e0e\u5f00/\u5173\u673a\u6807\u7b7e\u7684\u503c\u5206\u533a\u8f83\u660e\u663e"
    if inference.meaning == "frame tag":
        return "\u7528\u4e8e\u533a\u5206\u5e27\u6216\u62a5\u6587\u9636\u6bb5\u7684\u56fa\u5b9a\u6807\u8bb0"
    if inference.meaning == "fixed byte":
        return f"\u7a33\u5b9a\u56fa\u5b9a\u503c {summarize_hex_values(observed_values)}"
    if inference.meaning == "fixed field":
        return f"\u5f53\u524d\u6837\u672c\u4e2d\u4e3a\u56fa\u5b9a\u503c {summarize_hex_values(observed_values)}"
    if byte_index == 7:
        return "\u5f53\u524d\u66f4\u50cf\u6821\u9a8c/\u72b6\u6001\u5b57\u6bb5\uff0c\u4f46\u8bc1\u636e\u8fd8\u4e0d\u8db3"
    return inference.evidence
def _report_render_field_focus_table(
    lines: list[str],
    title: str,
    items: list[FieldInference],
) -> None:
    lines.extend(["", title, ""])
    if not items:
        lines.append("\u5f53\u524d\u6837\u672c\u8fd8\u6ca1\u6709\u5f62\u6210\u7a33\u5b9a\u7684\u5019\u9009\u7ed3\u8bba\u3002")
        return
    lines.extend(
        [
            "| \u6bb5\u540d | \u72b6\u6001 | \u5019\u9009\u542b\u4e49 | \u89c2\u6d4b\u503c | \u8bc1\u636e |",
            "|---|---|---|---|---|",
        ]
    )
    for item in items:
        lines.append(
            f"| {item.segment_name} | {item.status} | {escape_pipes(item.meaning)} | {escape_pipes(item.observed_values)} | {escape_pipes(item.evidence)} |"
        )
# Historical implementation kept only as cleanup reference; not used by the tool.
def _deprecated_render_markdown_report_v2(
    brand_name: str,
    mode_label: str,
    samples: list[LoadedSample],
    commands: list[CommandSample],
    notes: list[str],
    field_inferences: list[FieldInference],
    source_packet_rows: list[SourcePacketRow] | None = None,
) -> str:
    valid_chunks = collect_valid_chunks(commands)
    frame_counts = [len(command.chunks) for command in commands]
    payload_byte_counts = [len(chunk.payload_bytes) for chunk in valid_chunks if chunk.payload_bytes]
    payload_bit_counts = [chunk.payload_bit_count for chunk in valid_chunks if chunk.payload_bit_count]
    field_inference_map = {item.field_key: item for item in field_inferences}
    frame_byte_stats = collect_frame_byte_stats(commands)
    example_command = find_example_command(commands)
    representatives = _report_collect_group_representatives(samples)
    mark_codes = _report_summarize_type_codes(chunk.mark_type for chunk in valid_chunks)
    zero_codes = _report_summarize_type_codes(chunk.zero_type for chunk in valid_chunks)
    one_codes = _report_summarize_type_codes(chunk.one_type for chunk in valid_chunks)
    header_samples = summarize_hex_values((chunk.header_hex for chunk in valid_chunks), limit=6)
    separator_samples = summarize_hex_values(
        (chunk.separator_hex for chunk in valid_chunks),
        fallback="\u672a\u8bc6\u522b",
        limit=6,
    )
    tail_bit_summary = format_consistent_count(
        [sum(field.bit_count for field in chunk.tail_fields) for chunk in valid_chunks],
        "bit",
        "\u65e0",
    )
    mode_items = [item for item in field_inferences if item.meaning == "mode candidate"]
    temp_items = [item for item in field_inferences if item.meaning == "temperature candidate"]
    power_items = [item for item in field_inferences if item.meaning == "power candidate"]
    fixed_items = [
        item for item in field_inferences if item.meaning in {"fixed byte", "fixed field", "frame tag"}
    ][:12]
    unresolved_items = [item for item in field_inferences if item.status != STATUS_CONFIRMED][:12]
    lines: list[str] = [
        f"# {brand_name}\u7a7a\u8c03\u7ea2\u5916\u534f\u8bae\u5206\u6790\u6587\u6863",
        "",
        "## 1. \u534f\u8bae\u6982\u8ff0",
        "",
        (
            f"\u672c\u534f\u8bae\u6587\u6863\u7531\u81ea\u52a8\u5206\u6790\u5de5\u5177\u6839\u636e `{len(commands)}` \u6761 Learn \u62a5\u6587\u751f\u6210\uff0c"
            f"\u7528\u4e8e\u6574\u7406 `{brand_name}` \u7a7a\u8c03\u7ea2\u5916\u62a5\u6587\u7684\u8109\u51b2\u7f16\u7801\u89c4\u5219\u3001"
            "\u6570\u636e\u6bb5\u7ed3\u6784\u4ee5\u53ca\u5b57\u6bb5\u89c2\u5bdf\u7ed3\u8bba\u3002"
        ),
        "",
        "### 1.1 \u8109\u51b2\u7f16\u7801\u89c4\u5219",
        "",
        "| \u903b\u8f91\u503c | \u8109\u51b2\u7f16\u7801\uff08\u5b66\u4e60\u7801\uff09 | \u89c2\u5bdf\u8bf4\u660e |",
        "|---|---|---|",
        f"| `1` | {_report_build_pulse_pattern(mark_codes, one_codes)} | bit 1 \u901a\u5e38\u7531\u540c\u7c7b Mark + \u8f83\u957f Space \u7ec4\u6210 |",
        f"| `0` | {_report_build_pulse_pattern(mark_codes, zero_codes)} | bit 0 \u901a\u5e38\u7531\u540c\u7c7b Mark + \u8f83\u77ed Space \u7ec4\u6210 |",
        "",
        f"- \u89e3\u7801\u8f93\u5165\u6a21\u5f0f\uff1a`{mode_label}`",
        f"- \u53ef\u89e3\u7801\u6709\u6548\u5e27\u6570\uff1a`{len(valid_chunks)}` \u5e27",
        f"- \u6bcf\u6761\u6307\u4ee4\u5e27\u6570\uff1a{format_consistent_count(frame_counts, '帧', '未识别')}",
        f"- \u6bcf\u5e27\u6709\u6548\u8f7d\u8377\uff1a{format_consistent_count(payload_byte_counts, '字节', '未识别')} / {format_consistent_count(payload_bit_counts, 'bit', '未识别')}",
        "- \u5f53\u524d\u89e3\u7801\u5047\u8bbe\u4f4d\u5e8f\uff1a`LSB-first`",
        "",
        "### 1.2 \u62a5\u6587\u7ed3\u6784",
        "",
        "| \u7ec4\u6210\u90e8\u5206 | \u5185\u5bb9 |",
        "|---|---|",
        f"| \u524d\u5bfc\u7801/Header | \u5f53\u524d\u89c2\u5bdf\u5230\u7684 Header \u6837\u672c\uff1a{header_samples} |",
        (
            f"| \u6570\u636e\u6bb5 | \u6bcf\u6761\u6307\u4ee4 {format_consistent_count(frame_counts, '帧', '未识别')}"
            f"\uff0c\u5355\u5e27 payload \u957f\u5ea6\u4e3a {format_consistent_count(payload_byte_counts, '字节', '未识别')}"
            f" / {format_consistent_count(payload_bit_counts, 'bit', '未识别')} |"
        ),
        f"| \u5e27\u95f4\u5206\u9694/\u7ed3\u675f\u6807\u8bb0 | {separator_samples} |",
        f"| \u8865\u4f4d/\u5c3e\u6bb5 | \u89e3\u6790\u524d\u4f1a\u53bb\u6389 `0100` \u7ec8\u6b62\u7b26\u548c\u5c3e\u90e8 `FF` \u586b\u5145\uff1b\u5c3e\u90e8\u989d\u5916 bit \u7ea6\u4e3a {tail_bit_summary} |",
        "",
        "### 1.3 \u8f93\u5165\u6837\u672c",
        "",
        "| \u5206\u7ec4 | \u8bf4\u660e | Learn \u6570\u91cf | \u6765\u6e90\u6587\u4ef6 |",
        "|---|---|---:|---|",
    ]
    for sample in samples:
        source = sample.commands[0].source_file.name if sample.commands else "-"
        lines.append(
            f"| {sample.sample_name} | {escape_pipes(sample.description)} | {len(sample.commands)} | {source} |"
        )
    lines.extend(
        [
            "",
            "## 2. \u6570\u636e\u6bb5\u683c\u5f0f",
            "",
            "\u4ee5\u4e0b\u5185\u5bb9\u6309\u81ea\u52a8\u89e3\u7801\u540e\u7684 payload \u5b57\u8282\u7ed3\u679c\u6574\u7406\uff0c"
            "\u5c3d\u91cf\u4fdd\u6301\u4e0e\u4eba\u5de5\u534f\u8bae\u5206\u6790\u6587\u6863\u63a5\u8fd1\u7684\u8868\u8fbe\u65b9\u5f0f\u3002",
        ]
    )
    if not frame_byte_stats:
        lines.extend(["", "\u5f53\u524d\u6837\u672c\u4e2d\u8fd8\u6ca1\u6709\u7a33\u5b9a\u8bc6\u522b\u51fa\u53ef\u590d\u7528\u7684 payload \u5b57\u8282\u7ed3\u6784\u3002"])
    else:
        for frame_index in sorted(frame_byte_stats):
            lines.extend(
                [
                    "",
                    f"### 2.{frame_index} \u5b66\u4e60\u7801\u5e27{frame_index}\u6570\u636e\u6bb5",
                    "",
                    "| \u504f\u79fb | \u5b57\u6bb5 | \u8bf4\u660e | \u89c2\u6d4b\u503c | \u72b6\u6001 |",
                    "|---|---|---|---|---|",
                ]
            )
            byte_map = frame_byte_stats[frame_index]
            for byte_index in sorted(byte_map):
                values = [field.hex_value for field in byte_map[byte_index]]
                inference = field_inference_map.get(f"chunk{frame_index}.payload{byte_index * 8}")
                meaning = guess_field_label(byte_index, inference, values)
                status = inference.status if inference is not None else STATUS_UNKNOWN
                description = _report_describe_byte_role(byte_index, inference, values)
                lines.append(
                    f"| Byte{byte_index} | {escape_pipes(meaning)} | {escape_pipes(description)} | {summarize_hex_values(values)} | {status} |"
                )
    lines.extend(
        [
            "",
            "### 2.9 \u6837\u672c\u5206\u7ec4\u4ee3\u8868\u62a5\u6587",
            "",
            "| \u5206\u7ec4 | \u4ee3\u8868 Learn | \u8bf4\u660e | \u5e271 payload |",
            "|---|---|---|---|",
        ]
    )
    for sample in samples:
        representative = representatives.get(sample.sample_name)
        if representative is None:
            continue
        frame_hexes = summarize_command_frames(representative)
        lines.append(
            f"| {sample.sample_name} | {representative.learn_key} | {escape_pipes(representative.description)} | `{frame_hexes[0] if frame_hexes else '-'}` |"
        )
    lines.extend(["", "## 3. \u5b57\u6bb5\u8be6\u89e3", ""])
    _report_render_field_focus_table(lines, "### 3.1 \u6a21\u5f0f\u5b57\u6bb5\u5019\u9009", mode_items)
    _report_render_field_focus_table(lines, "### 3.2 \u6e29\u5ea6\u5b57\u6bb5\u5019\u9009", temp_items)
    _report_render_field_focus_table(lines, "### 3.3 \u5f00\u5173/\u72b6\u6001\u5b57\u6bb5\u5019\u9009", power_items)
    _report_render_field_focus_table(lines, "### 3.4 \u5176\u4ed6\u56fa\u5b9a\u5b57\u6bb5", fixed_items)
    lines.extend(
        [
            "",
            "## 4. \u5b66\u4e60\u7801\u6837\u672c\u6570\u636e",
            "",
            "\u6309\u5206\u7ec4\u6574\u7406\u7684 Learn \u6837\u672c payload \u5982\u4e0b\uff0c\u4fbf\u4e8e\u540e\u7eed\u4e0e\u4eba\u5de5\u534f\u8bae\u5206\u6790\u6216\u62a5\u6587\u8bb0\u5f55\u4ea4\u53c9\u5bf9\u7167\u3002",
            "",
            "| \u5206\u7ec4 | Learn | \u8bf4\u660e | Byte0~N |",
            "|---|---|---|---|",
        ]
    )
    for command in commands:
        frame_hexes = summarize_command_frames(command)
        lines.append(
            f"| {command.sample_name} | {command.learn_key} | {escape_pipes(command.description)} | `{frame_hexes[0] if frame_hexes else '-'}` |"
        )
    normalized_rows: list[tuple[str, str, str, str]] = []
    sample_channel_index: defaultdict[str, int] = defaultdict(int)
    for sample in samples:
        for command in sample.commands:
            packet16 = extract_normalized_packet16(command)
            if packet16 is None:
                continue
            sample_channel_index[sample.sample_name] += 1
            normalized_rows.append(
                (
                    sample.sample_name,
                    f"Ch{sample_channel_index[sample.sample_name]}",
                    command.description,
                    format_packet_bytes(packet16),
                )
            )
    if normalized_rows:
        lines.extend(
            [
                "",
                "### 4.2 标准化16字节候选",
                "",
                "以下视图按每字节 bit 反转生成，方便与报文记录或人工整理出的 16 字节协议格式直接对照。",
                "",
                "| 分组 | 通道 | 描述 | Byte0~15 |",
                "|---|---|---|---|",
            ]
        )
        for sample_name, channel_name, description, packet_hex in normalized_rows:
            lines.append(
                f"| {sample_name} | {channel_name} | {escape_pipes(description)} | `{packet_hex}` |"
            )
    if example_command is not None:
        frame_hexes = summarize_command_frames(example_command)
        lines.extend(
            [
                "",
                "### 4.1 \u89e3\u6790\u6837\u4f8b",
                "",
                f"\u4ee5\u4e0b\u6837\u4f8b\u53d6\u81ea `{example_command.learn_key}`\uff0c\u8bf4\u660e\u4e3a\u201c{escape_pipes(example_command.description)}\u201d\u3002",
                "",
                "| \u5e27 | payload \u5b57\u8282 |",
                "|---|---|",
            ]
        )
        for index, frame_hex in enumerate(frame_hexes, start=1):
            lines.append(f"| \u5e27{index} | `{frame_hex}` |")
    lines.extend(
        [
            "",
            "## 5. \u6307\u4ee4\u5bf9\u7167\u8868",
            "",
            "| \u5206\u7ec4 | Learn | \u8bf4\u660e | \u6a21\u5f0f | \u6e29\u5ea6 | \u5e271 | \u5e272 |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for command in commands:
        frame_hexes = summarize_command_frames(command)
        frame1 = frame_hexes[0] if len(frame_hexes) >= 1 else "-"
        frame2 = frame_hexes[1] if len(frame_hexes) >= 2 else "-"
        lines.append(
            f"| {command.sample_name} | {command.learn_key} | {escape_pipes(command.description)} | {format_mode_tag(command)} | {format_temperature_tag(command)} | `{frame1}` | `{frame2}` |"
        )
    lines.extend(["", "## 6. \u603b\u7ed3", "", "### 6.1 \u5df2\u89c2\u5bdf\u5230\u7684\u8f83\u7a33\u5b9a\u90e8\u5206", ""])
    if fixed_items:
        for item in fixed_items:
            lines.append(f"- {item.segment_name}\uff1a{item.meaning}\uff0c{item.evidence}")
    else:
        lines.append("- \u5f53\u524d\u5c1a\u65e0\u8db3\u591f\u7a33\u5b9a\u7684\u56fa\u5b9a\u5b57\u6bb5\u7ed3\u8bba\u3002")
    lines.extend(["", "### 6.2 \u5f85\u8fdb\u4e00\u6b65\u786e\u8ba4\u7684\u90e8\u5206", ""])
    if unresolved_items:
        for item in unresolved_items:
            lines.append(f"- {item.segment_name}\uff1a{item.meaning}\uff0c{item.evidence}")
    else:
        lines.append("- \u5f53\u524d\u672a\u53d1\u73b0\u989d\u5916\u5f85\u786e\u8ba4\u7684\u5b57\u6bb5\u5dee\u5f02\u3002")
    lines.extend(
        [
            "",
            "### 6.3 \u5907\u6ce8",
            "",
            f"- `{STATUS_CONFIRMED}` \u8868\u793a\u5f53\u524d\u6837\u672c\u5df2\u7ecf\u80fd\u7a33\u5b9a\u652f\u6301\u8be5\u7ed3\u8bba\u3002",
            f"- `{STATUS_INFERRED}` \u8868\u793a\u5b57\u6bb5\u53d8\u5316\u548c\u6807\u7b7e\u5173\u7cfb\u660e\u663e\uff0c\u4f46\u8fd8\u9700\u8981\u66f4\u591a\u6837\u672c\u786e\u8ba4\u3002",
            f"- `{STATUS_UNKNOWN}` \u8868\u793a\u5b57\u6bb5\u5b58\u5728\u53d8\u5316\uff0c\u4f46\u73b0\u6709\u8bc1\u636e\u4e0d\u8db3\u4ee5\u5b89\u5168\u547d\u540d\u3002",
            "- \u672c\u6587\u6863\u683c\u5f0f\u5c3d\u91cf\u5bf9\u9f50\u4eba\u5de5\u534f\u8bae\u5206\u6790\u6587\u6863\uff0c\u4f46\u5185\u5bb9\u4ecd\u4ee5\u81ea\u52a8\u89e3\u7801\u7ed3\u679c\u4e3a\u51c6\u3002",
        ]
    )
    lines.extend(f"- {escape_pipes(note)}" for note in notes)
    return "\n".join(lines) + "\n"
def render_tsv(commands: list[CommandSample], field_notes: dict[str, str]) -> str:
    rows = [
        [
            "样本",
            "Learn",
            "段名",
            "原始脉冲",
            "二进制",
            "十六进制",
            "位说明/字段说明",
        ]
    ]
    for command in commands:
        for chunk in command.chunks:
            rows.append(
                [
                    command.sample_name,
                    command.learn_key,
                    f"帧{chunk.index}-头",
                    chunk.header_hex,
                    "",
                    "",
                    "chunk header bytes",
                ]
            )
            for field in chunk.payload_fields:
                rows.append(
                    [
                        command.sample_name,
                        command.learn_key,
                        field.segment_name,
                        field.raw_hex,
                        field.bits,
                        field.hex_value,
                        field_notes.get(field.key, field.note),
                    ]
                )
            for field in chunk.tail_fields:
                rows.append(
                    [
                        command.sample_name,
                        command.learn_key,
                        field.segment_name,
                        field.raw_hex,
                        field.bits,
                        field.hex_value,
                        field.note,
                    ]
                )
            for marker in chunk.markers:
                rows.append(
                    [
                        command.sample_name,
                        command.learn_key,
                        f"帧{chunk.index}-标记",
                        marker.raw_hex,
                        "",
                        "",
                        "special marker or separator",
                    ]
                )
            if chunk.separator_hex:
                rows.append(
                    [
                        command.sample_name,
                        command.learn_key,
                        f"帧{chunk.index}-帧间分隔",
                        chunk.separator_hex,
                        "",
                        "",
                        "between frames",
                    ]
                )
    return "\n".join("\t".join(cell for cell in row) for row in rows) + "\n"
def escape_pipes(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", "<br>")
def _report_group_source_packet_rows(
    source_packet_rows: list[SourcePacketRow] | None,
) -> list[tuple[str, list[SourcePacketRow]]]:
    grouped: dict[str, list[SourcePacketRow]] = {}
    for row in source_packet_rows or []:
        grouped.setdefault(row.source_name, []).append(row)
    grouped_rows: list[tuple[str, list[SourcePacketRow]]] = []
    for source_name, rows in grouped.items():
        grouped_rows.append(
            (
                source_name,
                sorted(rows, key=lambda item: extract_learn_number(item.learn_key) or 0),
            )
        )
    return grouped_rows
def _report_display_source_name(source_name: str) -> str:
    stem, dot, _suffix = source_name.rpartition(".")
    if dot and stem:
        return f"{stem}.ini"
    return source_name
def _normalize_legacy_source_token(token: str) -> str:
    source_name = token.strip()
    if source_name.endswith("\u6587\u4ef6"):
        source_name = source_name[: -len("\u6587\u4ef6")]
    if not source_name.lower().endswith(".txt"):
        source_name = f"{source_name}.txt"
    return source_name
def assess_brand_readiness(
    commands: list[CommandSample],
    field_inferences: list[FieldInference],
    source_packet_rows: list[SourcePacketRow] | None,
) -> dict[str, object]:
    total_commands = len(commands)
    decoded_commands = sum(
        1
        for command in commands
        if any(chunk.payload_bytes for chunk in command.chunks)
    )
    packet16_commands = sum(
        1
        for command in commands
        if extract_preferred_standard_packet16(command) is not None
    )
    confirmed_fields = sum(1 for item in field_inferences if item.status == STATUS_CONFIRMED)
    inferred_fields = sum(1 for item in field_inferences if item.status == STATUS_INFERRED)
    total_fields = len(field_inferences)
    source_known = sum(1 for row in source_packet_rows or [] if row.packet_hex is not None)
    source_total = len(source_packet_rows or [])
    source_inferred = sum(1 for row in source_packet_rows or [] if row.status == STATUS_INFERRED)
    skipped_like = sum(1 for command in commands if not any(chunk.payload_bytes for chunk in command.chunks))
    command_decode_ratio = (decoded_commands / total_commands) if total_commands else 0.0
    packet16_ratio = (packet16_commands / total_commands) if total_commands else 0.0
    field_confirm_ratio = (confirmed_fields / total_fields) if total_fields else 0.0
    source_known_ratio = (source_known / source_total) if source_total else None
    mode_counter = Counter(
        str(command.tags.get("mode"))
        for command in commands
        if command.tags.get("mode") in {"cool", "heat", "off", "auto", "fan", "dry"}
    )
    temperature_values = sorted(
        {
            int(command.tags["temperature"])
            for command in commands
            if isinstance(command.tags.get("temperature"), int)
        }
    )
    has_power_cycle = any(is_power_cycle_command(command) for command in commands)
    if command_decode_ratio >= 0.8 and (packet16_ratio >= 0.5 or field_confirm_ratio >= 0.35):
        readiness = "稳定可解码"
        readiness_note = "当前样本已经足以稳定还原主要帧结构，可直接用于新增品牌的首版协议整理。"
    elif command_decode_ratio >= 0.5:
        readiness = "结构可解析"
        readiness_note = "当前样本已能还原主要帧与部分字段，但还需要更多样本才能稳定命名所有关键位。"
    else:
        readiness = "证据不足"
        readiness_note = "当前样本只能做脉冲结构化整理，还不足以稳定输出协议字段结论。"
    suggestions: list[str] = []
    if len(mode_counter) < 2:
        suggestions.append("补充至少一组制冷和一组制热样本，并在说明中明确对应关系。")
    if len(temperature_values) < 3:
        suggestions.append("补充 3 个以上温度点，便于自动识别温度字段的单调变化。")
    if not has_power_cycle:
        suggestions.append("补充开机、关机或模式切换样本，便于识别电源/状态位。")
    if source_total and source_known_ratio is not None and source_known_ratio < 0.7:
        suggestions.append("检查报文说明中的通道描述是否足够明确，避免出现大量未稳定解出的通道。")
    if packet16_ratio == 0 and command_decode_ratio >= 0.5:
        suggestions.append("当前协议不像海尔这类固定 16 字节结构，后续应重点观察帧长度和校验字段。")
    if skipped_like:
        suggestions.append("确认原始学习码中没有大量空报文、全 FF 报文或无效占位槽位。")
    if not suggestions:
        suggestions.append("当前样本覆盖度较好，可以优先补充边界功能样本，例如风速、扫风或辅热。")
    return {
        "label": readiness,
        "note": readiness_note,
        "command_decode_ratio": command_decode_ratio,
        "packet16_ratio": packet16_ratio,
        "field_confirm_ratio": field_confirm_ratio,
        "source_known_ratio": source_known_ratio,
        "source_inferred": source_inferred,
        "mode_counter": mode_counter,
        "temperature_values": temperature_values,
        "has_power_cycle": has_power_cycle,
        "suggestions": suggestions,
    }
def _iter_legacy_source_segments(text: str) -> Iterable[tuple[str, str]]:
    pattern = re.compile(
        r"(?P<source>[0-9A-Za-z_.\-\u4e00-\u9fff]+(?:\.txt)?(?:\u6587\u4ef6)?)\u4e2d(?P<body>.*?)(?=(?:[0-9A-Za-z_.\-\u4e00-\u9fff]+(?:\.txt)?(?:\u6587\u4ef6)?)\u4e2d|$)",
        re.S,
    )
    for match in pattern.finditer(text):
        yield _normalize_legacy_source_token(match.group("source")), match.group("body")
# Historical implementation kept only as cleanup reference; not used by the tool.
def _deprecated_parse_legacy_description_v2(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    compact = re.sub(r"\s+", "", text)
    compact = (
        compact.replace("\u3001", ",")
        .replace("\uff0c", ",")
        .replace("\uff1b", ",")
        .replace(";", ",")
    )
    clause_pattern = re.compile(
        r"(?P<refs>(?:Learn\d+(?:Code)?)(?:[,](?:Learn)?\d+(?:Code)?)*)"
        r"(?:\u662f|\u4e3a|=|\u4ee3\u8868)"
        r"(?P<desc>.*?)"
        r"(?=(?:[,])?Learn\d+(?:Code)?(?:[,](?:Learn)?\d+(?:Code)?)*(?:\u662f|\u4e3a|=|\u4ee3\u8868)|$)"
    )
    for match in clause_pattern.finditer(compact):
        description = match.group("desc").strip(" ,;\uff0c\uff1b\u3002")
        if not description or re.search(r"\u901a\u9053\d+[:\uff1a]", description):
            continue
        for learn_key in expand_learn_refs(match.group("refs")):
            mapping[learn_key] = description
    for source_name, body in _iter_legacy_source_segments(text):
        anchor = re.search(
            r"Learn(?P<learn>\d+)Code(?:\u4ee3\u8868|\u5bf9\u5e94)\u901a\u9053(?P<channel>\d+)",
            body,
            re.IGNORECASE,
        )
        base_learn = int(anchor.group("learn")) if anchor else 1
        channel_matches = list(
            re.finditer(
                r"\u901a\u9053\s*(?P<channel>\d+)\s*[:\uff1a]\s*(?P<desc>[^,;\uff0c\uff1b\u3002]+)",
                body,
            )
        )
        if not channel_matches:
            continue
        base_channel = int(anchor.group("channel")) if anchor else int(channel_matches[0].group("channel"))
        for channel_match in channel_matches:
            channel_number = int(channel_match.group("channel"))
            description = channel_match.group("desc").strip(" ,;\uff0c\uff1b\u3002")
            if not description:
                continue
            learn_number = base_learn + (channel_number - base_channel)
            mapping[f"{source_name}|Learn{learn_number}Code"] = description
    return mapping
def render_markdown_report(
    brand_name: str,
    mode_label: str,
    samples: list[LoadedSample],
    commands: list[CommandSample],
    notes: list[str],
    field_inferences: list[FieldInference],
    source_packet_rows: list[SourcePacketRow] | None = None,
) -> str:
    valid_chunks = collect_valid_chunks(commands)
    frame_counts = [len(command.chunks) for command in commands]
    payload_byte_counts = [len(chunk.payload_bytes) for chunk in valid_chunks if chunk.payload_bytes]
    payload_bit_counts = [chunk.payload_bit_count for chunk in valid_chunks if chunk.payload_bit_count]
    field_inference_map = {item.field_key: item for item in field_inferences}
    frame_byte_stats = collect_frame_byte_stats(commands)
    example_command = find_example_command(commands)
    representatives = _report_collect_group_representatives(samples)
    mark_codes = _report_summarize_type_codes(chunk.mark_type for chunk in valid_chunks)
    zero_codes = _report_summarize_type_codes(chunk.zero_type for chunk in valid_chunks)
    one_codes = _report_summarize_type_codes(chunk.one_type for chunk in valid_chunks)
    header_samples = summarize_hex_values((chunk.header_hex for chunk in valid_chunks), limit=6)
    separator_samples = summarize_hex_values(
        (chunk.separator_hex for chunk in valid_chunks),
        fallback="未识别",
        limit=6,
    )
    tail_bit_summary = format_consistent_count(
        [sum(field.bit_count for field in chunk.tail_fields) for chunk in valid_chunks],
        "bit",
        "无",
    )
    mode_items = [item for item in field_inferences if item.meaning == "mode candidate"]
    temp_items = [item for item in field_inferences if item.meaning == "temperature candidate"]
    power_items = [item for item in field_inferences if item.meaning == "power candidate"]
    fixed_items = [
        item for item in field_inferences if item.meaning in {"fixed byte", "fixed field", "frame tag"}
    ][:12]
    unresolved_items = [item for item in field_inferences if item.status != STATUS_CONFIRMED][:12]
    grouped_source_rows = _report_group_source_packet_rows(source_packet_rows)
    readiness = assess_brand_readiness(commands, field_inferences, source_packet_rows)
    mode_summary = (
        ", ".join(f"{mode}:{count}" for mode, count in readiness["mode_counter"].items())
        if readiness["mode_counter"]
        else "未识别"
    )
    temperature_summary = (
        ", ".join(str(value) for value in readiness["temperature_values"])
        if readiness["temperature_values"]
        else "未识别"
    )
    source_known_summary = (
        f"{readiness['source_known_ratio']:.0%}"
        if readiness["source_known_ratio"] is not None
        else "不适用"
    )
    lines: list[str] = [
        f"# {brand_name}空调红外协议分析文档",
        "",
        "## 1. 协议概述",
        "",
        (
            f"本文档由自动分析工具根据 `{len(commands)}` 条 Learn 报文生成，"
            f"用于整理 `{brand_name}` 空调红外报文的脉冲编码规则、数据段结构以及字段观察结论。"
        ),
        "",
        "### 1.1 脉冲编码规则",
        "",
        "| 逻辑值 | 脉冲编码（学习码） | 观察说明 |",
        "|---|---|---|",
        f"| `1` | {_report_build_pulse_pattern(mark_codes, one_codes)} | bit 1 通常由同类 Mark + 较长 Space 组成 |",
        f"| `0` | {_report_build_pulse_pattern(mark_codes, zero_codes)} | bit 0 通常由同类 Mark + 较短 Space 组成 |",
        "",
        f"- 解码输入模式：`{mode_label}`",
        f"- 可解码有效帧数：`{len(valid_chunks)}` 帧",
        f"- 每条指令帧数：{format_consistent_count(frame_counts, '帧', '未识别')}",
        f"- 每帧有效载荷：{format_consistent_count(payload_byte_counts, '字节', '未识别')} / {format_consistent_count(payload_bit_counts, 'bit', '未识别')}",
        "- 当前解码假设位序：`LSB-first`",
        "",
        "### 1.2 报文结构",
        "",
        "| 组成部分 | 内容 |",
        "|---|---|",
        f"| 前导码/Header | 当前观察到的 Header 样本：{header_samples} |",
        (
            f"| 数据段 | 每条指令 {format_consistent_count(frame_counts, '帧', '未识别')}，"
            f"单帧 payload 长度为 {format_consistent_count(payload_byte_counts, '字节', '未识别')}"
            f" / {format_consistent_count(payload_bit_counts, 'bit', '未识别')} |"
        ),
        f"| 帧间分隔/结束标记 | {separator_samples} |",
        f"| 补位/尾段 | 解析前会去掉 `0100` 终止符和尾部 `FF` 填充；尾部额外 bit 约为 {tail_bit_summary} |",
        "",
        "### 1.3 新品牌接入自检",
        "",
        f"- 当前判定：`{readiness['label']}`",
        f"- 判定说明：{readiness['note']}",
        f"- 指令可解码率：`{readiness['command_decode_ratio']:.0%}`",
        f"- 标准化结构覆盖率：`{readiness['packet16_ratio']:.0%}`",
        f"- 字段已确认比例：`{readiness['field_confirm_ratio']:.0%}`",
        f"- 原始文件通道可还原率：`{source_known_summary}`",
        f"- 已覆盖模式：{mode_summary}",
        f"- 已覆盖温度点：{temperature_summary}",
        f"- 是否包含开关机场景：{'是' if readiness['has_power_cycle'] else '否'}",
        "",
        "建议：",
    ]
    lines.extend(f"- {item}" for item in readiness["suggestions"])
    lines.extend(
        [
            "",
            "### 1.4 输入样本",
            "",
            "| 分组 | 说明 | Learn 数量 | 来源文件 |",
            "|---|---|---:|---|",
        ]
    )
    for sample in samples:
        source = sample.commands[0].source_file.name if sample.commands else "-"
        lines.append(
            f"| {sample.sample_name} | {escape_pipes(sample.description)} | {len(sample.commands)} | {source} |"
        )
    lines.extend(
        [
            "",
            "## 2. 数据段格式",
            "",
            "以下内容按自动解码后的 payload 字节结果整理，尽量保持与人工协议分析文档接近的表达方式。",
        ]
    )
    if not frame_byte_stats:
        lines.extend(["", "当前样本中还没有稳定识别出可复用的 payload 字节结构。"])
    else:
        for frame_index in sorted(frame_byte_stats):
            lines.extend(
                [
                    "",
                    f"### 2.{frame_index} 学习码帧{frame_index}数据段",
                    "",
                    "| 偏移 | 字段 | 说明 | 观测值 | 状态 |",
                    "|---|---|---|---|---|",
                ]
            )
            byte_map = frame_byte_stats[frame_index]
            for byte_index in sorted(byte_map):
                values = [field.hex_value for field in byte_map[byte_index]]
                inference = field_inference_map.get(f"chunk{frame_index}.payload{byte_index * 8}")
                meaning = guess_field_label(byte_index, inference, values)
                status = inference.status if inference is not None else STATUS_UNKNOWN
                description = _report_describe_byte_role(byte_index, inference, values)
                lines.append(
                    f"| Byte{byte_index} | {escape_pipes(meaning)} | {escape_pipes(description)} | {summarize_hex_values(values)} | {status} |"
                )
    lines.extend(
        [
            "",
            "### 2.9 样本分组代表报文",
            "",
            "| 分组 | 代表 Learn | 说明 | 帧1 payload |",
            "|---|---|---|---|",
        ]
    )
    for sample in samples:
        representative = representatives.get(sample.sample_name)
        if representative is None:
            continue
        frame_hexes = summarize_command_frames(representative)
        lines.append(
            f"| {sample.sample_name} | {representative.learn_key} | {escape_pipes(representative.description)} | `{frame_hexes[0] if frame_hexes else '-'}` |"
        )
    lines.extend(["", "## 3. 字段详解", ""])
    _report_render_field_focus_table(lines, "### 3.1 模式字段候选", mode_items)
    _report_render_field_focus_table(lines, "### 3.2 温度字段候选", temp_items)
    _report_render_field_focus_table(lines, "### 3.3 开关/状态字段候选", power_items)
    _report_render_field_focus_table(lines, "### 3.4 其他固定字段", fixed_items)
    lines.extend(
        [
            "",
            "## 4. 学习码样本数据",
            "",
            "本节优先按原始报文文件整理标准化 16 字节候选，使自动生成的协议文档更接近人工分析文档的通道展示方式。",
            "",
            "### 4.1 按原始文件整理的 16 字节候选",
        ]
    )
    if grouped_source_rows:
        for section_index, (source_name, rows) in enumerate(grouped_source_rows, start=1):
            display_source_name = _report_display_source_name(source_name)
            lines.extend(
                [
                    "",
                    f"#### 4.1.{section_index} {display_source_name} ({len(rows)}通道)",
                    "",
                    "| 通道 | Learn | 描述 | Byte0~15 | 状态 |",
                    "|---|---|---|---|---|",
                ]
            )
            for row in rows:
                packet_text = f"`{row.packet_hex}`" if row.packet_hex is not None else "未稳定解出"
                lines.append(
                    f"| {row.channel_name} | {row.learn_key} | {escape_pipes(row.description)} | {packet_text} | {row.status} |"
                )
    else:
        lines.extend(["", "当前没有可用的按文件 16 字节标准化视图。"])
    lines.extend(
        [
            "",
            "### 4.2 自动解码 payload 摘要",
            "",
            "| 分组 | Learn | 说明 | Byte0~N |",
            "|---|---|---|---|",
        ]
    )
    for command in commands:
        frame_hexes = summarize_command_frames(command)
        lines.append(
            f"| {command.sample_name} | {command.learn_key} | {escape_pipes(command.description)} | `{frame_hexes[0] if frame_hexes else '-'}` |"
        )
    if example_command is not None:
        frame_hexes = summarize_command_frames(example_command)
        lines.extend(
            [
                "",
                "### 4.3 解析样例",
                "",
                f"以下样例取自 `{example_command.learn_key}`，说明为“{escape_pipes(example_command.description)}”。",
                "",
                "| 帧 | payload 字节 |",
                "|---|---|",
            ]
        )
        for index, frame_hex in enumerate(frame_hexes, start=1):
            lines.append(f"| 帧{index} | `{frame_hex}` |")
    lines.extend(
        [
            "",
            "## 5. 指令对照表",
            "",
            "| 分组 | Learn | 说明 | 模式 | 温度 | 标准化16字节 | 帧1 | 帧2 |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for command in commands:
        frame_hexes = summarize_command_frames(command)
        frame1 = frame_hexes[0] if len(frame_hexes) >= 1 else "-"
        frame2 = frame_hexes[1] if len(frame_hexes) >= 2 else "-"
        packet16 = format_preferred_packet16_tag(command)
        lines.append(
            f"| {command.sample_name} | {command.learn_key} | {escape_pipes(command.description)} | {format_mode_tag(command)} | {format_temperature_tag(command)} | `{packet16}` | `{frame1}` | `{frame2}` |"
        )
    lines.extend(["", "## 6. 总结", "", "### 6.1 已观察到的较稳定部分", ""])
    if fixed_items:
        for item in fixed_items:
            lines.append(f"- {item.segment_name}：{item.meaning}，{item.evidence}")
    else:
        lines.append("- 当前尚无足够稳定的固定字段结论。")
    lines.extend(["", "### 6.2 待进一步确认的部分", ""])
    if unresolved_items:
        for item in unresolved_items:
            lines.append(f"- {item.segment_name}：{item.meaning}，{item.evidence}")
    else:
        lines.append("- 当前未发现额外待确认的字段差异。")
    lines.extend(
        [
            "",
            "### 6.3 备注",
            "",
            f"- `{STATUS_CONFIRMED}` 表示当前样本已经能稳定支持该结论。",
            f"- `{STATUS_INFERRED}` 表示字段变化和标签关系明显，但还需要更多样本确认。",
            f"- `{STATUS_UNKNOWN}` 表示字段存在变化，但现有证据不足以安全命名。",
            "- 本文档格式尽量对齐人工协议分析文档，但内容仍以自动解码结果为准。",
        ]
    )
    lines.extend(f"- {escape_pipes(note)}" for note in notes)
    return "\n".join(lines) + "\n"
