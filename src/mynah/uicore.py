"""UI-toolkit-agnostic core shared by the web UI and the legacy Tk GUI.

Everything here used to live in gui.py. It was extracted so the pywebview
frontend (backend.py / webui.py) can reuse the exact same scrubbing,
settings-transaction, consent-attestation, and recordings-indexing logic
without importing tkinter. gui.py re-exports these names so existing
imports (and tests) keep working unchanged.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, Optional

from . import secrets_store
from .config import AUTH_MODE_OWN_APP, AUTH_MODE_STREAMKIT, Config

# User-facing labels for the Discord identity selector, shared by the
# WebView2 settings panel (backend.get_settings options) and the legacy
# Tk dialog. Ordered: the recommended choice first.
_AUTH_MODE_LABELS = {
    AUTH_MODE_STREAMKIT: "Discord StreamKit identity (no app needed, recommended)",
    AUTH_MODE_OWN_APP: "My own Discord application (Client ID + Secret)",
}

log = logging.getLogger(__name__)


# Strip ASCII control chars (except tab) and a small set of Unicode
# directional-override characters from any string that gets routed through
# the log pane or status labels. Discord display names and meeting names
# can contain these and would otherwise let a malicious participant inject
# fake log lines or visually mask paths.
#
# Built from codepoint ranges (not literal characters) so this file stays
# pure ASCII — several of these codepoints are invisible or are treated as
# line terminators by editors, which makes a literal character class easy
# to corrupt silently.
_BAD_CODEPOINT_RANGES = [
    (0x0000, 0x0008),  # ASCII control chars (kept: tab 0x09, newline 0x0a)
    (0x000B, 0x001F),  # remaining ASCII control chars
    (0x007F, 0x007F),  # DEL
    (0x0080, 0x009F),  # C1 controls (NEL, etc.)
    (0x200B, 0x200D),  # zero-width space/non-joiner/joiner
    (0x200E, 0x200F),  # LRM, RLM
    (0x2028, 0x2029),  # LINE/PARAGRAPH SEPARATOR (Tk renders as newline)
    (0x202A, 0x202E),  # LRE, RLE, PDF, LRO, RLO
    (0x2060, 0x2060),  # WORD JOINER
    (0x2066, 0x2069),  # LRI, RLI, FSI, PDI
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
]
_BAD_LOG_CHARS = re.compile(
    "["
    + "".join(
        re.escape(chr(lo)) if lo == hi else re.escape(chr(lo)) + "-" + re.escape(chr(hi))
        for lo, hi in _BAD_CODEPOINT_RANGES
    )
    + "]"
)


def _scrub(s: str) -> str:
    """Make a string safe to render in the log pane without log spoofing."""
    if not isinstance(s, str):
        s = str(s)
    return _BAD_LOG_CHARS.sub("?", s).replace("\r", " ").replace("\n", " ")


def scrub_multiline(s: str) -> str:
    """Like _scrub but preserves newlines — for multi-line remote text
    (release notes) rendered via textContent in the web UI.

    CR is normalised BEFORE the character-class pass: it sits inside the
    scrubbed 0x0B-0x1F range, so scrubbing first would turn every CRLF
    line ending into a stray '?'.
    """
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return _BAD_LOG_CHARS.sub("?", s)


_CONSENT_FIELD_MAX = 256


def _capped(value: object) -> Optional[str]:
    """Length-cap an identity field before it lands in participants.json.

    Returns None unchanged so the absence-vs-empty distinction the
    consent audit trail relies on is preserved. Non-string truthy
    values are coerced to str first because the Discord RPC identity
    payload is contract-defined as a dict of strings, but a future
    schema bump could deliver an int snowflake.

    also strips bidi-override, zero-width, and
    control characters via `_scrub()` BEFORE capping. Without that, a
    malicious Discord display name containing U+202E (right-to-left
    override) or similar would land in `participants.json` and the
    consent log line, corrupting the audit trail and enabling log
    spoofing. Scrubbing first means the 256-char cap applies to the
    post-scrub length, matching the displayed/logged form.
    """
    if value is None:
        return None
    s = value if isinstance(value, str) else str(value)
    return _scrub(s)[:_CONSENT_FIELD_MAX]


def apply_settings_atomically(c: Config, new_values: dict):
    """Apply new Settings values to `c` atomically with respect to
    SecretWriteError.

    extracted from `SettingsDialog._save` so the
    rollback semantics are unit-testable without instantiating a Tk
    Toplevel. The contract is:

    - Snapshot the prior secret state (client secret, token, hf_token).
    - Attempt the secret writes in this order: token (cleared if the
      Discord credentials changed — the cached OAuth token belongs to the old
      application), client secret, hf_token. If any raises SecretWriteError, roll
      back the writes that already committed (best-effort: a rollback
      that itself raises is swallowed and logged) and return the
      original exception.
    - Only after all secret writes succeed, mutate the non-secret
      fields (client_id, whisper_model, audio_source, recordings_dir).
    - Returns None on success, the SecretWriteError instance on
      secret-write failure. The caller handles the persistence
      `c.save()` call and any UI dialogs.

    The previous (non-extracted) flow mutated `discord_client_id` and
    cleared the token BEFORE the secret writes that might fail, so a
    partial failure left the dialog telling the user "Settings were
    NOT saved" while the in-memory config carried the new client_id,
    a deleted token, and a half-applied keyring state.

    """
    new_client_id = new_values["discord_client_id"]
    new_client_secret = new_values["discord_client_secret"]
    new_hf_token = new_values["hf_token"]
    orig_client_secret = c.discord_client_secret
    # The auth mode decides which Discord application the cached OAuth
    # token belongs to, so a mode switch invalidates the token exactly
    # like a Client ID change does. Callers that predate the setting
    # (and the fake configs in tests) may omit it: treat as unchanged.
    orig_auth_mode = getattr(c, "discord_auth_mode", None)
    new_auth_mode = new_values.get("discord_auth_mode", orig_auth_mode)
    credentials_changed = (
        new_client_id != c.discord_client_id
        or new_client_secret != orig_client_secret
        or new_auth_mode != orig_auth_mode
    )
    orig_hf_token = c.hf_token
    orig_token = c.token
    secret_writes_committed: list[str] = []
    try:
        if credentials_changed:
            c.token = None
            secret_writes_committed.append("token")
        c.discord_client_secret = new_client_secret
        secret_writes_committed.append("client_secret")
        c.hf_token = new_hf_token
        secret_writes_committed.append("hf_token")
    except secrets_store.SecretWriteError as e:
        for kind in reversed(secret_writes_committed):
            try:
                if kind == "hf_token":
                    c.hf_token = orig_hf_token
                elif kind == "client_secret":
                    c.discord_client_secret = orig_client_secret
                elif kind == "token" and orig_token is not None:
                    c.token = orig_token
            except secrets_store.SecretWriteError as rollback_err:
                # the docstring promises
                # "swallowed and logged"; previously this was silently
                # swallowed without a log entry, leaving operators with
                # no breadcrumb to diagnose a double-failure (primary
                # write fails, rollback also fails). Matches the
                # logging pattern at config.py's migration rollback.
                log.warning(
                    "apply_settings_atomically: rollback of %s failed "
                    "(%s); credential store may be in an inconsistent "
                    "state — manual cleanup via OS credential manager "
                    "may be required.",
                    kind,
                    rollback_err,
                )
        return e
    c.discord_client_id = new_client_id
    if new_auth_mode is not None:
        c.discord_auth_mode = new_auth_mode
    c.whisper_model = new_values["whisper_model"]
    c.audio_source = new_values["audio_source"]
    c.recordings_dir = new_values["recordings_dir"]
    c.loopback_device_name = new_values.get("loopback_device_name", "")
    # Optional so the legacy Tk dialog (which has no toggle) and config
    # doubles in tests keep the existing value untouched.
    c.check_updates = bool(
        new_values.get("check_updates", getattr(c, "check_updates", True))
    )
    return None


CONSENT_DIALOG_TEXT = (
    "This will record audio of every participant in the current "
    "voice channel — your microphone AND Discord's system audio "
    "(everyone else you can hear).\n\n"
    "The recording is saved locally on this computer and is NOT "
    "uploaded anywhere. You are responsible for obtaining consent "
    "from the other participants before recording.\n\n"
    "Continue?"
)
# when the dialog text is reworded, bump
# `CONSENT_DIALOG_VERSION` so older participants.json entries
# remain unambiguously identifiable. The text-sha256 lets an
# auditor verify, byte-for-byte, that a recording's consent record
# references the exact dialog version that was shown at the time —
# the `dialog_text` field alone could be silently rewritten by a
# tool walking participants.json across versions.
CONSENT_DIALOG_VERSION = "v1"
CONSENT_DIALOG_SHA256 = hashlib.sha256(
    CONSENT_DIALOG_TEXT.encode("utf-8"),
).hexdigest()


def build_consent_record(identity: Optional[dict]) -> dict:
    """Build the consent attestation persisted into participants.json.

    Called by whichever UI showed the consent dialog, AFTER the user
    accepted. Length-caps identity fields before persistence: a Discord
    display name is user-controlled and reaches us via the RPC IPC
    channel. The legitimate values are tiny (snowflake IDs are ~20
    digits; usernames cap at 32 chars per Discord's own limit) so 256
    is a comfortable upper bound. Without this cap, a participant who
    chose a multi-megabyte display name would silently inflate every
    participants.json on disk.
    """
    identity = identity or {}
    granted_by_user_id = _capped(identity.get("id"))
    granted_by_username = _capped(
        identity.get("global_name") or identity.get("username")
    )
    record = {
        "granted_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds",
        ),
        "granted_by_user_id": granted_by_user_id,
        "granted_by_username": granted_by_username,
        "dialog_text": CONSENT_DIALOG_TEXT,
        "dialog_version": CONSENT_DIALOG_VERSION,
        "dialog_sha256": CONSENT_DIALOG_SHA256,
    }
    log.info(
        "Recording consent granted by %s (%s)",
        record["granted_by_username"], record["granted_by_user_id"],
    )
    return record


# ---- recording layout --------------------------------------------------------
# Every recording lives in its own folder under the recordings root:
#
#   Recordings/<meeting>_discord_YYYYMMDD_HHMMSS/
#       audio.wav           channel-split capture
#       participants.json   roster, join/leave + speaking-event timeline
#       transcript.txt      written by Transcribe
#       mapping.json        written only when speakers could not be auto-mapped
#
# Recordings made before this layout are flat files side by side in the
# root (`<base>_audio.wav`, `<base>_participants.json`,
# `<base>_audio_transcript.txt`, `<base>_audio_mapping.json`). They stay
# listed and transcribable in place; renaming one moves it into a folder.

AUDIO_FILENAME = "audio.wav"
PARTICIPANTS_FILENAME = "participants.json"
TRANSCRIPT_FILENAME = "transcript.txt"
MAPPING_FILENAME = "mapping.json"

_LEGACY_AUDIO_SUFFIX = "_audio.wav"
# "<meeting>_discord_YYYYMMDD_HHMMSS" or "discord_YYYYMMDD_HHMMSS", optionally
# followed by " [<server> - <channel>]" — the where-it-happened context the
# recorder appends automatically. The context sits AFTER the timestamp in a
# bracketed block so the user-editable meeting part stays unambiguous.
_RECORDING_BASE_RE = re.compile(
    r"^(?:(?P<meeting>.+)_)?discord_(?P<ts>\d{8}_\d{6})(?: \[(?P<context>[^\[\]]+)\])?$"
)
# Context parts may not contain the brackets that delimit the block.
_CONTEXT_SAFE = re.compile(r"[A-Za-z0-9 _\-.()&',!]")
_CONTEXT_PART_MAX = 40

# Discord channel types relevant to voice (see Discord's channel object).
CHANNEL_TYPE_DM = 1
CHANNEL_TYPE_GROUP_DM = 3

# Names this could legitimately produce a Windows path-safe filename
# component from. Anything outside this set is collapsed to '_'. We also
# reject the small set of Windows reserved device names case-insensitively.
_FILENAME_SAFE = re.compile(r"[A-Za-z0-9 _\-.()\[\]]")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _sanitize_meeting_name(raw: Optional[str]) -> Optional[str]:
    """Coerce a free-text meeting name into a Windows-safe filename component.

    - Drops every character that is not in a small allow-list (letters,
      digits, space, `_`, `-`, `.`, parens, square brackets).
    - Collapses runs of whitespace/underscores.
    - Strips leading/trailing whitespace, dots, and underscores (Explorer
      treats trailing dots/spaces specially on Windows).
    - Rejects Windows reserved device names (CON, NUL, COM1, LPT1, …) by
      returning None so the recorder falls back to the unprefixed default.
    - Caps at 64 chars to leave room for the timestamp suffix.

    Without this, `meeting_name = "../../evil"` from the GUI would let an
    attacker (or an unlucky paste) steer the recording folder outside the
    configured recordings directory.
    """
    if not raw:
        return None
    cleaned_chars = [c if _FILENAME_SAFE.match(c) else "_" for c in raw]
    cleaned = "".join(cleaned_chars)
    # Collapse runs of "_" / whitespace introduced by the substitution.
    cleaned = re.sub(r"[_\s]+", "_", cleaned).strip("._ ")
    cleaned = cleaned[:64].strip("._ ")
    if not cleaned:
        return None
    # Windows treats reserved device basenames specially EVEN WITH
    # extensions: "CON.txt", "NUL.log", "COM1.tar.gz" all refer to the
    # device, not a file. Check the stem before the first dot, not the
    # whole cleaned string, against the reserved set.
    head = cleaned.split(".", 1)[0]
    if head.upper() in _WINDOWS_RESERVED:
        return None
    return cleaned


def _clean_context_part(raw: object, limit: int = _CONTEXT_PART_MAX) -> str:
    """Server / channel names are user-controlled Discord strings. Keep a
    conservative character set (no brackets, no path separators), collapse
    whitespace, and cap the length so the folder name stays reasonable."""
    if not raw:
        return ""
    cleaned = "".join(c if _CONTEXT_SAFE.match(c) else " " for c in str(raw))
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" ._")
    return cleaned[:limit].strip(" ._")


def recording_context(
    guild_name: Optional[str],
    channel_name: Optional[str],
    channel_type: Optional[int] = None,
) -> Optional[str]:
    """The " [...]" block content describing where a call happened.

      server voice channel  -> "<server> - <channel>"
      direct call           -> "DM"
      group call            -> "Group DM - <name>" (or just "Group DM")

    None when nothing usable is known, so the folder name stays bare.
    """
    if channel_type == CHANNEL_TYPE_DM:
        return "DM"
    channel = _clean_context_part(channel_name)
    if channel_type == CHANNEL_TYPE_GROUP_DM:
        return f"Group DM - {channel}" if channel else "Group DM"
    server = _clean_context_part(guild_name)
    parts = [p for p in (server, channel) if p]
    return " - ".join(parts) or None


def recording_base_name(
    meeting: Optional[str], ts: str, context: Optional[str] = None
) -> str:
    """Folder name for a session: `[<meeting>_]discord_<ts>[ [<context>]]`."""
    base = f"{meeting}_discord_{ts}" if meeting else f"discord_{ts}"
    if context:
        base += f" [{context}]"
    return base


class ParsedRecordingName(NamedTuple):
    meeting: Optional[str]
    ts: str
    context: Optional[str]


def parse_recording_base(base: str) -> ParsedRecordingName:
    """Split a base name into (meeting or None, timestamp or "", context or None).

    Unrecognised names come back as (base, "", None) so they still get a label.
    """
    m = _RECORDING_BASE_RE.match(base)
    if not m:
        return ParsedRecordingName(base or None, "", None)
    return ParsedRecordingName(m.group("meeting"), m.group("ts"), m.group("context"))


def is_folder_layout(audio_path: Path) -> bool:
    return Path(audio_path).name == AUDIO_FILENAME


def recording_base(audio_path: Path) -> str:
    """The session's base name: the folder name in the folder layout, the
    `_audio.wav`-stripped stem for a legacy flat recording."""
    audio_path = Path(audio_path)
    if is_folder_layout(audio_path):
        return audio_path.parent.name
    stem = audio_path.stem
    if stem.endswith("_audio"):
        stem = stem[: -len("_audio")]
    return stem


@dataclass(frozen=True)
class RecordingFiles:
    audio: Path
    participants: Path
    transcript: Path
    mapping: Path
    # The recording's own folder; None for a legacy flat recording.
    folder: Optional[Path]


def recording_files(audio_path: Path) -> RecordingFiles:
    """Resolve every file that belongs to the recording `audio_path` is
    part of, in whichever layout it uses."""
    audio_path = Path(audio_path)
    parent = audio_path.parent
    if is_folder_layout(audio_path):
        return RecordingFiles(
            audio=audio_path,
            participants=parent / PARTICIPANTS_FILENAME,
            transcript=parent / TRANSCRIPT_FILENAME,
            mapping=parent / MAPPING_FILENAME,
            folder=parent,
        )
    base = recording_base(audio_path)
    return RecordingFiles(
        audio=audio_path,
        participants=parent / f"{base}_participants.json",
        transcript=parent / f"{audio_path.stem}_transcript.txt",
        mapping=parent / f"{audio_path.stem}_mapping.json",
        folder=None,
    )


def recording_display_parts(audio_path: Path) -> tuple[str, str, str]:
    """(meeting name or "Untitled", pretty timestamp, context or "") for UI rows."""
    meeting, ts_str, context = parse_recording_base(recording_base(audio_path))
    if len(ts_str) == 15 and ts_str[8] == "_" and ts_str[:8].isdigit():
        ts_pretty = f"{ts_str[:4]}-{ts_str[4:6]}-{ts_str[6:8]} {ts_str[9:11]}:{ts_str[11:13]}"
    else:
        ts_pretty = ts_str or "?"
    return _scrub(meeting or "Untitled"), ts_pretty, _scrub(context or "")


def format_recording_label(path: Path) -> str:
    """Build a human-friendly display string for a recording.

    Examples of the underlying name (folder, or legacy flat WAV):
      MEP Landing Page Call_discord_20260528_003930 [Eunify - general]/audio.wav
      discord_20260525_210051_audio.wav  (no meeting name, legacy)

    Result: "MEP Landing Page Call  --  2026-05-28 00:39  ·  Eunify - general"
    """
    meeting, ts_pretty, context = recording_display_parts(path)
    sep = "—"  # em dash, matching the original Tk label format
    label = f"{meeting}  {sep}  {ts_pretty}"
    if context:
        label += f"  ·  {context}"
    return label


def rename_recording(audio_path: Path, new_name: str, recordings_root: Path) -> Path:
    """Rename the recording `audio_path` belongs to and return its new
    audio path.

    Only the meeting part of `<meeting>_discord_<ts>` changes; the
    timestamp is kept so ordering and the date column stay put. The new
    name goes through the same sanitiser as names typed before a
    recording, so it cannot escape the recordings folder. An empty or
    all-unsafe name drops the meeting part (`discord_<ts>`).

    Folder-layout recordings are a single directory rename. Legacy flat
    recordings are moved into a new folder with the standard file names;
    a failure mid-move is rolled back so no file is left behind alone.

    Raises ValueError for unrecognised names or paths outside the root,
    FileExistsError when the target name is taken, and OSError for
    filesystem failures (e.g. a file still open on Windows).
    """
    root = Path(recordings_root).resolve()
    audio_path = Path(audio_path)
    resolved = audio_path.resolve()
    if root not in resolved.parents:
        raise ValueError("Recording is outside the recordings folder.")
    old_base = recording_base(audio_path)
    parsed = parse_recording_base(old_base)
    if not parsed.ts:
        raise ValueError(
            "This recording's name is not in Mynah's format; rename its "
            "folder in the file manager instead."
        )
    # Only the meeting part is the user's to edit; the timestamp and the
    # server/channel context are facts about the call and travel along.
    new_base = recording_base_name(
        _sanitize_meeting_name(new_name), parsed.ts, parsed.context
    )
    if new_base == old_base:
        return audio_path
    target = root / new_base
    if target.exists():
        raise FileExistsError(f"A recording named \"{new_base}\" already exists.")

    files = recording_files(audio_path)
    if files.folder is not None:
        files.folder.rename(target)
        return target / AUDIO_FILENAME

    # Legacy flat layout: gather the set into a folder.
    target.mkdir()
    moves = [
        (files.audio, target / AUDIO_FILENAME),
        (files.participants, target / PARTICIPANTS_FILENAME),
        (files.transcript, target / TRANSCRIPT_FILENAME),
        (files.mapping, target / MAPPING_FILENAME),
    ]
    done: list[tuple[Path, Path]] = []
    try:
        for src, dst in moves:
            if src.exists():
                src.rename(dst)
                done.append((src, dst))
    except OSError:
        for src, dst in reversed(done):
            try:
                dst.rename(src)
            except OSError as rollback_err:
                log.warning(
                    "rename_recording: rollback of %s failed (%s)", dst, rollback_err
                )
        try:
            target.rmdir()
        except OSError:
            pass
        raise
    return target / AUDIO_FILENAME


def index_recordings(recordings_path: Path) -> list[tuple[str, Path]]:
    """Scan the recordings folder and return (label, path) pairs, newest
    first, with display labels de-duplicated.

    Both layouts are scanned: one folder per recording (`<base>/audio.wav`)
    and legacy flat files (`<base>_audio.wav`) in the root. Only entries
    that have their participants.json are returned -- otherwise
    transcription would immediately fail.
    """
    valid: list[Path] = []
    try:
        for entry in Path(recordings_path).iterdir():
            if entry.is_dir():
                audio = entry / AUDIO_FILENAME
                if audio.is_file() and (entry / PARTICIPANTS_FILENAME).is_file():
                    valid.append(audio)
            elif entry.is_file() and entry.name.endswith(_LEGACY_AUDIO_SUFFIX):
                if recording_files(entry).participants.is_file():
                    valid.append(entry)
    except OSError as e:
        log.warning("Could not list recordings: %s", e)

    def _mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0

    valid.sort(key=_mtime, reverse=True)

    out: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for p in valid:
        label = format_recording_label(p)
        # Disambiguate if two recordings somehow render to the same label
        base = label
        i = 2
        while label in seen:
            label = f"{base} ({i})"
            i += 1
        seen.add(label)
        out.append((label, p))
    return out
