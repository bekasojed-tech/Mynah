"""Tests for the per-recording folder layout and the rename helper."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mynah import uicore
from mynah.uicore import (
    AUDIO_FILENAME,
    CHANNEL_TYPE_DM,
    CHANNEL_TYPE_GROUP_DM,
    MAPPING_FILENAME,
    PARTICIPANTS_FILENAME,
    TRANSCRIPT_FILENAME,
    format_recording_label,
    index_recordings,
    parse_recording_base,
    recording_base,
    recording_base_name,
    recording_context,
    recording_display_parts,
    recording_files,
    rename_recording,
)


def _make_folder_recording(root: Path, base: str, *, transcript: bool = False) -> Path:
    d = root / base
    d.mkdir()
    (d / AUDIO_FILENAME).write_bytes(b"RIFF")
    (d / PARTICIPANTS_FILENAME).write_text(json.dumps({"initial_participants": []}))
    if transcript:
        (d / TRANSCRIPT_FILENAME).write_text("Participants: a\n")
    return d / AUDIO_FILENAME


def _make_legacy_recording(root: Path, base: str, *, transcript: bool = False) -> Path:
    audio = root / f"{base}_audio.wav"
    audio.write_bytes(b"RIFF")
    (root / f"{base}_participants.json").write_text("{}")
    if transcript:
        (root / f"{base}_audio_transcript.txt").write_text("t")
    return audio


class TestNames:
    def test_base_name_with_and_without_meeting(self):
        assert recording_base_name("Standup", "20260102_030405") == "Standup_discord_20260102_030405"
        assert recording_base_name(None, "20260102_030405") == "discord_20260102_030405"

    def test_base_name_with_context(self):
        assert (
            recording_base_name("Standup", "20260102_030405", "Eunify - general")
            == "Standup_discord_20260102_030405 [Eunify - general]"
        )
        assert (
            recording_base_name(None, "20260102_030405", "DM")
            == "discord_20260102_030405 [DM]"
        )

    def test_parse_round_trips(self):
        assert parse_recording_base("Standup_discord_20260102_030405") == (
            "Standup", "20260102_030405", None
        )
        assert parse_recording_base("discord_20260102_030405") == (None, "20260102_030405", None)
        # Meeting names may themselves contain "_discord_"; the LAST one wins.
        assert parse_recording_base("a_discord_b_discord_20260102_030405") == (
            "a_discord_b", "20260102_030405", None
        )
        assert parse_recording_base("something-else") == ("something-else", "", None)

    def test_parse_with_context(self):
        parsed = parse_recording_base("Standup_discord_20260102_030405 [Eunify - general]")
        assert parsed.meeting == "Standup"
        assert parsed.ts == "20260102_030405"
        assert parsed.context == "Eunify - general"
        bare = parse_recording_base("discord_20260102_030405 [Group DM - friends]")
        assert bare == (None, "20260102_030405", "Group DM - friends")

    def test_context_strings(self):
        assert recording_context("Eunify", "general", 2) == "Eunify - general"
        assert recording_context("Eunify", "", 2) == "Eunify"
        assert recording_context("", "general", 2) == "general"
        assert recording_context("", "", 2) is None
        assert recording_context(None, None, None) is None
        # DMs have no channel name; group DMs may.
        assert recording_context("", "", CHANNEL_TYPE_DM) == "DM"
        assert recording_context("", "", CHANNEL_TYPE_GROUP_DM) == "Group DM"
        assert recording_context("", "the gang", CHANNEL_TYPE_GROUP_DM) == "Group DM - the gang"

    def test_context_is_sanitised(self):
        # Brackets would break the suffix parse; slashes would break paths.
        ctx = recording_context("Ev[il] Server/..", "..\\general", 2)
        assert "[" not in ctx and "]" not in ctx
        assert "/" not in ctx and "\\" not in ctx
        assert ctx == "Ev il Server - general"
        long = recording_context("x" * 100, "y" * 100, 2)
        assert long == "x" * 40 + " - " + "y" * 40
        # A context produced by the helper always round-trips through parse.
        base = recording_base_name("M", "20260102_030405", ctx)
        assert parse_recording_base(base).context == ctx

    def test_recording_base_for_both_layouts(self, tmp_path):
        folder_audio = tmp_path / "X_discord_20260102_030405" / AUDIO_FILENAME
        assert recording_base(folder_audio) == "X_discord_20260102_030405"
        legacy_audio = tmp_path / "X_discord_20260102_030405_audio.wav"
        assert recording_base(legacy_audio) == "X_discord_20260102_030405"

    def test_display_parts_and_label(self, tmp_path):
        p = tmp_path / "Weekly Sync_discord_20260528_003930" / AUDIO_FILENAME
        assert recording_display_parts(p) == ("Weekly Sync", "2026-05-28 00:39", "")
        assert format_recording_label(p) == "Weekly Sync  —  2026-05-28 00:39"
        legacy = tmp_path / "discord_20260525_210051_audio.wav"
        assert format_recording_label(legacy) == "Untitled  —  2026-05-25 21:00"

    def test_label_includes_context(self, tmp_path):
        p = tmp_path / "Weekly Sync_discord_20260528_003930 [Eunify - general]" / AUDIO_FILENAME
        assert recording_display_parts(p) == ("Weekly Sync", "2026-05-28 00:39", "Eunify - general")
        assert (
            format_recording_label(p)
            == "Weekly Sync  —  2026-05-28 00:39  ·  Eunify - general"
        )


class TestRecordingFiles:
    def test_folder_layout(self, tmp_path):
        audio = tmp_path / "base_discord_20260102_030405" / AUDIO_FILENAME
        f = recording_files(audio)
        assert f.folder == audio.parent
        assert f.participants == audio.parent / PARTICIPANTS_FILENAME
        assert f.transcript == audio.parent / TRANSCRIPT_FILENAME
        assert f.mapping == audio.parent / MAPPING_FILENAME

    def test_legacy_layout_keeps_historical_names(self, tmp_path):
        audio = tmp_path / "base_discord_20260102_030405_audio.wav"
        f = recording_files(audio)
        assert f.folder is None
        assert f.participants == tmp_path / "base_discord_20260102_030405_participants.json"
        assert f.transcript == tmp_path / "base_discord_20260102_030405_audio_transcript.txt"
        assert f.mapping == tmp_path / "base_discord_20260102_030405_audio_mapping.json"


class TestIndex:
    def test_lists_both_layouts_and_skips_incomplete(self, tmp_path):
        new = _make_folder_recording(tmp_path, "New_discord_20260102_030405")
        old = _make_legacy_recording(tmp_path, "Old_discord_20260101_010101")
        # Folder without participants.json and a stray wav: both ignored.
        (tmp_path / "Broken_discord_20260103_000000").mkdir()
        (tmp_path / "Broken_discord_20260103_000000" / AUDIO_FILENAME).write_bytes(b"x")
        (tmp_path / "stray_audio.wav").write_bytes(b"x")
        (tmp_path / "notes.txt").write_text("x")

        paths = [p for _, p in index_recordings(tmp_path)]
        assert set(paths) == {new, old}

    def test_missing_root_is_empty(self, tmp_path):
        assert index_recordings(tmp_path / "nope") == []


class TestRename:
    def test_folder_rename_keeps_timestamp(self, tmp_path):
        audio = _make_folder_recording(tmp_path, "Old_discord_20260102_030405", transcript=True)
        new_audio = rename_recording(audio, "New Name", tmp_path)
        assert new_audio == tmp_path / "New_Name_discord_20260102_030405" / AUDIO_FILENAME
        assert new_audio.exists()
        assert (new_audio.parent / TRANSCRIPT_FILENAME).exists()
        assert not audio.parent.exists()

    def test_rename_preserves_context_suffix(self, tmp_path):
        audio = _make_folder_recording(
            tmp_path, "Old_discord_20260102_030405 [Eunify - general]"
        )
        new_audio = rename_recording(audio, "New", tmp_path)
        assert new_audio.parent.name == "New_discord_20260102_030405 [Eunify - general]"
        # Clearing the name keeps the context too.
        bare = rename_recording(new_audio, "", tmp_path)
        assert bare.parent.name == "discord_20260102_030405 [Eunify - general]"

    def test_empty_name_drops_meeting_part(self, tmp_path):
        audio = _make_folder_recording(tmp_path, "Old_discord_20260102_030405")
        new_audio = rename_recording(audio, "   ", tmp_path)
        assert new_audio.parent.name == "discord_20260102_030405"

    def test_same_name_is_noop(self, tmp_path):
        audio = _make_folder_recording(tmp_path, "Same_discord_20260102_030405")
        assert rename_recording(audio, "Same", tmp_path) == audio
        assert audio.exists()

    def test_name_is_sanitised_not_trusted(self, tmp_path):
        audio = _make_folder_recording(tmp_path, "Old_discord_20260102_030405")
        new_audio = rename_recording(audio, "../../evil", tmp_path)
        assert new_audio.parent.parent == tmp_path
        assert ".." not in new_audio.parent.name

    def test_collision_refused(self, tmp_path):
        a = _make_folder_recording(tmp_path, "A_discord_20260102_030405")
        _make_folder_recording(tmp_path, "B_discord_20260102_030405")
        with pytest.raises(FileExistsError):
            rename_recording(a, "B", tmp_path)
        assert a.exists()

    def test_outside_root_refused(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        elsewhere = _make_folder_recording(tmp_path, "X_discord_20260102_030405")
        with pytest.raises(ValueError, match="outside"):
            rename_recording(elsewhere, "Y", root)

    def test_unrecognised_name_refused(self, tmp_path):
        d = tmp_path / "custom"
        d.mkdir()
        audio = d / AUDIO_FILENAME
        audio.write_bytes(b"x")
        with pytest.raises(ValueError, match="not in Mynah's format"):
            rename_recording(audio, "Y", tmp_path)

    def test_legacy_recording_is_moved_into_folder(self, tmp_path):
        audio = _make_legacy_recording(tmp_path, "Old_discord_20260101_010101", transcript=True)
        new_audio = rename_recording(audio, "Fresh", tmp_path)
        folder = tmp_path / "Fresh_discord_20260101_010101"
        assert new_audio == folder / AUDIO_FILENAME
        assert (folder / PARTICIPANTS_FILENAME).exists()
        assert (folder / TRANSCRIPT_FILENAME).read_text() == "t"
        assert not (folder / MAPPING_FILENAME).exists()
        assert not list(tmp_path.glob("*_audio.wav"))
        assert not list(tmp_path.glob("*_participants.json"))

    def test_legacy_move_rolls_back_on_failure(self, tmp_path, monkeypatch):
        audio = _make_legacy_recording(tmp_path, "Old_discord_20260101_010101", transcript=True)
        real_rename = Path.rename
        calls = {"n": 0}

        def flaky(self, target):
            calls["n"] += 1
            if calls["n"] == 3:  # third move (transcript) fails
                raise OSError("disk says no")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", flaky)
        with pytest.raises(OSError, match="disk says no"):
            rename_recording(audio, "Fresh", tmp_path)
        assert audio.exists()
        assert (tmp_path / "Old_discord_20260101_010101_participants.json").exists()
        assert (tmp_path / "Old_discord_20260101_010101_audio_transcript.txt").exists()
        assert not (tmp_path / "Fresh_discord_20260101_010101").exists()

    def test_renamed_recording_is_indexed_under_new_name(self, tmp_path):
        audio = _make_folder_recording(tmp_path, "Old_discord_20260102_030405")
        new_audio = rename_recording(audio, "Renamed", tmp_path)
        labels = dict(index_recordings(tmp_path))
        assert labels == {"Renamed  —  2026-01-02 03:04": new_audio}


def test_sanitizer_still_importable_from_recorder():
    from mynah.recorder import _sanitize_meeting_name

    assert _sanitize_meeting_name is uicore._sanitize_meeting_name
