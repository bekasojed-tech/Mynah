"""Session orchestrator: combines RPC participant tracking and audio capture."""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .audio import AudioRecorder
from .rpc import DiscordRPC
# The filename sanitiser and the on-disk layout helpers live in uicore so
# the rename feature (backend + both UIs) shares them without importing
# the audio stack. Re-exported here because tests and older call sites
# import `_sanitize_meeting_name` from this module.
from .uicore import (  # noqa: F401  (re-exports)
    _FILENAME_SAFE,
    _WINDOWS_RESERVED,
    AUDIO_FILENAME,
    PARTICIPANTS_FILENAME,
    _sanitize_meeting_name,
    recording_base_name,
    recording_context,
)

log = logging.getLogger(__name__)


@dataclass
class RecordingResult:
    audio_path: Path
    participants_path: Path
    initial_participants: list[str]
    events: list[dict] = field(default_factory=list)


class RecordingSession:
    """Records one meeting. Construct, start(), then stop()."""

    POLL_INTERVAL_SEC = 2.0

    def __init__(
        self,
        rpc: DiscordRPC,
        output_dir: Path,
        meeting_name: Optional[str] = None,
        audio_source: str = "mixed",
        consent_record: Optional[dict] = None,
        loopback_device_name: str = "",
    ):
        self.rpc = rpc
        self.output_dir = Path(output_dir)
        self.meeting_name = _sanitize_meeting_name(meeting_name)
        self.audio = AudioRecorder(
            source=audio_source,
            loopback_device_name=loopback_device_name,
        )
        # Issue #25 (privacy consent gate): an attestation that the
        # local user knowingly authorised the recording before
        # capture started. Persisted verbatim to participants.json so
        # downstream tools (and the user reviewing the recording
        # later) have an auditable trail of consent. The GUI builds
        # the record from a modal dialog; tests / scripted recorders
        # may pass it directly.
        self.consent_record = consent_record
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._start_time = 0.0
        # Snapshotted ONCE during start() after waiting for the first
        # audio sample to arrive. Frozen for the rest of the session so
        # every persisted timestamp (speaking events AND join/leave
        # events) shares the same time-zero. The pre-snapshot design
        # let early events use _start_time while later events used
        # first_audio_time, which produced a backward time-step at the
        # transition that corrupted the downstream diarization
        # DataFrame .
        self._audio_anchor_snapshot = 0.0
        self._participants: list[str] = []
        self._participants_detailed: list[dict] = []
        self._self_user_id: Optional[str] = None
        self._events: list[dict] = []
        self._events_lock = threading.Lock()
        self._speaking_events: list[dict] = []
        self._speaking_lock = threading.Lock()
        self._speaking_subscribed = False
        self._voice_channel_id: Optional[str] = None
        # Where the call happened — folded into the folder name and
        # persisted to participants.json. Server name needs a second RPC
        # round-trip (GET_GUILD) and is best-effort.
        self._channel_name: str = ""
        self._channel_type: Optional[int] = None
        self._guild_id: Optional[str] = None
        self._guild_name: str = ""
        self._base_name = ""

    def start(self) -> list[str]:
        # Query the current voice channel once so we know which channel to
        # subscribe to and so participants are populated atomically with the
        # SPEAKING_* subscriptions (no race against a join we missed).
        ch = self.rpc.get_voice_channel()
        if not ch:
            raise RuntimeError(
                "No participants found. Make sure you're joined to a Discord voice channel."
            )
        self._voice_channel_id = ch.get("id")
        if not self._voice_channel_id:
            raise RuntimeError("Discord returned a voice channel with no id field")
        self._channel_name = str(ch.get("name") or "")
        self._channel_type = ch.get("type") if isinstance(ch.get("type"), int) else None
        guild_id = ch.get("guild_id")
        self._guild_id = str(guild_id) if guild_id else None
        self._guild_name = ""
        if self._guild_id:
            guild = self.rpc.get_guild(self._guild_id) or {}
            self._guild_name = str(guild.get("name") or "")
        detailed: list[dict] = []
        for vs in ch.get("voice_states", []):
            user = vs.get("user") or {}
            uid = user.get("id")
            if not uid:
                continue
            name = user.get("global_name") or user.get("username") or "Unknown"
            detailed.append({"id": uid, "name": name})
        if not detailed:
            raise RuntimeError(
                "Voice channel found but no participants reported. "
                "Try Refresh Participants and Start Recording again."
            )
        self._participants_detailed = detailed
        self._participants = [p["name"] for p in detailed]
        self._self_user_id = (self.rpc.identity or {}).get("id")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._base_name = recording_base_name(
            self.meeting_name,
            ts,
            recording_context(self._guild_name, self._channel_name, self._channel_type),
        )
        self._events = [
            {
                "timestamp": 0.0,
                "event": "present",
                "id": p["id"],
                "username": p["name"],
            }
            for p in self._participants_detailed
        ]

        try:
            self.audio.start()
        except Exception:
            # AudioRecorder.start() already cleans up internally on raise
            # (closes streams, terminates PortAudio). We do not need to
            # call stop() here — and doing so would raise RuntimeError
            # because _running is False after a failed start.
            raise

        # Take the start timestamp as close as possible to the moment audio
        # capture is actually running so speaking-event offsets line up with
        # the audio timeline. Setting _start_time BEFORE audio.start() (as
        # the previous revision did) systematically shifted every label
        # earlier by the device-open latency (commonly 100-500 ms on
        # WASAPI), which produced visibly misaligned speaker boundaries
        # for short utterances at session start.
        self._start_time = time.time()

        # Snapshot the audio-anchor ONCE before subscribing to speaking
        # events. Wait up to _ANCHOR_WAIT_SEC for the capture thread to
        # deliver the first sample (typical WASAPI device-open latency
        # is 100-500 ms; we give ourselves 1 s of slack). The snapshot
        # is frozen for the rest of the session: every event uses the
        # same time-zero regardless of when it fires relative to the
        # first audio sample. This eliminates the backward time-step
        # between events recorded before vs after first_audio_time was
        # set that the pre-snapshot _audio_anchor() produced (in
        # ).
        self._audio_anchor_snapshot = self._snapshot_audio_anchor()

        # Subscribe to per-user speaking events for this channel. These give
        # us ground-truth "who spoke when" timestamps without needing
        # diarization heuristics. The callbacks run on the RPC reader thread
        # — keep them tiny.
        #
        # The subscriptions must succeed as a PAIR. If SPEAKING_START
        # succeeds and SPEAKING_STOP fails, we'd record opens with no
        # matching closes — every interval would stretch to audio end,
        # which is worse "ground truth" than the heuristic fallback. So we
        # roll back START on STOP failure and treat the whole session as
        # not-subscribed, letting transcription use the pyannote fallback.
        self._speaking_subscribed = False
        args = {"channel_id": self._voice_channel_id}
        try:
            self.rpc.subscribe("SPEAKING_START", args, self._on_speaking_start)
        except Exception as e:
            log.warning("SPEAKING_START subscribe failed (%s). Falling back to pyannote.", e)
        else:
            try:
                self.rpc.subscribe("SPEAKING_STOP", args, self._on_speaking_stop)
            except Exception as e:
                log.warning(
                    "SPEAKING_STOP subscribe failed (%s); rolling back SPEAKING_START. "
                    "Falling back to pyannote.", e,
                )
                try:
                    self.rpc.unsubscribe("SPEAKING_START", args,
                                         callback=self._on_speaking_start)
                except Exception:
                    pass
            else:
                self._speaking_subscribed = True
                log.info(
                    "Subscribed to SPEAKING_START/STOP for channel %s",
                    self._voice_channel_id,
                )

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        return list(self._participants)

    # ---- speaking-event callbacks ----

    _ANCHOR_WAIT_SEC = 1.0
    _ANCHOR_POLL_SEC = 0.01

    def _snapshot_audio_anchor(self) -> float:
        """Wait briefly for the first audio sample, then return the
        anchor for the rest of the session.

        Returns `audio.first_audio_time` if the capture thread has
        delivered its first sample within `_ANCHOR_WAIT_SEC`; otherwise
        falls back to `_start_time`. Direct attribute access — no
        getattr default — so a refactor that renames or removes
        `AudioRecorder.first_audio_time` raises `AttributeError`
        instead of silently falling back to the pre-fix behavior
        .
        """
        deadline = self._start_time + self._ANCHOR_WAIT_SEC
        while self.audio.first_audio_time is None and time.time() < deadline:
            time.sleep(self._ANCHOR_POLL_SEC)
        first = self.audio.first_audio_time
        if first is not None:
            return first
        log.warning(
            "Audio capture did not deliver a sample within %.1fs of "
            "audio.start() — falling back to wall-clock session start "
            "as anchor. Speaking-event timestamps may be offset by the "
            "actual device-open latency.",
            self._ANCHOR_WAIT_SEC,
        )
        return self._start_time

    def _audio_anchor(self) -> float:
        """The session's frozen audio-timeline anchor.

        Returns the value snapshotted in `start()` via
        `_snapshot_audio_anchor()`. Every persisted timestamp in the
        session (speaking events AND join/leave events) is computed as
        `time.time() - _audio_anchor()`, so they all share the same
        time-zero.
        """
        return self._audio_anchor_snapshot

    def _on_speaking_start(self, data: dict) -> None:
        if not self._running:
            return
        t = time.time() - self._audio_anchor()
        with self._speaking_lock:
            self._speaking_events.append({
                "timestamp": t,
                "event": "speaking_start",
                "user_id": data.get("user_id"),
            })

    def _on_speaking_stop(self, data: dict) -> None:
        if not self._running:
            return
        t = time.time() - self._audio_anchor()
        with self._speaking_lock:
            self._speaking_events.append({
                "timestamp": t,
                "event": "speaking_stop",
                "user_id": data.get("user_id"),
            })

    def _monitor_loop(self) -> None:
        # Track previous state by Discord user ID, not display name. Names are
        # mutable (people can change global_name mid-call) and not unique
        # (two users can share a display name), so name-based diffing can
        # generate spurious joined/left events.
        previous: dict[str, str] = {p["id"]: p["name"] for p in self._participants_detailed}
        while self._running:
            time.sleep(self.POLL_INTERVAL_SEC)
            if not self._running:
                break
            try:
                detailed = self.rpc.get_participants_detailed()
            except Exception as e:
                log.warning("Participant poll failed: %s", e)
                continue
            current: dict[str, str] = {p["id"]: p["name"] for p in detailed}
            # Use the audio anchor — same timeline as speaking events —
            # so the join/leave timestamps in participants.json are
            # directly comparable to the speaking-event timestamps in
            # the same file. With _start_time the two timelines drifted
            # by the device-open latency.
            t = time.time() - self._audio_anchor()

            with self._events_lock:
                # Joins: present now, not before.
                for uid, name in current.items():
                    if uid not in previous:
                        self._events.append({
                            "timestamp": t,
                            "event": "joined",
                            "id": uid,
                            "username": name,
                        })
                        log.info("[%.1fs] %s joined", t, name)

                # Leaves: present before, not now.
                for uid, name in previous.items():
                    if uid not in current:
                        self._events.append({
                            "timestamp": t,
                            "event": "left",
                            "id": uid,
                            "username": name,
                        })
                        log.info("[%.1fs] %s left", t, name)

            previous = current

    def stop(self) -> RecordingResult:
        if not self._running:
            raise RuntimeError("Session not running")
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)

        # Be polite — unsubscribe so further DISPATCHes don't pile up on the
        # reader thread after we're done. Failures here are non-fatal.
        if self._voice_channel_id and self._speaking_subscribed:
            args = {"channel_id": self._voice_channel_id}
            for evt_name, cb in (
                ("SPEAKING_START", self._on_speaking_start),
                ("SPEAKING_STOP", self._on_speaking_stop),
            ):
                try:
                    self.rpc.unsubscribe(evt_name, args, callback=cb)
                except Exception:
                    pass

        # Snapshot the metadata FIRST, under the locks, then write the
        # participants.json BEFORE calling audio.stop(). If audio.stop()
        # raises (e.g. a mid-recording capture error surfacing via
        # _capture_error), the participant list and speaking-event
        # timeline are already persisted to disk — the user still has the
        # evidentiary metadata even though the WAV is lost. The previous
        # order discarded both.
        #
        # Each recording gets its own folder named after the session
        # (`<meeting>_discord_<timestamp>`), holding audio.wav,
        # participants.json and, later, transcript.txt / mapping.json.
        # Renaming a recording is then a single folder rename.
        rec_dir = self.output_dir / self._base_name
        rec_dir.mkdir(parents=True, exist_ok=True)
        audio_path = rec_dir / AUDIO_FILENAME

        with self._speaking_lock:
            # Only surface speaking events if BOTH subscriptions were live;
            # otherwise the data is half-truth (starts without stops, or
            # vice versa) and would mislead the transcriber.
            speaking_events = list(self._speaking_events) if self._speaking_subscribed else []

        with self._events_lock:
            events_snapshot = list(self._events)

        participants_path = rec_dir / PARTICIPANTS_FILENAME
        participants_path.write_text(
            json.dumps(
                {
                    "initial_participants": self._participants,
                    "participants_detailed": self._participants_detailed,
                    "self_user_id": self._self_user_id,
                    "voice_channel_id": self._voice_channel_id,
                    "channel_name": self._channel_name,
                    "channel_type": self._channel_type,
                    "guild_id": self._guild_id,
                    "guild_name": self._guild_name,
                    "events": events_snapshot,
                    "speaking_events": speaking_events,
                    "speaking_events_complete": self._speaking_subscribed,
                    "audio_layout": self.audio.audio_layout(),
                    "consent": self.consent_record,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        self.audio.stop(audio_path)
        if self._speaking_subscribed:
            log.info(
                "Recorded %d speaking events from %d distinct users",
                len(speaking_events),
                len({e.get("user_id") for e in speaking_events if e.get("user_id")}),
            )
        else:
            log.info(
                "Speaking-event subscription was incomplete; falling back to "
                "diarization at transcribe time."
            )

        return RecordingResult(
            audio_path=audio_path,
            participants_path=participants_path,
            initial_participants=list(self._participants),
            events=events_snapshot,
        )
