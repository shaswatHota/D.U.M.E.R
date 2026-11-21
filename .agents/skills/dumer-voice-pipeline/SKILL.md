---
name: dumer-voice-pipeline
description: Implement D.U.M.E.R voice — push-to-talk, Vosk grammar-constrained command STT, whisper.cpp CPU dictation, Piper TTS, mic state, voice-taint rules. Use for audio input/output.
---
# Voice
- Voice is an interface, not an authority: transcripts are `Voice`-tainted input into the same matcher and policy.
- Command mode: Vosk with a grammar regenerated from the live registry; act on partials only for tier 0–1 with unique high-confidence match. Dictation/complex: whisper.cpp on CPU (don't steal VRAM).
- Tier ≥2 never executes on voice alone (on-screen confirm); optional speaker verification; PTT default, wake word optional; always-visible mic state; no raw audio retention by default.
- Runs in `dumer-voice` sandbox (no network, no file access beyond models). Models optional and removable; TTS = Piper.
- Never act on audio from the agent's own TTS (loop guard); duck/ignore during playback.
- Tests: grammar regeneration, misrecognition near-misses, replay of recorded command audio at tier ≥2 is refused.
