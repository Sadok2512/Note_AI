import whisper
import os

# Utiliser un dossier temporaire universel autorisé en écriture
os.environ["XDG_CACHE_HOME"] = "/tmp"

# Charger le modèle Whisper-large une seule fois
model = whisper.load_model("large")

def transcribe_audio(file_path: str) -> str:
    print(f"🔊 Transcribing file: {file_path} with Whisper-large")
    result = model.transcribe(file_path, language="fr", verbose=False)
    segments = result.get("segments", [])

    if not segments:
        return result["text"]

    transcript_lines = []
    speaker_index = 1
    previous_end = 0.0

    for seg in segments:
        start = seg["start"]
        end = seg["end"]
        text = seg["text"].strip()

        # Changer de speaker si silence > 2 secondes
        if start - previous_end > 2.0:
            speaker_index += 1

        speaker_label = f"Speaker {speaker_index}"
        transcript_lines.append(f"{speaker_label}: {text}")
        previous_end = end

    return "\n".join(transcript_lines)
