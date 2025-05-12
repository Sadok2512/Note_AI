from pathlib import Path
from fastapi import UploadFile
import shutil
import json

# Utilisation de /tmp pour éviter les erreurs de permission
BASE_UPLOAD_DIR = Path("/tmp/uploads")
BASE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def save_upload_file(upload_file: UploadFile, destination: Path) -> None:
    with destination.open("wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

def save_metadata_json(metadata: dict, destination: Path) -> None:
    with destination.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=4)

def get_file_duration_in_seconds(file_path: str) -> float:
    # Optional: if you're calculating duration using pydub or librosa
    try:
        import wave
        import contextlib
        with contextlib.closing(wave.open(file_path, 'r')) as f:
            frames = f.getnframes()
            rate = f.getframerate()
            return frames / float(rate)
    except Exception:
        return 0.0
