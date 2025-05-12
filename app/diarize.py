from pyannote.audio import Pipeline
from fastapi import APIRouter, File, UploadFile
import tempfile
import os

router = APIRouter()

# Utiliser le token Hugging Face via variable d'environnement
HUGGINGFACE_TOKEN = os.environ.get("HUGGINGFACE_TOKEN")
pipeline = Pipeline.from_pretrained("pyannote/speaker-diarization", use_auth_token=HUGGINGFACE_TOKEN)

@router.post("/diarize")
async def diarize_audio(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        diarization = pipeline(tmp_path)
        segments = [
            {
                "start": f"{segment.start:.1f}",
                "end": f"{segment.end:.1f}",
                "speaker": f"{label}"
            }
            for segment, _, label in diarization.itertracks(yield_label=True)
        ]

        os.remove(tmp_path)
        return {"segments": segments}

    except Exception as e:
        return {"error": str(e)}