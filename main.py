from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import uuid
import datetime
import json

# Import auth router
from app import auth

app = FastAPI()

# Mount authentication routes
app.include_router(auth.router, prefix="/auth")

# ----------------------
# ✅ CORS Configuration
# ----------------------
origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://noteai-frontend.vercel.app ",  # Removed trailing space
    "https://noteai-frontend.netlify.app "
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# 📁 File Upload Setup
# ----------------------
UPLOAD_DIR = Path("/tmp/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Utility imports
from app.utils import save_upload_file, save_metadata_json, get_file_duration_in_seconds


@app.post("/upload-audio")
async def upload_audio(file: UploadFile = File(...), user_id: str = Form(...)):
    user_dir = UPLOAD_DIR / user_id
    user_dir.mkdir(parents=True, exist_ok=True)

    file_id = str(uuid.uuid4())
    extension = Path(file.filename).suffix
    file_path = user_dir / f"{file_id}{extension}"

    save_upload_file(file, file_path)
    duration = get_file_duration_in_seconds(str(file_path))

    metadata = {
        "id": file_id,
        "filename": file.filename,
        "stored_as": file_path.name,
        "uploaded_at": datetime.datetime.now().isoformat(),
        "duration_sec": duration,
        "transcript": "",
        "summary": ""
    }

    metadata_path = file_path.with_suffix(".json")
    save_metadata_json(metadata, metadata_path)

    return {"message": "Upload successful", "metadata": metadata}


@app.get("/history/{user_id}")
async def get_history(user_id: str):
    user_dir = UPLOAD_DIR / user_id
    if not user_dir.exists():
        return []
    history = []
    for file in user_dir.glob("*.json"):
        with open(file, "r") as f:
            history.append(json.load(f))
    return sorted(history, key=lambda x: x["uploaded_at"], reverse=True)


@app.post("/transcribe/{user_id}/{file_id}")
async def transcribe(user_id: str, file_id: str):
    metadata_file = next((UPLOAD_DIR / user_id).glob(f"{file_id}*.json"), None)
    if not metadata_file:
        raise HTTPException(status_code=404, detail="File not found")
    with open(metadata_file, "r") as f:
        metadata = json.load(f)
    metadata["transcript"] = f"Transcription simulée de {metadata['filename']}."
    save_metadata_json(metadata, metadata_file)
    return {"transcript": metadata["transcript"]}


@app.post("/summary/{user_id}/{file_id}")
async def summarize(user_id: str, file_id: str):
    metadata_file = next((UPLOAD_DIR / user_id).glob(f"{file_id}*.json"), None)
    if not metadata_file:
        raise HTTPException(status_code=404, detail="File not found")
    with open(metadata_file, "r") as f:
        metadata = json.load(f)
    metadata["summary"] = f"Résumé généré pour {metadata['filename']}."
    save_metadata_json(metadata, metadata_file)
    return {"summary": metadata["summary"]}


@app.get("/download/{user_id}/{file_id}.{ext}")
async def download_export(user_id: str, file_id: str, ext: str):
    metadata_file = next((UPLOAD_DIR / user_id).glob(f"{file_id}*.json"), None)
    if not metadata_file:
        raise HTTPException(status_code=404, detail="File not found")
    with open(metadata_file, "r") as f:
        metadata = json.load(f)
    export_file = UPLOAD_DIR / user_id / f"{file_id}.{ext}"
    export_file.write_text(
        f"Transcript:\n{metadata['transcript']}\n\nSummary:\n{metadata['summary']}"
    )
    return FileResponse(export_file, filename=f"{metadata['filename']}.{ext}")


# Optional: Root route for testing
@app.get("/")
async def root():
    return {"message": "NoteAI Backend is running!"}
