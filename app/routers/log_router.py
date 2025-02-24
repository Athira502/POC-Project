import os
from typing import List
from fastapi import APIRouter, File, UploadFile, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from app.services.log_service import parse_and_store_logs
from app.models.database import get_db
from app.models.log import LogEntry
from app.schemas.log_schema import LogEntryResponse

router = APIRouter()

UPLOAD_DIR = "uploaded_logs"

os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload-log/")
async def upload_log(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())

        parse_and_store_logs(file_path, db)

        return JSONResponse(status_code=200, content={"message": "Log file successfully parsed and stored!"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/", response_model=List[LogEntryResponse])
async def get_logs(db: Session = Depends(get_db)):
    try:
        logs = db.query(LogEntry).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
