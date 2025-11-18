from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from utils import check_vote, VoteRequest as VoteRequestModel
from models import Album

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory albums storage (same as Go version)
albums = [
    {"id": "1", "title": "Blue Train", "artist": "John Coltrane", "price": 56.99},
    {"id": "2", "title": "Jeru", "artist": "Gerry Mulligan", "price": 17.99},
    {"id": "3", "title": "Sarah Vaughan and Clifford Brown", "artist": "Sarah Vaughan", "price": 39.99},
]


class VoteRequest(BaseModel):
    seal: str
    journal: str
    journal_abi: str
    image_id: str
    nullifier: str
    age: int
    is_student: bool
    poll_id: int
    option_a: int
    option_b: int


@app.get("/albums")
async def get_albums():
    return albums


@app.get("/albums/{album_id}")
async def get_album_by_id(album_id: str):
    for album in albums:
        if album["id"] == album_id:
            return album
    raise HTTPException(status_code=404, detail="album not found")


@app.post("/albums")
async def post_albums(album: Album):
    albums.append(album.dict())
    return album


@app.post("/checkvote")
async def checkvote_endpoint(vote_request: VoteRequest):
    try:
        vote_model = VoteRequestModel(
            seal=vote_request.seal,
            journal=vote_request.journal,
            journal_abi=vote_request.journal_abi,
            image_id=vote_request.image_id,
            nullifier=vote_request.nullifier,
            age=vote_request.age,
            is_student=vote_request.is_student,
            poll_id=vote_request.poll_id,
            option_a=vote_request.option_a,
            option_b=vote_request.option_b,
        )
        result = check_vote(vote_model)
        # Convert dataclass to dict for JSON serialization
        result_dict = {
            "nullifier": result.nullifier,
            "age": result.age,
            "is_student": result.is_student,
            "poll_id": result.poll_id,
            "option_a": result.option_a,
            "option_b": result.option_b,
        }
        return {"status": "success", "result": result_dict}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Mount static files (pointing to parent directory's web folder)
import os
web_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
if os.path.exists(web_path):
    app.mount("/web", StaticFiles(directory=web_path), name="web")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8080)

