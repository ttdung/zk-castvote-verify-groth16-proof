from pydantic import BaseModel


class Album(BaseModel):
    id: str
    title: str
    artist: str
    price: float

