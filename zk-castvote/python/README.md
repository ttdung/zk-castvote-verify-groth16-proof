# Python Backend for Anonymous Voting

This is the Python conversion of the Go backend for anonymous voting with RISC-Zero zkSNARK verification.

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Running the Server

```bash
python app.py
```

Or using uvicorn directly:
```bash
uvicorn app:app --host localhost --port 8080
```

The server will start on `http://localhost:8080`.

## API Endpoints

- `GET /albums` - Get all albums
- `GET /albums/{id}` - Get album by ID
- `POST /albums` - Create a new album
- `POST /checkvote` - Verify a vote using RISC-Zero zkSNARK proof

## Structure

- `app.py` - Main FastAPI application
- `models.py` - Pydantic models
- `utils/` - Utility functions for vote checking and bincode decoding
- `risc0/` - RISC-Zero verification logic
- `groth16/` - Groth16 zkSNARK verification logic

## Dependencies

- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `pydantic` - Data validation
- `py-ecc` - Elliptic curve cryptography (BN128/Groth16)

