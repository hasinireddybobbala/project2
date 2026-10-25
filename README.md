Name: Hasini Bobbala
Course: CSCE 3550 – Project 2

# CSCE 3550 Project 2 – SQLite-backed JWKS Server

Python extension of the Project 1 JWKS server. Private keys are stored in
`totally_not_my_privateKeys.db` (PKCS1 PEM in a BLOB column) and all queries
use bound parameters to prevent SQL injection.

## Run
    pip install -r requirements.txt
    python3 main.py            # serves on http://localhost:8080

## Endpoints
- `POST /auth` – signs a JWT with an unexpired key from the DB;
  `POST /auth?expired` signs with an expired key.
- `GET /.well-known/jwks.json` – JWKS of all unexpired keys.

## Tests / lint
    python3 -m pytest --cov=main --cov-report=term-missing
    flake8

## Gradebot
Run the server, then in another terminal run the provided gradebot
`project2` command against `http://localhost:8080` from this directory
(so it can find the `.db` file). Save screenshots into `screenshots/`.
