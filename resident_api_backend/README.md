# Resident Management System API (FastAPI)

Runs on preview port **3001**.

## Quick start (local)

```bash
pip install -r requirements.txt
uvicorn src.api.main:app --host 0.0.0.0 --port 3001 --reload
```

Open API docs:
- http://localhost:3001/docs
- OpenAPI JSON: http://localhost:3001/openapi.json

## Demo accounts (seeded automatically if DB empty)

- Admin: `admin@example.com` / `admin123`
- User: `user@example.com` / `user123`

## Key routes

### Auth
- `POST /auth/login` -> returns JWT token
- `GET /auth/me` -> returns current user info (requires `Authorization: Bearer <token>`)

### Residents
- `GET /residents` (public) supports:
  - `q` (search by name/email)
  - `page` (1-based)
  - `page_size` (max 50)
- `GET /residents/{id}` (public)
- `POST /residents` (admin)
- `PUT /residents/{id}` (admin)
- `DELETE /residents/{id}` (admin)

### Uploads
- `POST /uploads/photo` (admin) multipart upload, returns `{ photo_url: "/uploads/..." }`
- Static files served under `/uploads/*`

## Environment

See `.env.example`. Defaults are provided so the preview can run without secrets.
For production, always set a strong `JWT_SECRET`.
