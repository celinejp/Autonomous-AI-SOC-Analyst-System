# Setup Guide

## Quick Start

1. **Clone and navigate**
   ```bash
   git clone <repo-url>
   cd Autonomous-AI-SOC-Analyst-System
   ```

2. **Set environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your ANTHROPIC_API_KEY
   ```

3. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Initialize databases** (first time only)
   ```bash
   docker-compose exec backend python scripts/init_db.py
   ```

5. **Generate sample data** (optional)
   ```bash
   docker-compose exec backend python scripts/generate_sample_data.py
   ```

6. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## Manual Setup (Without Docker)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start PostgreSQL, Redis, Qdrant separately
# Update .env with connection strings

python scripts/init_db.py
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Troubleshooting

### Port conflicts
If ports are already in use, modify `docker-compose.yml` to use different ports.

### API key issues
Ensure `ANTHROPIC_API_KEY` is set in `.env` file.

### Database connection errors
Check that PostgreSQL, Redis, and Qdrant are running:
```bash
docker-compose ps
```

### Frontend can't connect to backend
Check `NEXT_PUBLIC_API_URL` in `.env` matches your backend URL.

