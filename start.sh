#!/bin/bash

# Autonomous AI SOC Analyst System - Start Script
# This script starts all services required for the system

set -e

echo "🚀 Starting Autonomous AI SOC Analyst System..."
echo "================================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Ollama is running (for LLM)
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "⚠️  Warning: Ollama is not running on port 11434."
    echo "   Starting without Ollama may cause LLM errors."
    echo "   Install Ollama: https://ollama.ai/"
    echo "   Then run: ollama pull llama3.1"
    echo ""
fi

# Start backend services (PostgreSQL, Redis, Qdrant, Backend API)
echo "📦 Starting backend services (PostgreSQL, Redis, Qdrant, Backend)..."
docker-compose up -d postgres redis qdrant backend

# Wait for services to be healthy
echo ""
echo "⏳ Waiting for services to be ready..."
sleep 5

# Check PostgreSQL
echo "   Checking PostgreSQL..."
until docker-compose exec -T postgres pg_isready -U soc_user > /dev/null 2>&1; do
    echo "      Waiting for PostgreSQL..."
    sleep 2
done
echo "   ✅ PostgreSQL is ready"

# Check Redis
echo "   Checking Redis..."
until docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; do
    echo "      Waiting for Redis..."
    sleep 2
done
echo "   ✅ Redis is ready"

# Check Qdrant
echo "   Checking Qdrant..."
until curl -s http://localhost:6333/health > /dev/null 2>&1; do
    echo "      Waiting for Qdrant..."
    sleep 2
done
echo "   ✅ Qdrant is ready"

# Check Backend API
echo "   Checking Backend API..."
until curl -s http://localhost:8000/api/health/basic > /dev/null 2>&1; do
    echo "      Waiting for Backend API..."
    sleep 2
done
echo "   ✅ Backend API is ready"

# Initialize database (if needed)
echo ""
echo "🗄️  Initializing database..."
docker-compose exec -T backend python scripts/init_db.py 2>/dev/null || echo "   Database already initialized or init script not found"

# Start frontend (in development mode, run locally for faster iteration)
echo ""
echo "🎨 Frontend Options:"
echo "   1. Start frontend with Docker (slower, production-like)"
echo "   2. Run frontend locally (faster, recommended for development)"
echo ""
read -p "Choose option (1 or 2, default: 2): " frontend_option
frontend_option=${frontend_option:-2}

if [ "$frontend_option" = "1" ]; then
    echo "📦 Starting frontend with Docker..."
    docker-compose up -d frontend
    echo "   ⏳ Waiting for frontend..."
    sleep 10
    echo "   ✅ Frontend is ready at http://localhost:3000"
else
    echo "📦 To run frontend locally, run in a separate terminal:"
    echo "   cd frontend && npm install && npm run dev"
    echo ""
    echo "   Frontend will be available at http://localhost:3000"
fi

echo ""
echo "================================================"
echo "✅ System started successfully!"
echo ""
echo "🌐 Services:"
echo "   - Backend API:     http://localhost:8000"
echo "   - API Docs:        http://localhost:8000/docs"
echo "   - Frontend:        http://localhost:3000"
echo "   - PostgreSQL:      localhost:5433"
echo "   - Redis:           localhost:6379"
echo "   - Qdrant:          http://localhost:6333"
echo ""
echo "📝 Next Steps:"
echo "   1. Access the frontend at http://localhost:3000"
echo "   2. Upload security logs or use Demo Mode to test"
echo "   3. View incidents and analysis results"
echo ""
echo "🛑 To stop all services:"
echo "   ./stop.sh or docker-compose down"
echo ""
