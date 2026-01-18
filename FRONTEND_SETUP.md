# 🚀 Frontend Setup Instructions

## Prerequisites

1. **Node.js 20+** - [Download](https://nodejs.org/)
2. **npm** (comes with Node.js)
3. **Backend must be running** - `./start.sh` or `docker-compose up -d`

## Installation

1. **Navigate to frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```
   
   This will install:
   - Next.js 15
   - React 18
   - TypeScript
   - Tailwind CSS
   - React Query
   - Recharts
   - shadcn/ui dependencies

3. **Start development server**
   ```bash
   npm run dev
   ```

4. **Open browser**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000/docs

## Troubleshooting

### Error: Cannot find module '@tanstack/react-query'
**Solution:** Run `npm install` in the frontend directory

### Error: Cannot connect to backend API
**Solution:** 
1. Make sure backend is running: `docker-compose ps`
2. Check backend health: `curl http://localhost:8000/api/health/basic`
3. Start backend: `./start.sh`

### Error: Port 3000 already in use
**Solution:**
```bash
# Kill process on port 3000
lsof -ti:3000 | xargs kill -9

# Or use a different port
PORT=3001 npm run dev
```

### TypeScript errors
**Solution:** These are normal if dependencies aren't installed. Run `npm install` first.

## Quick Test

After installing dependencies, test the frontend:

```bash
# 1. Install dependencies
cd frontend
npm install

# 2. Start dev server
npm run dev

# 3. Open browser to http://localhost:3000
# 4. Check console for errors
# 5. Try navigating to different pages:
#    - http://localhost:3000 (Dashboard)
#    - http://localhost:3000/incidents (Incidents List)
#    - http://localhost:3000/ingest (Log Ingestion)
#    - http://localhost:3000/insights (Analytics)
```

## Production Build

```bash
cd frontend
npm run build
npm start
```

## Status

✅ **Frontend files created and ready**
⚠️ **Dependencies need to be installed** (`npm install`)
✅ **Backend API is working**

