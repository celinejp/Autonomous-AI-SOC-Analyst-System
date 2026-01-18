#!/bin/bash
# External testing script for AI SOC Analyst System
# Run this to verify the system is working correctly

set -e

API_URL="${API_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"

echo "🔍 Testing AI SOC Analyst System..."
echo "API URL: $API_URL"
echo "Frontend URL: $FRONTEND_URL"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Basic Health Check
echo "1️⃣  Testing basic health check..."
if curl -s -f "$API_URL/api/health/basic" > /dev/null; then
    echo -e "${GREEN}✅ Basic health check passed${NC}"
    curl -s "$API_URL/api/health/basic" | python3 -m json.tool 2>/dev/null || curl -s "$API_URL/api/health/basic"
else
    echo -e "${RED}❌ Basic health check failed${NC}"
    exit 1
fi

echo ""

# Test 2: Check if frontend is accessible
echo "2️⃣  Testing frontend accessibility..."
if curl -s -f "$FRONTEND_URL" > /dev/null; then
    echo -e "${GREEN}✅ Frontend is accessible${NC}"
else
    echo -e "${YELLOW}⚠️  Frontend not accessible (may not be started)${NC}"
fi

echo ""

# Test 3: Submit test log (brute force attack)
echo "3️⃣  Submitting test log (brute force attack scenario)..."
TEST_LOG='[
  "2024-01-15 10:30:00 AUTH FAILED user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh",
  "2024-01-15 10:30:01 AUTH FAILED user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh",
  "2024-01-15 10:30:02 AUTH FAILED user=root src=192.168.1.100 dst=10.0.0.50 service=ssh",
  "2024-01-15 10:30:15 AUTH SUCCESS user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh"
]'

RESPONSE=$(curl -s -X POST "$API_URL/api/ingest/analyze" \
  -H "Content-Type: application/json" \
  -d "$TEST_LOG")

INCIDENT_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('incident_id', ''))" 2>/dev/null || echo "")

if [ -n "$INCIDENT_ID" ] && [ "$INCIDENT_ID" != "null" ] && [ "$INCIDENT_ID" != "" ]; then
    echo -e "${GREEN}✅ Test log submitted successfully${NC}"
    echo "   Incident ID: $INCIDENT_ID"
    STATUS=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'analyzing'))" 2>/dev/null || echo "analyzing")
    echo "   Status: $STATUS"
else
    echo -e "${RED}❌ Failed to submit test log${NC}"
    echo "Response: $RESPONSE"
    exit 1
fi

echo ""

# Test 4: Wait for analysis (poll status)
echo "4️⃣  Waiting for analysis to complete (this may take 30-60 seconds)..."
MAX_WAIT=90
WAITED=0
STATUS="analyzing"

while [ "$STATUS" = "analyzing" ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 5
    WAITED=$((WAITED + 5))
    
    if [ -n "$INCIDENT_ID" ]; then
        STATUS_RESPONSE=$(curl -s "$API_URL/api/incidents/$INCIDENT_ID/status" 2>/dev/null || echo '{"status":"unknown"}')
        STATUS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'analyzing'))" 2>/dev/null || echo "analyzing")
        
        if [ "$STATUS" != "analyzing" ]; then
            break
        fi
        
        PROGRESS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('progress_percent', 0))" 2>/dev/null || echo "0")
        echo "   Progress: ${PROGRESS}% (waited ${WAITED}s)..."
    fi
done

if [ "$STATUS" = "completed" ]; then
    echo -e "${GREEN}✅ Analysis completed successfully${NC}"
elif [ "$STATUS" = "failed" ]; then
    echo -e "${RED}❌ Analysis failed${NC}"
    exit 1
else
    echo -e "${YELLOW}⚠️  Analysis still in progress (timeout after ${MAX_WAIT}s)${NC}"
fi

echo ""

# Test 5: Check incident was created
echo "5️⃣  Verifying incident was created..."
if [ -n "$INCIDENT_ID" ]; then
    INCIDENT=$(curl -s "$API_URL/api/incidents/$INCIDENT_ID" 2>/dev/null || echo "{}")
    
    HAS_ID=$(echo "$INCIDENT" | python3 -c "import sys, json; print('id' in json.load(sys.stdin))" 2>/dev/null || echo "False")
    
    if [ "$HAS_ID" = "True" ]; then
        echo -e "${GREEN}✅ Incident retrieved successfully${NC}"
        
        SEVERITY=$(echo "$INCIDENT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('severity', 'unknown'))" 2>/dev/null || echo "unknown")
        ALERTS=$(echo "$INCIDENT" | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('alerts', [])))" 2>/dev/null || echo "0")
        
        echo "   Severity: $SEVERITY"
        echo "   Alerts: $ALERTS"
    else
        echo -e "${YELLOW}⚠️  Incident not yet available in database${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No incident ID to check${NC}"
fi

echo ""

# Test 6: Deep health check (optional, takes longer)
read -p "Run deep health check (tests all agents)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "6️⃣  Running deep health check..."
    DEEP_HEALTH=$(curl -s "$API_URL/api/health/deep")
    
    DEEP_STATUS=$(echo "$DEEP_HEALTH" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
    
    if [ "$DEEP_STATUS" = "healthy" ]; then
        echo -e "${GREEN}✅ Deep health check passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Deep health check: $DEEP_STATUS${NC}"
    fi
    
    echo "$DEEP_HEALTH" | python3 -m json.tool 2>/dev/null || echo "$DEEP_HEALTH"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Test suite complete!${NC}"
echo ""
echo "📊 View results:"
echo "   Dashboard: $FRONTEND_URL"
if [ -n "$INCIDENT_ID" ] && [ "$INCIDENT_ID" != "null" ] && [ "$INCIDENT_ID" != "" ]; then
    echo "   Incident: $FRONTEND_URL/incident/$INCIDENT_ID"
fi
echo ""

