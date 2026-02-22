#!/bin/bash

# Comprehensive Feature Test Script
# Tests all functionality of the SOC Analyst System

set -e

echo "🧪 Testing All Features - Autonomous AI SOC Analyst System"
echo "============================================================"
echo ""

API_URL="http://localhost:8000/api"
PASSED=0
FAILED=0

test_endpoint() {
    local name=$1
    local method=$2
    local endpoint=$3
    local data=$4
    
    echo -n "Testing $name... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$API_URL$endpoint" 2>&1)
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data" 2>&1)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo "✅ PASS"
        ((PASSED++))
        return 0
    else
        echo "❌ FAIL (HTTP $http_code)"
        echo "   Response: $body"
        ((FAILED++))
        return 1
    fi
}

echo "1️⃣  Health & Infrastructure Tests"
echo "-----------------------------------"
test_endpoint "Basic Health Check" "GET" "/health/basic"
test_endpoint "Database Connection" "GET" "/health/basic"
test_endpoint "Redis Connection" "GET" "/health/basic"

echo ""
echo "2️⃣  Core API Endpoints"
echo "-----------------------------------"
test_endpoint "List Incidents" "GET" "/incidents?limit=10"
test_endpoint "Dashboard Stats" "GET" "/dashboard/stats"
test_endpoint "Attack Coverage" "GET" "/metrics/attack-coverage"
test_endpoint "SOC KPIs" "GET" "/metrics/soc-kpis?hours=24"
test_endpoint "Organization Profile" "GET" "/organization/profile"

echo ""
echo "3️⃣  Log Ingestion Tests"
echo "-----------------------------------"
SAMPLE_LOGS='["2024-01-15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45"]'
RESULT=$(curl -s -X POST "$API_URL/ingest/analyze" \
    -H "Content-Type: application/json" \
    -d "$SAMPLE_LOGS" 2>&1)

echo -n "Testing Log Ingestion... "
if echo "$RESULT" | jq -e '.incident_id' > /dev/null 2>&1; then
    INCIDENT_ID=$(echo "$RESULT" | jq -r '.incident_id')
    echo "✅ PASS (Incident ID: ${INCIDENT_ID:0:8}...)"
    ((PASSED++))
else
    echo "❌ FAIL"
    echo "   Response: $RESULT"
    ((FAILED++))
    INCIDENT_ID=""
fi

if [ -n "$INCIDENT_ID" ]; then
    echo ""
    echo "4️⃣  Incident Management Tests"
    echo "-----------------------------------"
    test_endpoint "Get Incident Details" "GET" "/incidents/$INCIDENT_ID"
    
    # Wait a bit for analysis to complete
    echo -n "Waiting for analysis (30s)... "
    sleep 30
    echo "Done"
    
    test_endpoint "Get Incident After Analysis" "GET" "/incidents/$INCIDENT_ID"
    test_endpoint "Debug Last Analysis (by incident)" "GET" "/debug/last-analysis/$INCIDENT_ID"
fi

echo ""
echo "5️⃣  Cloud Log Parser Tests"
echo "-----------------------------------"
CLOUDTRAIL_LOG='["{\"eventTime\": \"2024-01-15T10:00:00Z\", \"eventName\": \"ConsoleLogin\", \"sourceIPAddress\": \"203.0.113.45\", \"awsRegion\": \"us-east-1\"}"]'
RESULT=$(curl -s -X POST "$API_URL/ingest/analyze" \
    -H "Content-Type: application/json" \
    -d "$CLOUDTRAIL_LOG" 2>&1)
echo -n "Testing AWS CloudTrail Parser... "
if echo "$RESULT" | jq -e '.incident_id' > /dev/null 2>&1; then
    echo "✅ PASS"
    ((PASSED++))
else
    echo "❌ FAIL"
    ((FAILED++))
fi

AZURE_LOG='["{\"time\": \"2024-01-15T10:00:00Z\", \"callerIpAddress\": \"203.0.113.46\", \"operationName\": {\"value\": \"Microsoft.Compute/virtualMachines/write\"}}"]'
RESULT=$(curl -s -X POST "$API_URL/ingest/analyze" \
    -H "Content-Type: application/json" \
    -d "$AZURE_LOG" 2>&1)
echo -n "Testing Azure Monitor Parser... "
if echo "$RESULT" | jq -e '.incident_id' > /dev/null 2>&1; then
    echo "✅ PASS"
    ((PASSED++))
else
    echo "❌ FAIL"
    ((FAILED++))
fi

GCP_LOG='["{\"timestamp\": \"2024-01-15T10:00:00Z\", \"protoPayload\": {\"methodName\": \"google.cloud.bigquery.v2.JobService.InsertJob\", \"requestMetadata\": {\"callerIp\": \"203.0.113.47\"}}}"]'
RESULT=$(curl -s -X POST "$API_URL/ingest/analyze" \
    -H "Content-Type: application/json" \
    -d "$GCP_LOG" 2>&1)
echo -n "Testing GCP Audit Log Parser... "
if echo "$RESULT" | jq -e '.incident_id' > /dev/null 2>&1; then
    echo "✅ PASS"
    ((PASSED++))
else
    echo "❌ FAIL"
    ((FAILED++))
fi

echo ""
echo "6️⃣  Advanced Features Tests"
echo "-----------------------------------"
test_endpoint "Synthetic Dataset Stats" "GET" "/synthetic/dataset-stats"
test_endpoint "Synthetic Generate" "POST" "/synthetic/generate" '{"count":2}'

echo ""
echo "============================================================"
echo "📊 Test Results Summary"
echo "============================================================"
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo "📈 Total:  $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed. Check the output above."
    exit 1
fi

