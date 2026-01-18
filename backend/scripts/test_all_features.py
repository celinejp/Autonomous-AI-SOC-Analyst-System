#!/usr/bin/env python3
"""
Comprehensive system test - validates all features work correctly
Run: python scripts/test_all_features.py
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()
BASE_URL = "http://localhost:8000/api"


class SystemTester:
    def __init__(self):
        self.results = []
        self.client = httpx.AsyncClient(timeout=180.0)
    
    async def test_1_health_checks(self):
        """Test: All services are healthy"""
        console.print("\n[bold cyan]Test 1: Health Checks[/bold cyan]")
        
        try:
            # Check basic health
            resp = await self.client.get(f"{BASE_URL}/health/basic")
            assert resp.status_code == 200
            health = resp.json()
            
            checks = {
                "API Server": health.get("status") == "healthy",
                "Database": health.get("checks", {}).get("database", {}).get("status") == "pass",
                "Redis": health.get("checks", {}).get("redis", {}).get("status") == "pass",
                "Qdrant": health.get("checks", {}).get("qdrant", {}).get("status") == "pass",
            }
            
            for service, status in checks.items():
                icon = "✅" if status else "❌"
                console.print(f"  {icon} {service}: {'OK' if status else 'FAIL'}")
            
            return all(checks.values())
        except Exception as e:
            console.print(f"  ❌ Health check failed: {e}")
            return False
    
    async def test_2_agent_execution(self):
        """Test: All 6 agents execute successfully"""
        console.print("\n[bold cyan]Test 2: Agent Execution[/bold cyan]")
        
        try:
            # Load test fixture
            fixture = Path("backend/tests/fixtures/brute_force_ssh.json")
            if not fixture.exists():
                console.print("  ⚠️  Fixture not found - creating it first...")
                return False
            
            with open(fixture) as f:
                test_data = json.load(f)
            
            # Submit logs
            resp = await self.client.post(
                f"{BASE_URL}/ingest/analyze",
                json=test_data["logs"]
            )
            assert resp.status_code == 200
            result = resp.json()
            incident_id = result["incident_id"]
            console.print(f"  📝 Created incident: {incident_id}")
            
            # Poll for completion
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("  ⏳ Analyzing...", total=None)
                
                while True:
                    await asyncio.sleep(2)
                    resp = await self.client.get(f"{BASE_URL}/incidents/{incident_id}/status")
                    status_data = resp.json()
                    
                    if status_data["status"] == "completed":
                        progress.update(task, description="  ✅ Analysis complete!")
                        break
                    elif status_data["status"] == "failed":
                        console.print(f"  ❌ Analysis failed: {status_data.get('error')}")
                        return False
            
            # Validate each agent ran
            debug_resp = await self.client.get(f"{BASE_URL}/debug/last-analysis/{incident_id}")
            trace = debug_resp.json()["workflow_trace"]
            
            agents = ["ingest", "detect", "enrich", "analyze", "critique", "plan_response"]
            
            all_passed = True
            for agent in agents:
                agent_data = trace.get(agent, {})
                status = agent_data.get("status", "unknown")
                icon = "✅" if status == "completed" else "❌"
                console.print(f"  {icon} {agent}: {status}")
                if status != "completed":
                    error = agent_data.get("errors", [])
                    if error:
                        console.print(f"      Error: {error[0] if error else 'Unknown'}")
                    all_passed = False
            
            return all_passed
        except Exception as e:
            console.print(f"  ❌ Agent execution test failed: {e}")
            return False
    
    async def test_3_detection_accuracy(self):
        """Test: Detects known attacks correctly"""
        console.print("\n[bold cyan]Test 3: Detection Accuracy[/bold cyan]")
        
        fixtures = [
            ("brute_force_ssh.json", "Brute Force SSH"),
            ("sql_injection.json", "SQL Injection"),
            ("port_scan.json", "Port Scan"),
            ("normal_traffic.json", "Benign Traffic"),
        ]
        
        results = []
        for fixture_name, attack_type in fixtures:
            fixture_path = Path(f"backend/tests/fixtures/{fixture_name}")
            if not fixture_path.exists():
                console.print(f"  ⚠️  Skipping {attack_type} - fixture not found")
                continue
            
            with open(fixture_path) as f:
                test_data = json.load(f)
            
            try:
                # Ingest and analyze
                resp = await self.client.post(
                    f"{BASE_URL}/ingest/analyze",
                    json=test_data["logs"]
                )
                incident_id = resp.json()["incident_id"]
                
                # Wait for completion
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"  Testing {attack_type}..."),
                    console=console,
                ) as progress:
                    task = progress.add_task("", total=None)
                    
                    while True:
                        await asyncio.sleep(2)
                        resp = await self.client.get(f"{BASE_URL}/incidents/{incident_id}/status")
                        if resp.json()["status"] in ["completed", "failed"]:
                            break
                
                # Validate detection
                expected = test_data["expected_detection"]
                validation_resp = await self.client.get(
                    f"{BASE_URL}/debug/validate-incident/{incident_id}",
                    params={
                        "expected_severity": expected.get("min_severity", "low"),
                        "expected_mitre_techniques": ",".join(expected.get("mitre_techniques", [])),
                        "expected_min_alerts": expected.get("min_alerts", 0),
                    }
                )
                validation = validation_resp.json()
                
                passed = validation["passed"]
                icon = "✅" if passed else "❌"
                console.print(f"  {icon} {attack_type}")
                
                if not passed:
                    for check, result in validation["checks"].items():
                        if not result:
                            console.print(f"      Failed: {check}")
                            console.print(f"      Expected: {expected}")
                            console.print(f"      Got: {validation['actual']}")
                
                results.append(passed)
            except Exception as e:
                console.print(f"  ❌ {attack_type} test failed: {e}")
                results.append(False)
        
        accuracy = sum(results) / len(results) if results else 0
        console.print(f"\n  📊 Accuracy: {accuracy*100:.1f}% ({sum(results)}/{len(results)} passed)")
        return accuracy >= 0.75  # 75% threshold
    
    async def test_4_api_endpoints(self):
        """Test: All API endpoints respond correctly"""
        console.print("\n[bold cyan]Test 4: API Endpoints[/bold cyan]")
        
        endpoints = [
            ("GET", "/health/basic", 200),
            ("GET", "/incidents?limit=10", 200),
            ("GET", "/dashboard/stats", 200),
            ("GET", "/mitre/techniques", 200),
        ]
        
        all_passed = True
        for method, endpoint, expected_status in endpoints:
            try:
                if method == "GET":
                    resp = await self.client.get(f"{BASE_URL}{endpoint}")
                
                passed = resp.status_code == expected_status
                icon = "✅" if passed else "❌"
                console.print(f"  {icon} {method} {endpoint}: {resp.status_code}")
                
                if not passed:
                    all_passed = False
            except Exception as e:
                console.print(f"  ❌ {method} {endpoint}: {str(e)}")
                all_passed = False
        
        return all_passed
    
    async def test_5_performance(self):
        """Test: System meets performance requirements"""
        console.print("\n[bold cyan]Test 5: Performance[/bold cyan]")
        
        try:
            # Test dashboard load time
            start = time.time()
            await self.client.get(f"{BASE_URL}/dashboard/stats")
            dashboard_time = time.time() - start
            
            # Test analysis time
            fixture = Path("backend/tests/fixtures/brute_force_ssh.json")
            with open(fixture) as f:
                test_data = json.load(f)
            
            start = time.time()
            resp = await self.client.post(
                f"{BASE_URL}/ingest/analyze",
                json=test_data["logs"]
            )
            incident_id = resp.json()["incident_id"]
            
            while True:
                await asyncio.sleep(1)
                resp = await self.client.get(f"{BASE_URL}/incidents/{incident_id}/status")
                if resp.json()["status"] == "completed":
                    break
            
            analysis_time = time.time() - start
            
            benchmarks = {
                "Dashboard Load": (dashboard_time, 3.0, "seconds"),
                "Full Analysis": (analysis_time, 90.0, "seconds"),
            }
            
            all_passed = True
            for metric, (actual, threshold, unit) in benchmarks.items():
                passed = actual <= threshold
                icon = "✅" if passed else "❌"
                console.print(f"  {icon} {metric}: {actual:.2f}{unit} (threshold: {threshold}{unit})")
                if not passed:
                    all_passed = False
            
            return all_passed
        except Exception as e:
            console.print(f"  ❌ Performance test failed: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all tests and generate report"""
        console.print(Panel.fit(
            "[bold cyan]AI SOC ANALYST - SYSTEM TEST SUITE[/bold cyan]\n"
            "[dim]Comprehensive validation of all system features[/dim]",
            border_style="cyan"
        ))
        
        tests = [
            self.test_1_health_checks,
            self.test_2_agent_execution,
            self.test_3_detection_accuracy,
            self.test_4_api_endpoints,
            self.test_5_performance,
        ]
        
        results = []
        for test_func in tests:
            try:
                result = await test_func()
                results.append((test_func.__doc__.replace("Test: ", ""), result))
            except Exception as e:
                console.print(f"[red]❌ Test failed with exception: {e}[/red]")
                results.append((test_func.__doc__.replace("Test: ", ""), False))
        
        # Summary table
        console.print("\n[bold]Test Summary[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Test", style="dim", width=40)
        table.add_column("Result", justify="center")
        
        for test_name, passed in results:
            table.add_row(
                test_name,
                "[green]✅ PASS[/green]" if passed else "[red]❌ FAIL[/red]"
            )
        
        console.print(table)
        
        # Overall result
        total_passed = sum(1 for _, p in results if p)
        total_tests = len(results)
        
        if total_passed == total_tests:
            console.print(f"\n[bold green]🎉 ALL TESTS PASSED ({total_passed}/{total_tests})[/bold green]")
        else:
            console.print(f"\n[bold red]❌ SOME TESTS FAILED ({total_passed}/{total_tests} passed)[/bold red]")
        
        await self.client.aclose()
        return total_passed == total_tests


if __name__ == "__main__":
    tester = SystemTester()
    success = asyncio.run(tester.run_all_tests())
    exit(0 if success else 1)

