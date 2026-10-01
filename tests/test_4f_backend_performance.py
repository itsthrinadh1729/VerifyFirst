import time
import requests
import statistics
import concurrent.futures

BASE_URL = "http://localhost:8000/api/v1"

def measure_endpoint(endpoint, payload, iterations=100):
    latencies = []
    successes = 0
    failures = 0
    
    url = f"{BASE_URL}/{endpoint}"
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                successes += 1
            else:
                failures += 1
        except Exception:
            failures += 1
        latencies.append((time.perf_counter() - start) * 1000)
        
    return {
        "endpoint": endpoint,
        "count": iterations,
        "success": successes,
        "failure": failures,
        "min": min(latencies),
        "max": max(latencies),
        "avg": statistics.mean(latencies)
    }

def run_stress():
    print("--- 4F.5 Backend API Performance ---")
    
    res = measure_endpoint("analyze", {"url": "https://example.com/safe", "chatId": "perf1"})
    print(res)
    
    res = measure_endpoint("analyze-file", {"filename": "document.pdf", "chatId": "perf2"})
    print(res)
    
    res = measure_endpoint("analyze-message", {"message": "Hello world", "chatId": "perf3"})
    print(res)
    
    print("\n--- 4F.6 Message-specific Performance (Length Stress) ---")
    lengths = [10, 100, 500, 1000, 4000]
    for length in lengths:
        msg = "A" * length
        res = measure_endpoint("analyze-message", {"message": msg, "chatId": f"len{length}"}, iterations=20)
        print(f"Length {length}: {res['avg']:.2f} ms avg")

if __name__ == "__main__":
    run_stress()
