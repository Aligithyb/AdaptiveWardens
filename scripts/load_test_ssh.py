#!/usr/bin/env python3
import asyncio
import asyncssh
import time
import argparse
import logging
import random
import statistics
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("load-test")

class Metrics:
    def __init__(self):
        self.successes = 0
        self.failures = 0
        self.latencies = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

metrics = Metrics()

async def attack_session(host, port, username, password, session_idx):
    start = time.time()
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            host, port=port, username=username, password=password, known_hosts=None
        ), timeout=10.0)
        
        async with conn.create_process("bash") as process:
            await asyncio.sleep(0.5)
            commands = ["whoami", "pwd", "ls -la /var/log", "cat /etc/passwd", "exit"]
            
            for cmd in commands:
                process.stdin.write(cmd + "\n")
                await asyncio.sleep(random.uniform(0.1, 0.4))
            
        conn.close()
        latency = time.time() - start
        metrics.latencies.append(latency)
        metrics.successes += 1
        return True
    except asyncio.TimeoutError:
        logger.error(f"[Session {session_idx}] Timeout")
        metrics.failures += 1
        return False
    except Exception as e:
        logger.error(f"[Session {session_idx}] Failed: {e}")
        metrics.failures += 1
        return False

async def main(args):
    logger.info(f"Starting load test on {args.host}:{args.port} with {args.concurrency} concurrent tasks.")
    
    tasks = []
    metrics.start_time = time.time()
    
    for i in range(args.total):
        tasks.append(attack_session(args.host, args.port, "root", "root123", i))
        
        if len(tasks) >= args.concurrency:
            await asyncio.gather(*tasks)
            tasks = []
    
    if tasks:
        await asyncio.gather(*tasks)
        
    metrics.end_time = time.time()
    duration = metrics.end_time - metrics.start_time
    
    rps = args.total / duration if duration > 0 else 0
    avg_latency = statistics.mean(metrics.latencies) if metrics.latencies else 0
    p95_latency = statistics.quantiles(metrics.latencies, n=100)[94] if len(metrics.latencies) > 1 else avg_latency
    failure_rate = (metrics.failures / args.total) * 100
    
    report = f"""# Performance Metrics Report

## Test Configuration
- **Target**: {args.host}:{args.port}
- **Total Requests**: {args.total}
- **Max Concurrency**: {args.concurrency}

## Results
- **Duration**: {duration:.2f} seconds
- **Requests Per Second (RPS)**: {rps:.2f}
- **Successful Sessions**: {metrics.successes}
- **Failed Sessions**: {metrics.failures}
- **Failure Rate**: {failure_rate:.2f}%

## Latency
- **Average Latency**: {avg_latency:.2f}s
- **P95 Latency**: {p95_latency:.2f}s
"""
    
    print(report)
    
    os.makedirs("docs", exist_ok=True)
    with open("docs/performance.md", "w") as f:
        f.write(report)
    logger.info("Saved performance metrics to docs/performance.md")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Honeypot Load Tester")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=2222, help="Target port")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent connections")
    parser.add_argument("-n", "--total", type=int, default=50, help="Total connections to make")
    args = parser.parse_args()
    
    asyncio.run(main(args))
