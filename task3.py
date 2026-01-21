#!/usr/bin/env python3
"""
Task 3: Performance Comparison - RSA vs AES

This script performs performance comparison between public key (RSA) and 
symmetric key (AES) algorithms using OpenSSL speed benchmarks.

It runs:
- openssl speed RSA
- openssl speed AES

And generates two graphs:
1. Block size vs. throughput for various AES key sizes
2. RSA key size vs. throughput for each RSA function (sign, verify, etc.)
"""

import subprocess
import re
import argparse
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple
import sys
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def benchmark_aes_custom(block_sizes: List[int], key_sizes: List[int] = [128, 192, 256], 
                         duration: float = 2.0) -> Dict[str, Dict[int, float]]:
    """
    Custom AES benchmark using Python's cryptography library.
    Tests AES with specified block sizes and key sizes.
    
    Args:
        block_sizes: List of block sizes (in bytes) to test
        key_sizes: List of AES key sizes in bits (default: [128, 192, 256])
        duration: Duration in seconds to run each test (default: 2.0)
    
    Returns:
        Dictionary mapping cipher type (e.g., 'aes-128-cbc') to dict of block_size -> throughput (ops/sec)
    """
    aes_data = {}
    
    print(f"Running custom AES benchmark for {len(block_sizes)} block sizes...")
    print(f"Each test will run for {duration} seconds...")
    
    for key_size in key_sizes:
        key = get_random_bytes(key_size // 8)
        cipher_name = f'aes-{key_size}-cbc'
        throughputs = {}
        
        for block_size in block_sizes:
            # Pad data to multiple of 16 bytes (AES block size) for CBC mode
            # For benchmarking, we ensure data is a multiple of 16 bytes
            if block_size % 16 != 0:
                pad_len = 16 - (block_size % 16)
                padded_size = block_size + pad_len
            else:
                padded_size = block_size
            data = get_random_bytes(padded_size)
            
            # Warm-up: run a few operations
            for _ in range(10):
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher.encrypt(data)
            
            # Benchmark: count operations in the specified duration
            operations = 0
            start_time = time.time()
            
            while time.time() - start_time < duration:
                iv = get_random_bytes(16)  # New IV for each encryption (CBC requirement)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                cipher.encrypt(data)
                operations += 1
            
            elapsed = time.time() - start_time
            throughput = operations / elapsed if elapsed > 0 else 0
            throughputs[block_size] = throughput
            
            print(f"  {cipher_name} @ {block_size} bytes: {throughput:,.0f} ops/sec", end='\r')
        
        print()  # New line after each key size
        aes_data[cipher_name] = throughputs
    
    return aes_data


def run_openssl_speed(command: str) -> str:
    """
    Run OpenSSL speed command and return output.
    
    Args:
        command: The OpenSSL speed command (e.g., "openssl speed RSA" or "openssl speed AES")
    
    Returns:
        The stdout output from the command
    """
    try:
        # Split command for subprocess
        cmd_parts = command.split()
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # 5 minute timeout
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: openssl not found. Please install OpenSSL.")
        sys.exit(1)


def parse_aes_output(output: str) -> Dict[str, Dict[int, float]]:
    """
    Parse OpenSSL AES speed output.
    
    Format example:
    type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
    aes-128-cbc     123456.78    234567.89   345678.90   456789.01    567890.12    678901.23 k
    aes-192-cbc     98765.43     87654.32    76543.21    65432.10     54321.09     43210.98 k
    aes-256-cbc     54321.09     43210.98    32109.87    21098.76     10987.65     9876.54 k
    
    Returns:
        Dictionary mapping cipher type to dict of block_size -> throughput (in operations/sec)
    """
    lines = output.strip().split('\n')
    aes_data = {}
    
    # Find header line
    header_idx = None
    for i, line in enumerate(lines):
        if '16 bytes' in line.lower() and '64 bytes' in line.lower():
            header_idx = i
            break
    
    if header_idx is None:
        raise ValueError("Could not find header in AES output")
    
    # Parse block sizes from header
    header_line = lines[header_idx]
    block_sizes = []
    for match in re.finditer(r'(\d+)\s+bytes', header_line):
        block_sizes.append(int(match.group(1)))
    
    # Parse data lines (look for aes-*-cbc or aes-*-ecb patterns)
    # LibreSSL format: "aes-128 cbc     424326.64k   437226.52k   ..."
    for i in range(header_idx + 1, len(lines)):
        line = lines[i].strip()
        if not line or line.startswith('OpenSSL') or line.startswith('LibreSSL'):
            continue
        
        # Match AES cipher names (e.g., "aes-128 cbc", "aes-256 ecb")
        # LibreSSL uses spaces: "aes-128 cbc" instead of "aes-128-cbc"
        aes_match = re.match(r'(aes-\d+)\s+(cbc|ecb|gcm|ctr)\s+(.+)', line)
        if aes_match:
            key_size = aes_match.group(1)  # e.g., "aes-128"
            mode = aes_match.group(2)      # e.g., "cbc"
            cipher_name = f"{key_size}-{mode}"  # Normalize to "aes-128-cbc"
            data_values = aes_match.group(3).split()
            
            # Extract throughput values (values have 'k' suffix: "424326.64k")
            throughputs = {}
            for j, size in enumerate(block_sizes):
                if j < len(data_values):
                    # Remove non-numeric characters and convert
                    val_str = re.sub(r'[^\d.]', '', data_values[j])
                    if val_str:
                        throughput = float(val_str)
                        # Check if there's a multiplier (k, m, etc.)
                        # Note: 'k' in LibreSSL means 1000, not 1024
                        if 'k' in data_values[j].lower():
                            throughput *= 1000
                        elif 'm' in data_values[j].lower():
                            throughput *= 1000000
                        throughputs[size] = throughput
            
            if throughputs:
                aes_data[cipher_name] = throughputs
    
    return aes_data


def parse_rsa_output(output: str) -> Dict[str, Dict[int, float]]:
    """
    Parse OpenSSL RSA speed output.
    
    Format example:
    sign    verify    sign/s verify/s
    rsa 512 bits   0.000123s   0.000012s   8130.1  83333.3
    rsa 1024 bits  0.000456s   0.000045s   2192.9  22222.2
    rsa 2048 bits  0.001789s   0.000123s    558.9   8130.1
    rsa 4096 bits  0.006789s   0.000456s    147.3   2192.9
    
    Returns:
        Dictionary mapping operation type to dict of key_size -> throughput (ops/sec)
    """
    lines = output.strip().split('\n')
    rsa_data = {}
    
    # Find header line (format: "                  sign    verify    sign/s verify/s")
    header_idx = None
    for i, line in enumerate(lines):
        if 'sign' in line.lower() and 'verify' in line.lower() and 'sign/s' in line.lower():
            header_idx = i
            break
    
    if header_idx is None:
        raise ValueError("Could not find header in RSA output")
    
    # Parse data lines
    # LibreSSL format: "rsa  512 bits 0.000098s 0.000002s  10205.6 401264.6"
    sign_data = {}
    verify_data = {}
    
    for i in range(header_idx + 1, len(lines)):
        line = lines[i].strip()
        if not line or line.startswith('OpenSSL') or line.startswith('LibreSSL'):
            continue
        
        # Match RSA key size lines - more flexible regex to handle variable spacing
        # Format: "rsa  512 bits 0.000098s 0.000002s  10205.6 401264.6"
        rsa_match = re.match(r'rsa\s+(\d+)\s+bits\s+[\d.]+\w\s+[\d.]+\w\s+([\d.]+)\s+([\d.]+)', line)
        if rsa_match:
            key_size = int(rsa_match.group(1))
            sign_throughput = float(rsa_match.group(2))
            verify_throughput = float(rsa_match.group(3))
            
            sign_data[key_size] = sign_throughput
            verify_data[key_size] = verify_throughput
    
    if sign_data:
        rsa_data['sign'] = sign_data
    if verify_data:
        rsa_data['verify'] = verify_data
    
    return rsa_data


def plot_aes_results(aes_data: Dict[str, Dict[int, float]], show_plot: bool = True):
    """
    Plot AES block size vs. throughput for various key sizes.
    
    Args:
        aes_data: Dictionary from parse_aes_output()
        show_plot: If True, display the plot interactively. If False, only save.
    """
    plt.figure(figsize=(12, 8))
    
    # Sort cipher names by key size for consistent legend
    sorted_ciphers = sorted(aes_data.keys(), key=lambda x: int(re.search(r'\d+', x).group()))
    
    for cipher_name in sorted_ciphers:
        data = aes_data[cipher_name]
        block_sizes = sorted(data.keys())
        # Convert operations/sec to Mb/s: (ops/sec × block_size_bytes × 8 bits/byte) / 1,000,000
        throughputs = [(data[size] * size * 8) / 1_000_000 for size in block_sizes]
        
        # Extract key size and mode for label
        key_match = re.search(r'aes-(\d+)-(cbc|ecb|gcm)', cipher_name)
        if key_match:
            key_size = key_match.group(1)
            mode = key_match.group(2).upper()
            label = f'AES-{key_size}-{mode}'
        else:
            label = cipher_name
        
        plt.plot(block_sizes, throughputs, marker='o', linewidth=2, markersize=8, label=label)
    
    plt.xlabel('Block Size (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (Mb/s)', fontsize=12, fontweight='bold')
    plt.title('AES Performance: Block Size vs. Throughput', fontsize=14, fontweight='bold')
    plt.legend(loc='best', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)
    plt.yscale('log')
    plt.ylim(bottom=1)  # Start y-axis scale at 10^0 (1)
    plt.tight_layout()
    
    # Save figure
    output_file = 'aes_performance.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"AES performance graph saved to: {output_file}")
    
    if show_plot:
        plt.show()
    else:
        plt.close()


def plot_rsa_results(rsa_data: Dict[str, Dict[int, float]], show_plot: bool = True):
    """
    Plot RSA key size vs. throughput for each RSA function.
    
    Args:
        rsa_data: Dictionary from parse_rsa_output()
        show_plot: If True, display the plot interactively. If False, only save.
    """
    plt.figure(figsize=(12, 8))
    
    for operation in sorted(rsa_data.keys()):
        data = rsa_data[operation]
        key_sizes = sorted(data.keys())
        throughputs = [data[size] for size in key_sizes]
        
        plt.plot(key_sizes, throughputs, marker='s', linewidth=2, markersize=8, 
                label=f'RSA {operation.capitalize()}')
    
    plt.xlabel('RSA Key Size (bits)', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (operations/sec)', fontsize=12, fontweight='bold')
    plt.title('RSA Performance: Key Size vs. Throughput', fontsize=14, fontweight='bold')
    plt.legend(loc='best', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.xscale('log', base=2)
    plt.yscale('log')
    plt.tight_layout()
    
    # Save figure
    output_file = 'rsa_performance.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"RSA performance graph saved to: {output_file}")
    
    if show_plot:
        plt.show()
    else:
        plt.close()


def main():
    """
    Main function to run OpenSSL speed tests and generate graphs.
    """
    parser = argparse.ArgumentParser(description="Task 3: RSA vs AES Performance Comparison")
    parser.add_argument('--no-show', action='store_true', 
                       help='Save graphs without displaying them (useful for non-interactive environments)')
    args = parser.parse_args()
    
    show_plot = not args.no_show
    
    print("=" * 60)
    print("Task 3: RSA vs AES Performance Comparison")
    print("=" * 60)
    
    # Run custom AES benchmark with 30 different block sizes
    print("\n[1/2] Running custom AES benchmark with 30 block sizes...")
    print("This may take a few minutes...")
    
    # Generate 30 block sizes: powers of 2 and some intermediate values
    # Covering range from 16 bytes (AES block size) to 4096 bytes
    block_sizes = [
        16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256,
        320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048,
        2560, 3072, 4096
    ]
    # Ensure exactly 30 block sizes
    assert len(block_sizes) == 30, f"Expected 30 block sizes, got {len(block_sizes)}"
    
    print(f"Testing block sizes: {block_sizes}")
    
    # Use custom benchmark function instead of OpenSSL (since -bytes option not supported)
    aes_data = benchmark_aes_custom(block_sizes, key_sizes=[128, 192, 256], duration=2.0)
    print("AES benchmark complete.")
    
    print(f"\nFound {len(aes_data)} AES cipher configurations.")
    for cipher, data in aes_data.items():
        print(f"  - {cipher}: {len(data)} block sizes")
    
    # # Run OpenSSL speed RSA
    # print("\n[1/2] Running OpenSSL speed RSA...")
    # print("This may take a few minutes...")
    # rsa_output = run_openssl_speed("openssl speed rsa")
    # print("RSA benchmark complete.")
    
    # # Parse RSA results
    # print("\n[2/2] Parsing RSA results...")
    # rsa_data = parse_rsa_output(rsa_output)
    # print(f"Found {len(rsa_data)} RSA operation types.")
    # for op, data in rsa_data.items():
    #     print(f"  - {op}: {len(data)} key sizes")
    
    # Initialize rsa_data as empty dict since RSA testing is commented out
    rsa_data = {}
    
    # Generate graphs
    print("\n" + "=" * 60)
    print("Generating performance graphs...")
    print("=" * 60)
    
    if aes_data:
        print("\nGenerating AES performance graph...")
        plot_aes_results(aes_data, show_plot=show_plot)
    else:
        print("Warning: No AES data to plot.")
    
    if rsa_data:
        print("\nGenerating RSA performance graph...")
        plot_rsa_results(rsa_data, show_plot=show_plot)
    else:
        print("Warning: No RSA data to plot.")
    
    print("\n" + "=" * 60)
    print("Task 3 complete!")
    print("=" * 60)
    
    # Print summary statistics
    print("\nSummary Statistics:")
    print("\nAES Results:")
    for cipher, data in sorted(aes_data.items()):
        max_throughput = max(data.values())
        max_size = max(k for k, v in data.items() if v == max_throughput)
        print(f"  {cipher}: Max throughput {max_throughput:,.0f} ops/sec at {max_size} bytes")
    
    print("\nRSA Results:")
    for op, data in sorted(rsa_data.items()):
        for key_size in sorted(data.keys()):
            print(f"  {op} ({key_size} bits): {data[key_size]:,.2f} ops/sec")


if __name__ == "__main__":
    main()
