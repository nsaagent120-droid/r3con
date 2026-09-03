#!/usr/bin/env python3
"""
r3con Multi-AI Example
Demonstrate communication with multiple local AI models simultaneously.
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.multi_ai_manager import MultiAIManager


def print_header(title):
    """Print formatted header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def example_1_discover_servers():
    """Example 1: Discover available local AI servers."""
    print_header("Example 1: Server Discovery")
    
    manager = MultiAIManager()
    manager.print_summary()


def example_2_send_analysis():
    """Example 2: Send analysis to all available AIs."""
    print_header("Example 2: Send Analysis to All AIs")
    
    manager = MultiAIManager()
    
    if not manager.available_servers:
        print("[-] No local AI servers available.")
        print("[*] Start a local AI server first:")
        print("    ollama serve")
        return
    
    vulnerable_code = """
    void process_input(char *user_data) {
        char buffer[64];
        strcpy(buffer, user_data);
        printf("Processed: %s\\n", buffer);
    }
    """
    
    prompt = f"Analyze this code for vulnerabilities:\\n{vulnerable_code}"
    
    print("[*] Sending code to all available AI models...\n")
    
    responses = manager.send_to_all(
        prompt=prompt,
        system_prompt="You are a security expert. Analyze for vulnerabilities."
    )
    
    if responses:
        print(f"\n[+] Received {len(responses)} responses")
        for ai_name, response in responses.items():
            print(f"\n[{ai_name}]\n{response[:500]}...")


def example_3_compare_analysis():
    """Example 3: Compare analyses from multiple AIs."""
    print_header("Example 3: Compare & Aggregate AI Responses")
    
    manager = MultiAIManager()
    
    if not manager.available_servers:
        print("[-] No local AI servers available.")
        return
    
    print("[*] Running comparison analysis...\n")
    result = manager.compare_analysis("Found buffer overflow vulnerability")
    print(f"[+] Total responses: {result['total_responses']}")


def main():
    """Run examples."""
    print("""
    r3con Multi-AI Integration Examples
    Communicate with multiple local AI models simultaneously
    """)
    
    print("1. Discover Servers")
    example_1_discover_servers()
    
    print("\n2. Send Analysis")
    example_2_send_analysis()
    
    print("\n3. Compare Responses")
    example_3_compare_analysis()


if __name__ == "__main__":
    main()
