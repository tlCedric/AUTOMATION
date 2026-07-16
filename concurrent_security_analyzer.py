#!/usr/bin/env python3
"""
Concurrent Security Analyzer
Runs Nmap_analyzer.py for efficient security auditing.
Analyzes Nmap scan results for the first target.

This updated version will accept any file that contains port numbers (for example
lines like "80/tcp open" or other text containing port/protocol pairs) and
will generate a simple report from those ports even if the file is not an XML
Nmap report. If the input is an Nmap XML file, the existing Nmap_analyzer
functions are used.
"""

import sys
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional, List, Dict
import subprocess
import re


class ConcurrentSecurityAnalyzer:
    """Manages execution of security analysis tools."""
    
    def __init__(self, nmap_xml_file: str, output_dir: str = "./security_reports"):
        """
        Initialize the analyzer.
        
        Args:
            nmap_xml_file: Path to Nmap XML output file or any file containing port numbers
            output_dir: Directory to store all generated reports
        """
        self.nmap_xml_file = nmap_xml_file
        self.output_dir = output_dir
        self.start_time = None
        self.end_time = None
        self.results = {
            'nmap_analyzer': None,
            'errors': []
        }
        
        # Create output directory if it doesn't exist
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def _read_file_head(self, path: str, size: int = 4096) -> str:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(size)
        except Exception:
            return ""

    def _is_xml(self, head: str) -> bool:
        # Heuristic: XML declaration or nmaprun tag
        head_strip = head.lstrip()
        return head_strip.startswith('<?xml') or '<nmaprun' in head_strip.lower()

    def _extract_ports_from_text(self, text: str) -> List[Dict[str, str]]:
        """
        Extract port/protocol occurrences from arbitrary text.
        Looks for patterns like '80/tcp', '53/udp', or 'port 22' and returns a
        list of dicts with port and proto (when available).
        """
        ports = []
        seen = set()

        # Pattern for explicit port/proto like 80/tcp or 53/udp
        for m in re.finditer(r"\b(\d{1,5})\/(tcp|udp)\b", text, flags=re.IGNORECASE):
            port = int(m.group(1))
            proto = m.group(2).lower()
            key = (port, proto)
            if key not in seen:
                seen.add(key)
                ports.append({'port': port, 'proto': proto, 'snippet': m.group(0)})

        # Pattern for 'port 22' or 'port:22'
        for m in re.finditer(r"\bport[:\s]*?(\d{1,5})\b", text, flags=re.IGNORECASE):
            port = int(m.group(1))
            key = (port, None)
            if key not in seen:
                seen.add(key)
                ports.append({'port': port, 'proto': 'unknown', 'snippet': m.group(0)})

        # Pattern for common 'open ssh 22/tcp' style: capture standalone port numbers
        # but avoid capturing large unrelated numbers by limiting to 1-5 digits and
        # checking surrounding context for typical separators.
        for m in re.finditer(r"(?:(?:\b|:))(?<!/)(\d{1,5})(?:\b)", text):
            port = int(m.group(1))
            if 0 < port <= 65535:
                # skip if already seen by explicit pattern
                if any(p['port'] == port for p in ports):
                    continue
                # only add if nearby words suggest ports (open, tcp, udp, port)
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                ctx = text[start:end].lower()
                if any(k in ctx for k in ('tcp', 'udp', 'port', 'open', '/tcp', '/udp')):
                    ports.append({'port': port, 'proto': 'unknown', 'snippet': m.group(0)})

        return ports

    def _generate_simple_report(self, parsed_ports: List[Dict[str, str]], report_path: str, source_file: str) -> None:
        """
        Generate a simple markdown report listing all discovered ports.
        """
        lines = []
        lines.append(f"# Simple Port Report for {os.path.basename(source_file)}")
        lines.append("")
        lines.append(f"Generated: {datetime.utcnow().isoformat()} UTC")
        lines.append("")
        lines.append("## Discovered Ports")
        lines.append("")

        if not parsed_ports:
            lines.append("No port-like patterns were detected in the input file.")
        else:
            lines.append("| Port | Protocol | Example Snippet |")
            lines.append("|------|----------|-----------------|")
            for p in parsed_ports:
                port = p.get('port')
                proto = p.get('proto', 'unknown')
                snippet = (p.get('snippet') or '').replace('\n', ' ')[:120]
                lines.append(f"| {port} | {proto} | {snippet} |")

        with open(report_path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines))

    def _display_simple_summary(self, parsed_ports: List[Dict[str, str]]):
        print("[+] Simple port extraction summary:")
        if not parsed_ports:
            print("    No ports found in the provided file.")
        else:
            for p in parsed_ports:
                print(f"    - Port {p['port']} ({p.get('proto', 'unknown')}) — example: {p.get('snippet')}")

    def run_nmap_analyzer(self) -> bool:
        """
        Run the Nmap analyzer.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            print("[*] Starting Nmap Analyzer...")
            
            # Check if file exists
            if not os.path.exists(self.nmap_xml_file):
                error_msg = f"[-] Input file not found: {self.nmap_xml_file}"
                print(error_msg)
                self.results['errors'].append(error_msg)
                return False

            # Read head of file to decide whether it's XML or plain text
            head = self._read_file_head(self.nmap_xml_file, size=8192)
            is_xml = self._is_xml(head)

            if is_xml:
                # Import and run Nmap analyzer on XML input
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                try:
                    from Nmap_analyzer import parse_nmap_xml, generate_report, display_summary
                except Exception as e:
                    error_msg = f"[-] Failed to import Nmap_analyzer: {e}"
                    print(error_msg)
                    self.results['errors'].append(error_msg)
                    return False

                # Parse the XML file
                parsed_data = parse_nmap_xml(self.nmap_xml_file)

                # Display summary
                try:
                    display_summary(parsed_data)
                except Exception:
                    # If the external display_summary fails, ignore and continue
                    pass

                # Generate report in output directory
                report_path = os.path.join(self.output_dir, "nmap_security_report.md")
                try:
                    generate_report(parsed_data, report_path)
                except Exception as e:
                    # If the external generate_report fails, fall back to a simple report
                    print(f"[!] Nmap_analyzer.generate_report failed: {e} — falling back to simple report")
                    # Attempt to extract ports from the XML text as a fallback
                    text = self._read_file_head(self.nmap_xml_file, size=10_000_000)
                    parsed_ports = self._extract_ports_from_text(text)
                    self._generate_simple_report(parsed_ports, report_path, self.nmap_xml_file)

                self.results['nmap_analyzer'] = report_path
                print(f"[+] Nmap Analyzer completed: {report_path}")
                return True

            else:
                # Non-XML file: try to detect port numbers and generate a simple report
                text = ''
                try:
                    with open(self.nmap_xml_file, 'r', encoding='utf-8', errors='ignore') as fh:
                        text = fh.read()
                except Exception as e:
                    error_msg = f"[-] Failed to read input file: {e}"
                    print(error_msg)
                    self.results['errors'].append(error_msg)
                    return False

                parsed_ports = self._extract_ports_from_text(text)
                if not parsed_ports:
                    error_msg = f"[-] No port-like patterns detected in file: {self.nmap_xml_file}"
                    print(error_msg)
                    self.results['errors'].append(error_msg)
                    return False

                # Display simple summary
                self._display_simple_summary(parsed_ports)

                # Generate and save a simple markdown report
                report_path = os.path.join(self.output_dir, "ports_from_input_report.md")
                self._generate_simple_report(parsed_ports, report_path, self.nmap_xml_file)

                self.results['nmap_analyzer'] = report_path
                print(f"[+] Simple port report generated: {report_path}")
                return True

        except Exception as e:
            error_msg = f"[-] Nmap Analyzer error: {str(e)}"
            print(error_msg)
            self.results['errors'].append(error_msg)
            return False
    
    def run(self) -> dict:
        """
        Run the analyzer.
        
        Returns:
            Dictionary containing results and timing information
        """
        self.start_time = datetime.now()
        print(f"\n{'='*70}")
        print(f"SECURITY ANALYZER")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Output Directory: {os.path.abspath(self.output_dir)}")
        print(f"{'='*70}\n")
        
        # Run nmap analyzer
        self.run_nmap_analyzer()
        
        self.end_time = datetime.now()
        
        return self.generate_summary()
    
    def generate_summary(self) -> dict:
        """
        Generate a summary of the analysis results.
        
        Returns:
            Dictionary with summary information
        """
        duration = (self.end_time - self.start_time).total_seconds()
        
        summary = {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': duration,
            'output_directory': os.path.abspath(self.output_dir),
            'nmap_report': self.results['nmap_analyzer'],
            'errors': self.results['errors'],
            'success': len(self.results['errors']) == 0
        }
        
        return summary
    
    def print_summary(self, summary: dict):
        """
        Print a formatted summary of results.
        
        Args:
            summary: Dictionary containing summary information
        """
        print(f"\n{'='*70}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*70}")
        print(f"Start Time:         {summary['start_time']}")
        print(f"End Time:           {summary['end_time']}")
        print(f"Duration:           {summary['duration_seconds']:.2f} seconds")
        print(f"Output Directory:   {summary['output_directory']}")
        print(f"\nGenerated Reports:")
        
        if summary['nmap_report']:
            print(f"  ✓ Nmap Analysis:    {summary['nmap_report']}")
        else:
            print(f"  ✗ Nmap Analysis:    Failed")
        
        if summary['errors']:
            print(f"\nErrors ({len(summary['errors'])}):")
            for error in summary['errors']:
                print(f"  {error}")
        else:
            print(f"\n✓ No errors encountered")
        
        print(f"{'='*70}\n")
    
    def save_summary_json(self, summary: dict) -> str:
        """
        Save summary as JSON file.
        
        Args:
            summary: Dictionary containing summary information
            
        Returns:
            Path to saved JSON file
        """
        import json
        
        summary_file = os.path.join(self.output_dir, "analysis_summary.json")
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        return summary_file


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python concurrent_security_analyzer.py <nmap_xml_file_or_any_file_with_ports> [output_directory]")
        print("\nExample:")
        print("  python concurrent_security_analyzer.py scan.xml")
        print("  python concurrent_security_analyzer.py scan.txt ./reports")
        sys.exit(1)
    
    nmap_xml_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./security_reports"
    
    # Create and run analyzer
    analyzer = ConcurrentSecurityAnalyzer(nmap_xml_file, output_dir)
    summary = analyzer.run()
    
    # Print and save summary
    analyzer.print_summary(summary)
    summary_json = analyzer.save_summary_json(summary)
    print(f"[+] Summary saved to: {summary_json}\n")
    
    # Exit with appropriate code
    sys.exit(0 if summary['success'] else 1)


if __name__ == "__main__":
    main()
