#!/usr/bin/env python3
"""
Concurrent Security Analyzer
Runs Nmap_analyzer.py for efficient security auditing.
Analyzes Nmap scan results for the first target.
"""

import sys
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional
import subprocess


class ConcurrentSecurityAnalyzer:
    """Manages execution of security analysis tools."""
    
    def __init__(self, nmap_xml_file: str, output_dir: str = "./security_reports"):
        """
        Initialize the analyzer.
        
        Args:
            nmap_xml_file: Path to Nmap XML output file
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
    
    def run_nmap_analyzer(self) -> bool:
        """
        Run the Nmap analyzer.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            print("[*] Starting Nmap Analyzer...")
            
            # Check if Nmap XML file exists
            if not os.path.exists(self.nmap_xml_file):
                error_msg = f"[-] Nmap XML file not found: {self.nmap_xml_file}"
                print(error_msg)
                self.results['errors'].append(error_msg)
                return False
            
            # Import and run Nmap analyzer
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from Nmap_analyzer import parse_nmap_xml, generate_report, display_summary
            
            # Parse the XML file
            parsed_data = parse_nmap_xml(self.nmap_xml_file)
            
            # Display summary
            display_summary(parsed_data)
            
            # Generate report in output directory
            report_path = os.path.join(self.output_dir, "nmap_security_report.md")
            generate_report(parsed_data, report_path)
            
            self.results['nmap_analyzer'] = report_path
            print(f"[+] Nmap Analyzer completed: {report_path}")
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
        print("Usage: python concurrent_security_analyzer.py <nmap_xml_file> [output_directory]")
        print("\nExample:")
        print("  python concurrent_security_analyzer.py scan.xml")
        print("  python concurrent_security_analyzer.py scan.xml ./reports")
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
