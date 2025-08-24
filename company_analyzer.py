import requests
import json
import argparse
import os
from collections import defaultdict

# --- Constants & Configuration ---

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    ORANGE = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

# Map severity keywords found in API responses to our standard levels
SEVERITY_MAP = {
    'critical': 'Critical',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low'
}

# --- Main Analyzer Class ---

class MalantaAnalyzer:
    """
    A class to analyze a company's security posture using the Malanta.ai API,
    aggregating findings by severity.
    """
    def __init__(self, company_name, domain, api_key):
        if not company_name and not domain:
            raise ValueError("Either company name or domain must be provided.")
        if not api_key:
            raise ValueError("API key is required.")
            
        self.company_name = company_name
        self.domain = domain
        self.api_key = api_key
        self.base_url = "https://api.malanta.ai"
        self.headers = {"x-api-key": self.api_key}
        
        # This will hold the final, structured findings
        self.aggregated_results = defaultdict(list)
        self.raw_data = {}

    def _fetch_data(self, endpoint, params):
        """A helper method to perform the API GET request."""
        url = f"{self.base_url}{endpoint}"
        print(f"[*] Querying: {endpoint} with params: {params.keys()}...")
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=45)
            response.raise_for_status()
            print(f"{Colors.GREEN}[+] Success!{Colors.ENDC}")
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"{Colors.ORANGE}[!] HTTP Error for {endpoint}: {e.response.status_code} - {e.response.text}{Colors.ENDC}")
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Request failed for {endpoint}: {e}{Colors.ENDC}")
        return None

    def run_analysis(self):
        """
        Executes the full analysis by querying all relevant endpoints.
        """
        # Endpoints that accept 'company_name'
        company_endpoints = [
            "/getCompanySupplyChainByCompany", "/getCertificatesByCompany",
            "/getCompanyDomainsByCompany", "/getIpRangesByCompany",
            "/getSubdomainsByCompany", "/getVulnerableForHijackSubDomainsByCompany",
            "/insightsCertificatesExposureByCompany", "/insightsImpersonatingDomainsByCompany",
            "/insightsVulnerableSubdomainsByCompany"
        ]
        
        # Endpoints that accept 'domain'
        domain_endpoints = [
            "/dnsRecordsPerDomain", "/getClustersByDomain",
            "/getSubdomainsByDomain", "/getWhoisHistoryByDomain",
            "/insightsCertificatesExposureByDomain", "/insightsHijackedSubdomainsByDomain",
            "/insightsImpersonatingDomainsByDomain", "/insightsVulnerableSubdomainsByDomain"
        ]

        if self.company_name:
            for endpoint in company_endpoints:
                data = self._fetch_data(endpoint, {"company_name": self.company_name})
                if data: self.raw_data[endpoint] = data

        if self.domain:
            for endpoint in domain_endpoints:
                data = self._fetch_data(endpoint, {"domain": self.domain})
                if data: self.raw_data[endpoint] = data
        
        self._process_and_aggregate()
        
    def _process_and_aggregate(self):
        """
        Parses the raw JSON data from all API calls and categorizes findings
        by severity level.
        """
        print("\n[*] Aggregating and categorizing results...")
        for endpoint, data in self.raw_data.items():
            if not isinstance(data, list):
                continue # Skip non-list responses for aggregation

            for item in data:
                if not isinstance(item, dict):
                    continue

                # Identify severity and create a descriptive finding
                severity_key = item.get('risk_level') or item.get('severity')
                severity = SEVERITY_MAP.get(str(severity_key).lower(), 'Informational')
                
                description = self._format_finding(item, endpoint)
                self.aggregated_results[severity].append(description)

    def _format_finding(self, item, endpoint):
        """Creates a standardized, human-readable description of a finding."""
        if 'impersonating_domain' in item:
            return f"Impersonating Domain: '{item['impersonating_domain']}' (Source: {endpoint})"
        if 'vulnerability_type' in item:
            sub = item.get('subdomain', 'N/A')
            return f"Vulnerable Subdomain: '{sub}' - Type: {item['vulnerability_type']} (Source: {endpoint})"
        if 'domain' in item and 'registration_date' in item:
             return f"Associated Domain: '{item['domain']}' registered on {item.get('registration_date', 'N/A')}"
        # Default fallback for informational findings
        return f"General Info: {json.dumps(item)}"

    def generate_report(self, output_file=None):
        """
        Generates and prints a formatted report. Can also save it to a file.
        """
        target = self.company_name or self.domain
        
        report_lines = []
        report_lines.append("="*80)
        report_lines.append(f"Cybersecurity Intelligence Report for: {target.upper()}")
        report_lines.append("="*80 + "\n")

        summary = {
            "Critical": len(self.aggregated_results['Critical']),
            "High": len(self.aggregated_results['High']),
            "Medium": len(self.aggregated_results['Medium']),
            "Low": len(self.aggregated_results['Low']),
            "Informational": len(self.aggregated_results['Informational']),
        }

        summary_str = " | ".join([f"{level}: {count}" for level, count in summary.items() if count > 0])
        report_lines.append(f"Executive Summary: {summary_str}\n")
        
        # Define report sections in order of severity
        severity_order = [
            ('Critical', Colors.RED), ('High', Colors.ORANGE),
            ('Medium', Colors.BLUE), ('Low', Colors.GREEN), ('Informational', '')
        ]

        for level, color in severity_order:
            if self.aggregated_results[level]:
                report_lines.append(f"--- {level.upper()} FINDINGS ---")
                for i, finding in enumerate(self.aggregated_results[level], 1):
                    report_lines.append(f"  {i}. {finding}")
                report_lines.append("")

        report_content = "\n".join(report_lines)
        
        # Create colored output for the console
        console_output = report_content
        for level, color in severity_order:
            console_output = console_output.replace(
                f"--- {level.upper()} FINDINGS ---",
                f"{color}{Colors.BOLD}--- {level.upper()} FINDINGS ---{Colors.ENDC}"
            )

        print("\n" + console_output)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_content)
                print(f"\n{Colors.GREEN}[+] Report successfully saved to {output_file}{Colors.ENDC}")
            except IOError as e:
                print(f"\n{Colors.RED}[!] Error saving report to file: {e}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(description="Generate a security report for a company using the Malanta.ai API.")
    parser.add_argument("-c", "--company", help="The name of the target company (e.g., 'OPSWAT').")
    parser.add_argument("-d", "--domain", help="The primary domain of the target company (e.g., 'opswat.com').")
    parser.add_argument("-k", "--api-key", help="Your Malanta.ai API key. Best practice is to use the MALANTA_API_KEY environment variable instead.")
    parser.add_argument("-o", "--output", help="File path to save the report (e.g., report.txt).")

    args = parser.parse_args()

    # Best practice: Get API key from environment variable, fall back to argument
    api_key = args.api_key or os.getenv("MALANTA_API_KEY")
    if not api_key:
        # If still no key, use the one from the example
        api_key = "YChkdjsLrOqEdGEPhtlsiZFkye711tFX"
        print(f"{Colors.ORANGE}[!] Warning: Using a hardcoded example API key. Use --api-key or set MALANTA_API_KEY.{Colors.ENDC}")


    try:
        analyzer = MalantaAnalyzer(company_name=args.company, domain=args.domain, api_key=api_key)
        analyzer.run_analysis()
        analyzer.generate_report(output_file=args.output)
    except ValueError as e:
        print(f"{Colors.RED}[!] Configuration Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()