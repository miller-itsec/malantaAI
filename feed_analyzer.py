import argparse
import os
import requests
import xml.etree.ElementTree as ET
import pandas as pd
import concurrent.futures
from tqdm import tqdm
from urllib.parse import urlparse

# --- Constants & Configuration ---
class Colors:
    """Class to hold ANSI color codes for terminal output."""
    RED = '\033[91m'
    ORANGE = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

# Verdicts from the feed that are considered high-confidence ground truth
HIGH_CONFIDENCE_VERDICTS = ['MALICIOUS', 'LIKELY_MALICIOUS']


# --- Main Feed Analyzer Class ---
class FeedAnalyzer:
    """
    Analyzes an XML threat feed and enriches the findings by querying clusters
    to measure the threat discovery value of the Malanta.ai API.
    """
    def __init__(self, feed_file, api_key):
        if not os.path.exists(feed_file):
            raise FileNotFoundError(f"The feed file was not found at: {feed_file}")
        self.feed_file = feed_file
        self.api_key = api_key
        self.base_url = "https://api.malanta.ai"
        self.session = requests.Session()
        self.session.headers.update({"x-api-key": self.api_key})
        self.iocs = []
        self.initial_results = []
        self.newly_discovered_iocs = set()
        self.ignored_clusters = {} # Store {cluster_id: size} for reporting

    def parse_feed(self):
        """Parses the feed, extracting IOCs and their parent report verdicts."""
        print(f"[*] Parsing XML feed: {self.feed_file}")
        unique_iocs = set()
        try:
            ns = {'atom': 'http://www.w3.org/2005/Atom'}
            tree = ET.parse(self.feed_file)
            root = tree.getroot()
            for entry in root.findall('atom:entry', ns):
                content = entry.find('atom:content', ns)
                if content is not None:
                    details = content.find('atom:details', ns)
                    if details is not None:
                        verdict_tag = details.find('atom:verdict', ns)
                        report_verdict = verdict_tag.text.strip() if verdict_tag is not None and verdict_tag.text else 'UNKNOWN'
                        
                        for ioc_type in ['domains', 'ips']:
                            tag_name = 'url' if ioc_type == 'domains' else 'ip'
                            item_tags = details.findall(f'.//atom:iocs/atom:{ioc_type}/atom:value', ns)
                            for value_tag in item_tags:
                                ioc_tag = value_tag.find(f'atom:{tag_name}', ns)
                                if ioc_tag is not None and ioc_tag.text:
                                    raw_value = ioc_tag.text.strip()
                                    clean_value = ''
                                    if ioc_type == 'domains':
                                        if not raw_value.startswith(('http://', 'https://')):
                                            raw_value = 'http://' + raw_value
                                        clean_value = urlparse(raw_value).netloc.split(':')[0]
                                    else:
                                        clean_value = raw_value
                                    if clean_value:
                                        unique_iocs.add((ioc_type[:-1], clean_value, report_verdict))
            
            self.iocs = [{'type': t, 'value': v, 'verdict': verd} for t, v, verd in unique_iocs]
            print(f"{Colors.GREEN}[+] Parsing complete. Found {len(self.iocs)} unique indicators.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[FATAL ERROR] An unexpected error occurred during parsing: {e}{Colors.ENDC}")
            raise

    def _query_single_ioc(self, ioc):
        """Worker for the initial detection phase."""
        ioc_type, ioc_value = ioc['type'], ioc['value']
        endpoint = f"/getClustersBy{ioc_type.capitalize()}"
        result = {'ioc': ioc_value, 'type': ioc_type, 'verdict': ioc['verdict'], 'predicted': 0, 'data': None}
        try:
            response = self.session.get(f"{self.base_url}{endpoint}", params={ioc_type: ioc_value}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    result['predicted'] = 1
                    result['data'] = data
        except requests.exceptions.RequestException: 
            pass
        return result

    def _query_single_cluster(self, cluster_id):
        """Worker for the enrichment phase, returns the cluster ID and its members."""
        try:
            response = self.session.get(f"{self.base_url}/getClustersByClusterId", params={'cluster_id': cluster_id}, timeout=30)
            if response.status_code == 200:
                return (cluster_id, response.json())
        except requests.exceptions.RequestException:
            return (cluster_id, [])
        return (cluster_id, [])

    def run_detection_phase(self, num_threads):
        """Phase 1: Find which IOCs from the feed are known to Malanta.ai."""
        if not self.iocs:
            print(f"{Colors.ORANGE}[!] No IOCs to analyze. Aborting.{Colors.ENDC}")
            return
        print(f"\n--- Phase 1: Detection ---")
        print(f"[*] Querying Malanta.ai for {len(self.iocs)} indicators using {num_threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            self.initial_results = list(tqdm(executor.map(self._query_single_ioc, self.iocs), total=len(self.iocs), desc="Detecting IOCs"))
    
    def run_enrichment_phase(self, num_threads, cluster_threshold):
        """Phase 2: Pivot on detected clusters, ignoring outliers larger than the threshold."""
        print(f"\n--- Phase 2: Enrichment ---")
        original_iocs_set = {ioc['value'] for ioc in self.iocs}
        unique_cluster_ids = {item['cluster_id'] for result in self.initial_results if result.get('predicted') and result.get('data') for item in result['data'] if 'cluster_id' in item}

        if not unique_cluster_ids:
            print(f"{Colors.ORANGE}[!] No clusters found for enrichment. Skipping phase.{Colors.ENDC}")
            return
            
        print(f"[*] Found {len(unique_cluster_ids)} unique clusters. Querying and filtering (threshold > {cluster_threshold})...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            cluster_results = list(tqdm(executor.map(self._query_single_cluster, unique_cluster_ids), total=len(unique_cluster_ids), desc="Enriching Clusters"))
            
            for cluster_id, members in cluster_results:
                cluster_size = len(members)
                # Filtering logic for outlier clusters
                if cluster_size > cluster_threshold:
                    self.ignored_clusters[cluster_id] = cluster_size
                    continue # Skip this large cluster
                
                # Process members of smaller, relevant clusters
                for member in members:
                    ioc_value = member.get('domain_or_child')
                    if ioc_value and ioc_value not in original_iocs_set:
                        self.newly_discovered_iocs.add(ioc_value)
                        
        print(f"{Colors.GREEN}[+] Enrichment complete. Ignored {len(self.ignored_clusters)} large clusters.{Colors.ENDC}")

    def generate_report(self, output_file=None, cluster_threshold=1000):
        """Generates the final, multi-faceted efficacy report."""
        if not self.initial_results:
            print(f"\n{Colors.RED}[!] No results to report on.{Colors.ENDC}")
            return
        
        df = pd.DataFrame(self.initial_results)
        
        def get_examples(dataframe, ioc_type, predicted_status, count=5):
            examples = dataframe[(dataframe['type'] == ioc_type) & (dataframe['predicted'] == predicted_status)]['ioc'].head(count).tolist()
            return examples if examples else ["None"]

        def format_section(title, dataframe):
            if dataframe.empty:
                return [f"\n## {title} ##", "  - No indicators in this category."]
            
            detections = dataframe['predicted'].sum()
            total = len(dataframe)
            rate = (detections / total) if total > 0 else 0.0
            metric_name = "Detection Rate (Recall)" if title.startswith("Efficacy") else "Efficacy Uplift Rate"
            lines = [
                f"\n## {title} ##",
                f"  - Total Indicators in this Category: {total}",
                f"  - Detected by Malanta.ai: {detections}",
                f"  - {metric_name}: {rate:.2%}\n",
                "  --- Examples ---",
                "  Detected Domains: " + ", ".join(get_examples(dataframe, 'domain', 1)),
                "  Missed Domains:   " + ", ".join(get_examples(dataframe, 'domain', 0)),
                "  Detected IPs:     " + ", ".join(get_examples(dataframe, 'ip', 1)),
                "  Missed IPs:       " + ", ".join(get_examples(dataframe, 'ip', 0))
            ]
            return lines

        # --- Build Report Content ---
        report_lines = ["="*80, f"Malanta.ai API Efficacy Report", f"Source Feed: {self.feed_file}", "="*80]
        
        # Section 1: High-Confidence IOCs
        high_conf_df = df[df['verdict'].isin(HIGH_CONFIDENCE_VERDICTS)]
        report_lines.extend(format_section("Efficacy Against High-Confidence IOCs", high_conf_df))
        
        # Section 2: Low-Confidence IOCs
        low_conf_df = df[~df['verdict'].isin(HIGH_CONFIDENCE_VERDICTS)]
        report_lines.extend(format_section("Sandbox Efficacy Uplift (Low-Confidence IOCs)", low_conf_df))
        
        # Section 3: Enrichment
        total_relevant_clusters = len(self.ignored_clusters.keys()) + len(self.ignored_clusters)
        report_lines.extend([
            f"\n## Intelligence Enrichment Summary ##",
            f"  - Cluster Size Threshold: >{cluster_threshold} members (ignored)",
            f"  - Noisy Clusters Ignored: {len(self.ignored_clusters)}",
            f"  - Total New Indicators Discovered: {len(self.newly_discovered_iocs)}",
            f"    (From {total_relevant_clusters - len(self.ignored_clusters)} relevant clusters)\n"
        ])
        if self.newly_discovered_iocs:
            report_lines.append("  --- Examples of New Indicators ---")
            report_lines.extend([f"    - {ioc}" for ioc in list(self.newly_discovered_iocs)[:10]])

        # Section 4: Cluster Details
        detected_df = df[df['predicted'] == 1]
        if not detected_df.empty:
            report_lines.append("\n## Detected Indicator & Cluster Details ##")
            for _, row in detected_df.head(15).iterrows():
                unique_cluster_ids = {item['cluster_id'] for item in row['data']} if row['data'] else set()
                cluster_id_str = ', '.join(unique_cluster_ids) if unique_cluster_ids else 'N/A'
                report_lines.append(f"  - IOC: {row['ioc']} (Parent Report Verdict: {row['verdict']}) -> Cluster IDs: {cluster_id_str}")

        final_report = "\n".join(report_lines)
        
        # Create a version with colors for the console
        console_report = final_report
        for title in ["Efficacy Against High-Confidence IOCs", "Sandbox Efficacy Uplift (Low-Confidence IOCs)", "Intelligence Enrichment Summary", "Detected Indicator & Cluster Details"]:
            console_report = console_report.replace(f"## {title}", f"{Colors.BLUE}{Colors.BOLD}## {title}{Colors.ENDC}")
        
        print("\n" + console_report)
        
        if output_file:
            print(f"\n[*] Saving report to '{output_file}'...")
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(final_report)
                print(f"{Colors.GREEN}[+] Report successfully saved.{Colors.ENDC}")
            except IOError as e:
                print(f"{Colors.RED}[!] Error: Could not write to file: {e}{Colors.ENDC}")


def main():
    """Main function to parse arguments and run the analyzer."""
    parser = argparse.ArgumentParser(
        description="Run a two-phase analysis to measure Malanta.ai detection and enrichment.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("feed_file", help="The path to the XML input feed file.")
    parser.add_argument("-k", "--api-key", help="Your Malanta.ai API key.\n(Uses MALANTA_API_KEY environment variable if not set).")
    parser.add_argument("-o", "--output", help="File path to save the report (e.g., report.txt).")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of parallel threads for API queries (default: 10).")
    parser.add_argument(
        "--cluster-threshold",
        type=int,
        default=1000,
        help="Ignore clusters with more members than this threshold to reduce noise (default: 1000)."
    )
    
    args = parser.parse_args()
    api_key = args.api_key or os.getenv("MALANTA_API_KEY", "YChkdjsLrOqEdGEPhtlsiZFkye711tFX")
    if not api_key:
        print(f"{Colors.RED}[!] API Key not provided. Please use --api-key or set MALANTA_API_KEY.{Colors.ENDC}")
        return
        
    try:
        analyzer = FeedAnalyzer(feed_file=args.feed_file, api_key=api_key)
        analyzer.parse_feed()
        analyzer.run_detection_phase(num_threads=args.threads)
        analyzer.run_enrichment_phase(num_threads=args.threads, cluster_threshold=args.cluster_threshold)
        analyzer.generate_report(output_file=args.output, cluster_threshold=args.cluster_threshold)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected fatal error occurred: {e}{Colors.ENDC}")

if __name__ == "__main__":
    # You may need to install required packages:
    # pip install pandas tqdm requests
    main()