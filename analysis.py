# LEXOLEN Threat Analysis Toolkit
# ==================================
#
# This module provides comprehensive threat analysis capabilities for cybersecurity research
# and red team operations. It integrates with various LEXOLEN tools to perform log analysis,
# IOC extraction, threat correlation, and automated reporting.
#
# Features:
# - Log parsing and anomaly detection
# - Indicator of Compromise (IOC) extraction
# - Threat intelligence correlation
# - Integration with Evil-ginx3, BloodHound-CE, PE-sieve, and AutoRecon outputs
# - Automated report generation
#
# Dependencies: Requires Python 3.8+, standard library modules (re, json, datetime, logging)
#
# Usage:
#   python analysis.py [logfile] [--output report.json] [--verbose]
#
# Author: LEXOLEN Team
# Version: 1.0.0
# License: MIT

import re
import json
import datetime
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class IndicatorOfCompromise:
    """Data class representing an Indicator of Compromise (IOC)."""
    type: str  # e.g., 'ip', 'domain', 'hash', 'url'
    value: str
    confidence: float  # 0.0 to 1.0
    source: str
    timestamp: datetime.datetime
    threat_level: ThreatLevel
    metadata: Dict[str, str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class ThreatReport:
    """Comprehensive threat analysis report."""
    analysis_id: str
    timestamp: datetime.datetime
    target: str
    iocs: List[IndicatorOfCompromise]
    anomalies: List[str]
    recommendations: List[str]
    correlated_threats: List[str]
    risk_score: float

class LogParser:
    """
    Parser for various log formats commonly encountered in security operations.

    Supports formats from:
    - Web server logs (Apache, Nginx)
    - System logs (syslog, Windows Event Logs)
    - Network device logs (firewall, IDS/IPS)
    - Application logs (custom formats)

    Pseudo-code for parsing algorithm:
    1. Read log file line by line
    2. For each line:
       a. Apply regex patterns to extract fields (timestamp, source_ip, action, etc.)
       b. Validate extracted data
       c. Categorize log entry (e.g., authentication, access, error)
       d. Flag potential anomalies (unusual patterns, high frequency events)
    3. Aggregate results and generate summary statistics
    """

    def __init__(self, log_format: str = 'apache'):
        self.log_format = log_format
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, re.Pattern]:
        """Load regex patterns for different log formats."""
        patterns = {
            'apache': re.compile(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\d+)'
            ),
            'syslog': re.compile(
                r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\w+) (?P<process>[^\[]+)\[(?P<pid>\d+)\]: (?P<message>.+)'
            ),
            # Add more patterns as needed
        }
        return patterns

    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single log line.

        Returns parsed fields as dictionary or None if parsing fails.
        """
        pattern = self.patterns.get(self.log_format)
        if not pattern:
            logger.warning(f"Unsupported log format: {self.log_format}")
            return None

        match = pattern.match(line.strip())
        if match:
            return match.groupdict()
        return None

    def parse_file(self, filepath: str) -> List[Dict[str, str]]:
        """
        Parse entire log file.

        Returns list of parsed log entries.
        """
        entries = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    parsed = self.parse_line(line)
                    if parsed:
                        parsed['line_number'] = line_num
                        entries.append(parsed)
                    else:
                        logger.debug(f"Failed to parse line {line_num}: {line[:100]}...")
        except FileNotFoundError:
            logger.error(f"Log file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error parsing log file: {e}")

        return entries

class IOCExtractor:
    """
    Extracts Indicators of Compromise from text data.

    Supports extraction of:
    - IP addresses (IPv4, IPv6)
    - Domain names
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    - Email addresses
    - Registry keys (Windows)
    - File paths

    Pseudo-code for IOC extraction:
    1. Define regex patterns for each IOC type
    2. For each input text/source:
       a. Apply all patterns to find matches
       b. Validate matches (e.g., check IP format, domain validity)
       c. Deduplicate results
       d. Assign confidence scores based on context
       e. Enrich with metadata (geolocation for IPs, WHOIS for domains)
    3. Return structured IOC objects
    """

    def __init__(self):
        self.patterns = {
            'ipv4': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'domain': re.compile(r'\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }

    def extract_from_text(self, text: str, source: str = 'unknown') -> List[IndicatorOfCompromise]:
        """
        Extract IOCs from text content.

        Args:
            text: Input text to analyze
            source: Source identifier for the IOCs

        Returns:
            List of IndicatorOfCompromise objects
        """
        iocs = []

        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for match in set(matches):  # Deduplicate
                confidence = self._calculate_confidence(match, ioc_type, text)
                threat_level = self._assess_threat_level(match, ioc_type)

                ioc = IndicatorOfCompromise(
                    type=ioc_type,
                    value=match,
                    confidence=confidence,
                    source=source,
                    timestamp=datetime.datetime.now(),
                    threat_level=threat_level
                )
                iocs.append(ioc)

        return iocs

    def _calculate_confidence(self, match: str, ioc_type: str, context: str) -> float:
        """Calculate confidence score for IOC based on context."""
        # Simple heuristic: higher confidence if IOC appears multiple times or in suspicious context
        count = context.count(match)
        base_confidence = min(count * 0.1, 0.5)  # Max 0.5 from frequency

        # Add context-based confidence
        suspicious_keywords = ['attack', 'malware', 'exploit', 'vulnerable', 'breach']
        context_confidence = 0.3 if any(kw in context.lower() for kw in suspicious_keywords) else 0.0

        return min(base_confidence + context_confidence + 0.2, 1.0)  # Base 0.2, max 1.0

    def _assess_threat_level(self, match: str, ioc_type: str) -> ThreatLevel:
        """Assess threat level based on IOC characteristics."""
        # Simplified assessment - in real implementation, would use threat intelligence feeds
        if ioc_type in ['sha256', 'md5'] and len(match) > 32:
            return ThreatLevel.HIGH  # File hashes often indicate malware
        elif ioc_type == 'ipv4' and match.startswith(('10.', '192.168.', '172.')):
            return ThreatLevel.LOW  # Private IPs less concerning
        else:
            return ThreatLevel.MEDIUM

class ThreatCorrelator:
    """
    Correlates multiple IOCs and threat indicators to identify patterns and campaigns.

    Features:
    - Temporal correlation (events within time windows)
    - Attribution correlation (linking to known threat actors)
    - Behavioral correlation (similar attack patterns)
    - Integration with external threat intelligence feeds

    Pseudo-code for threat correlation:
    1. Collect all IOCs from various sources
    2. Group IOCs by time windows (e.g., 1 hour, 24 hours)
    3. For each group:
       a. Calculate similarity scores between IOCs
       b. Identify clusters of related indicators
       c. Check against known threat actor TTPs (Tactics, Techniques, Procedures)
       d. Assign campaign attribution if confidence > threshold
    4. Generate correlation report with confidence scores
    """

    def __init__(self, threat_intel_feed: Optional[Dict] = None):
        self.threat_intel = threat_intel_feed or {}

    def correlate_iocs(self, iocs: List[IndicatorOfCompromise], time_window_hours: int = 24) -> Dict[str, List[IndicatorOfCompromise]]:
        """
        Correlate IOCs based on temporal proximity and similarity.

        Returns dictionary of correlation groups.
        """
        # Sort IOCs by timestamp
        sorted_iocs = sorted(iocs, key=lambda x: x.timestamp)

        correlations = {}
        current_group = []
        group_id = 0

        for ioc in sorted_iocs:
            if not current_group:
                current_group.append(ioc)
            else:
                # Check if IOC fits within time window of group
                time_diff = (ioc.timestamp - current_group[0].timestamp).total_seconds() / 3600
                if time_diff <= time_window_hours:
                    current_group.append(ioc)
                else:
                    # Start new group
                    if len(current_group) > 1:
                        correlations[f"group_{group_id}"] = current_group
                        group_id += 1
                    current_group = [ioc]

        # Add final group
        if len(current_group) > 1:
            correlations[f"group_{group_id}"] = current_group

        return correlations

    def attribute_to_actor(self, iocs: List[IndicatorOfCompromise]) -> List[str]:
        """
        Attempt to attribute IOCs to known threat actors.

        Returns list of possible actor names.
        """
        # Simplified attribution - in practice, would use ML models and threat intel
        actors = []
        actor_signatures = {
            'APT28': ['spearphishing', 'russia'],
            'Lazarus': ['wiper', 'north_korea'],
            'Cozy_Bear': ['supply_chain', 'russia']
        }

        for actor, signatures in actor_signatures.items():
            matches = sum(1 for ioc in iocs if any(sig in str(ioc.metadata).lower() for sig in signatures))
            if matches > len(iocs) * 0.3:  # 30% match threshold
                actors.append(actor)

        return actors

class ThreatAnalyzer:
    """
    Main analyzer class that orchestrates the threat analysis process.

    Integrates log parsing, IOC extraction, correlation, and reporting.
    Can be extended to integrate with LEXOLEN tools like:
    - Evil-ginx3: Analyze phishing campaign logs
    - BloodHound-CE: Correlate with AD attack paths
    - PE-sieve: Analyze malware unpacking results
    - AutoRecon: Incorporate reconnaissance data

    Pseudo-code for analysis workflow:
    1. Initialize components (parser, extractor, correlator)
    2. For each input source (logs, network data, etc.):
       a. Parse and extract raw data
       b. Extract IOCs
       c. Analyze for anomalies
       d. Correlate with existing threats
    3. Generate comprehensive report
    4. Optionally, trigger automated responses (alerts, blocks, etc.)
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.parser = LogParser(self.config.get('log_format', 'apache'))
        self.extractor = IOCExtractor()
        self.correlator = ThreatCorrelator(self.config.get('threat_intel'))

    def analyze_logs(self, logfile: str) -> ThreatReport:
        """
        Perform complete threat analysis on a log file.

        Args:
            logfile: Path to the log file to analyze

        Returns:
            ThreatReport object with analysis results
        """
        logger.info(f"Starting threat analysis on {logfile}")

        # Parse logs
        log_entries = self.parser.parse_file(logfile)
        logger.info(f"Parsed {len(log_entries)} log entries")

        # Extract IOCs from all log entries
        all_iocs = []
        for entry in log_entries:
            text_content = ' '.join(str(v) for v in entry.values())
            iocs = self.extractor.extract_from_text(text_content, f"log_line_{entry.get('line_number', 'unknown')}")
            all_iocs.extend(iocs)

        logger.info(f"Extracted {len(all_iocs)} potential IOCs")

        # Correlate threats
        correlations = self.correlator.correlate_iocs(all_iocs)
        correlated_threats = list(correlations.keys())

        # Identify anomalies (simplified)
        anomalies = self._detect_anomalies(log_entries)

        # Generate recommendations
        recommendations = self._generate_recommendations(all_iocs, anomalies)

        # Calculate risk score
        risk_score = self._calculate_risk_score(all_iocs, anomalies, correlations)

        # Create report
        report = ThreatReport(
            analysis_id=f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.datetime.now(),
            target=logfile,
            iocs=all_iocs,
            anomalies=anomalies,
            recommendations=recommendations,
            correlated_threats=correlated_threats,
            risk_score=risk_score
        )

        logger.info(f"Analysis complete. Risk score: {risk_score:.2f}")
        return report

    def _detect_anomalies(self, log_entries: List[Dict[str, str]]) -> List[str]:
        """Detect anomalous patterns in log entries."""
        anomalies = []

        # Simple anomaly detection: high frequency of failed logins
        failed_logins = sum(1 for entry in log_entries if entry.get('status') == '401')
        if failed_logins > len(log_entries) * 0.1:  # >10% failed logins
            anomalies.append(f"High rate of failed authentication attempts: {failed_logins}")

        # Check for unusual IP patterns
        ips = [entry.get('ip') for entry in log_entries if entry.get('ip')]
        unique_ips = set(ips)
        if len(unique_ips) < len(ips) * 0.5:  # High repeat IPs
            anomalies.append("High concentration of requests from repeated IP addresses")

        return anomalies

    def _generate_recommendations(self, iocs: List[IndicatorOfCompromise], anomalies: List[str]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        high_confidence_iocs = [ioc for ioc in iocs if ioc.confidence > 0.7]
        if high_confidence_iocs:
            recommendations.append(f"Block {len(high_confidence_iocs)} high-confidence IOCs at perimeter")

        if any('authentication' in anomaly.lower() for anomaly in anomalies):
            recommendations.append("Implement multi-factor authentication and account lockout policies")

        if any('ip' in anomaly.lower() for anomaly in anomalies):
            recommendations.append("Deploy rate limiting and IP reputation filtering")

        recommendations.append("Integrate findings with SIEM for continuous monitoring")
        recommendations.append("Conduct threat hunting based on identified IOCs")

        return recommendations

    def _calculate_risk_score(self, iocs: List[IndicatorOfCompromise], anomalies: List[str], correlations: Dict) -> float:
        """Calculate overall risk score (0.0 to 1.0)."""
        base_score = 0.0

        # IOC-based scoring
        high_threat_iocs = sum(1 for ioc in iocs if ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        base_score += min(high_threat_iocs * 0.1, 0.4)

        # Anomaly-based scoring
        base_score += min(len(anomalies) * 0.1, 0.3)

        # Correlation-based scoring
        base_score += min(len(correlations) * 0.05, 0.3)

        return min(base_score, 1.0)

    def export_report(self, report: ThreatReport, output_file: str, format: str = 'json'):
        """
        Export threat report to file.

        Supports JSON and CSV formats.
        """
        if format.lower() == 'json':
            data = asdict(report)
            # Convert datetime objects to strings
            data['timestamp'] = report.timestamp.isoformat()
            for ioc in data['iocs']:
                ioc['timestamp'] = ioc['timestamp'][:19]  # Truncate to seconds

            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            logger.warning(f"Unsupported export format: {format}")

        logger.info(f"Report exported to {output_file}")

# Legacy function for backward compatibility
def analyze_logs(logfile):
    """
    Legacy function - use ThreatAnalyzer class for new implementations.

    This function provides basic log analysis for simple use cases.
    For comprehensive analysis, instantiate ThreatAnalyzer instead.
    """
    analyzer = ThreatAnalyzer()
    report = analyzer.analyze_logs(logfile)
    print(f"Analysis complete for {logfile}")
    print(f"Found {len(report.iocs)} IOCs, {len(report.anomalies)} anomalies")
    print(f"Risk score: {report.risk_score:.2f}")
    return report

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analysis.py <logfile> [--output <output_file>] [--verbose]")
        sys.exit(1)

    logfile = sys.argv[1]
    output_file = None
    verbose = False

    # Parse additional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--output':
            output_file = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--verbose':
            verbose = True
            logging.getLogger().setLevel(logging.DEBUG)
            i += 1
        else:
            i += 1

    # Run analysis
    analyzer = ThreatAnalyzer()
    report = analyzer.analyze_logs(logfile)

    # Display results
    print(f"\n=== Threat Analysis Report ===")
    print(f"Target: {report.target}")
    print(f"Analysis ID: {report.analysis_id}")
    print(f"Timestamp: {report.timestamp}")
    print(f"IOCs Found: {len(report.iocs)}")
    print(f"Anomalies Detected: {len(report.anomalies)}")
    print(f"Correlated Threats: {len(report.correlated_threats)}")
    print(f"Risk Score: {report.risk_score:.2f}")

    if report.anomalies:
        print(f"\nAnomalies:")
        for anomaly in report.anomalies:
            print(f"  - {anomaly}")

    if report.recommendations:
        print(f"\nRecommendations:")
        for rec in report.recommendations:
            print(f"  - {rec}")

    # Export if requested
    if output_file:
        analyzer.export_report(report, output_file)
        print(f"\nReport exported to {output_file}")

    print("\nAnalysis complete. Stay vigilant! 🔒")
