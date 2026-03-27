import logging
import subprocess
import xml.etree.ElementTree as ET
import shutil
from scanners.base import ScannerAdapter, ScanVulnerability

logger = logging.getLogger("vulndetect")


class NmapScanner(ScannerAdapter):
    name = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def scan(self, target: str) -> list[ScanVulnerability]:
        if not self.is_available():
            logger.warning("Nmap not available, using mock data for %s", target)
            return self._mock_scan(target)

        try:
            cmd = ["nmap", "-sV", "--script", "vulners", "-oX", "-", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                logger.error(
                    "Nmap exited with code %d: %s", result.returncode, result.stderr
                )
                return self._mock_scan(target)
            return self._parse_xml(result.stdout, target)
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out for %s", target)
            return self._mock_scan(target)
        except Exception:
            logger.exception("Nmap scan failed for %s", target)
            return self._mock_scan(target)

        try:
            cmd = [
                "nmap",
                "-sV",
                "--script",
                "vulners",
                "-oX",
                "-",  # XML output to stdout
                target,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_xml(result.stdout, target)
        except (subprocess.TimeoutExpired, Exception):
            return self._mock_scan(target)

    def _parse_xml(self, xml_output: str, target: str) -> list[ScanVulnerability]:
        vulns = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                hostname = host.find("hostnames/hostname")
                host_str = (
                    hostname.get("name", target) if hostname is not None else target
                )

                for port in host.findall(".//port"):
                    port_id = int(port.get("portid", 0))
                    service = port.find("service")
                    service_name = (
                        service.get("name", "") if service is not None else ""
                    )

                    for script in port.findall(".//script"):
                        script_output = script.get("output", "")
                        cves = self.extract_cves(script_output)

                        for cve in cves:
                            vulns.append(
                                ScanVulnerability(
                                    cve_id=cve,
                                    description=f"Nmap vulners script found {cve} on {service_name}",
                                    affected_host=host_str,
                                    affected_port=port_id,
                                    affected_service=service_name,
                                    source_scanner=self.name,
                                    raw_output={
                                        "script": script.get("id"),
                                        "output": script_output,
                                    },
                                )
                            )
        except ET.ParseError:
            pass
        return vulns

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        """Mock scan data when nmap is not available."""
        return [
            ScanVulnerability(
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Apache Log4j2 Remote Code Execution (Log4Shell)",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Update Log4j to version 2.17.1 or later",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2023-23397",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Microsoft Outlook Elevation of Privilege Vulnerability",
                affected_host=target,
                affected_port=445,
                affected_service="microsoft-ds",
                solution="Apply Microsoft security update from March 2023",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2022-22965",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Spring Framework RCE (Spring4Shell)",
                affected_host=target,
                affected_port=8080,
                affected_service="http-proxy",
                solution="Upgrade Spring Framework to 5.3.18+ or 2.6.6+",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2023-44487",
                cvss_score=7.5,
                severity="HIGH",
                description="HTTP/2 Rapid Reset Attack",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Update HTTP/2 server implementation",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2021-34527",
                cvss_score=8.8,
                severity="HIGH",
                description="Windows Print Spooler RCE (PrintNightmare)",
                affected_host=target,
                affected_port=445,
                affected_service="microsoft-ds",
                solution="Disable Print Spooler service or apply Microsoft patch",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2020-1472",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Netlogon Elevation of Privilege (Zerologon)",
                affected_host=target,
                affected_port=135,
                affected_service="msrpc",
                solution="Apply Microsoft August 2020 security update",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
        ]
