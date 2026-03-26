"""
VirusTotal API integration for external threat intelligence.
Provides endpoint analysis from VirusTotal to augment phishing detection.
"""

import logging
import os
from typing import Dict, Optional
import requests

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer:
    """Analyzes URLs using VirusTotal API v3."""
    
    API_URL = "https://www.virustotal.com/api/v3/urls"
    TIMEOUT = 10
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal analyzer.
        
        Args:
            api_key (str): VirusTotal API key. If None, tries to read from VT_API_KEY env var.
        """
        # Try to get API key from parameter, env var, or config
        self.api_key = api_key or os.getenv('VT_API_KEY')
        
        if self.api_key:
            logger.info("VirusTotal API key loaded successfully")
        else:
            logger.warning("VirusTotal API key not found. Set VT_API_KEY environment variable.")
        
        self.headers = {
            'x-apikey': self.api_key or '',
            'User-Agent': 'Phishing-Detection-System/1.0'
        }
    
    def is_configured(self) -> bool:
        """Check if VirusTotal API is properly configured."""
        return bool(self.api_key)
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze URL using VirusTotal API.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Analysis result with threat information
                {
                    'success': bool,
                    'malicious_score': float (0.0-1.0),
                    'engine_results': dict,
                    'detection_summary': str,
                    'scan_date': str,
                    'error': str or None,
                    'cached': bool
                }
        """
        result = {
            'url': url,
            'success': False,
            'malicious_score': 0.5,  # Default neutral
            'engine_results': {},
            'detection_summary': '',
            'scan_date': None,
            'error': None,
            'cached': False
        }
        
        if not self.is_configured():
            result['error'] = 'VirusTotal API key not configured'
            logger.warning("VirusTotal analysis skipped: API key not configured")
            return result
        
        try:
            logger.info(f"Analyzing URL with VirusTotal: {url}")
            
            # Send URL for analysis
            files = {'url': (None, url)}
            
            response = requests.post(
                self.API_URL,
                headers=self.headers,
                files=files,
                timeout=self.TIMEOUT
            )
            
            if response.status_code == 204:
                # URL already in queue
                logger.info(f"URL queued for analysis: {url}")
                result['success'] = True
                result['detection_summary'] = "URL queued for analysis"
                return result
            
            if response.status_code != 200:
                error_msg = f"VirusTotal API error: {response.status_code}"
                logger.warning(error_msg)
                result['error'] = error_msg
                return result
            
            # Parse response
            analysis_data = response.json()
            analysis_id = analysis_data.get('data', {}).get('id')
            
            if not analysis_id:
                logger.warning("No analysis ID received from VirusTotal")
                result['error'] = "No analysis ID in response"
                return result
            
            # Get analysis results
            return self._get_analysis_results(analysis_id, url)
            
        except requests.exceptions.Timeout:
            result['error'] = 'VirusTotal API timeout'
            logger.warning(f"VirusTotal analysis timeout for {url}")
            return result
        except requests.exceptions.ConnectionError:
            result['error'] = 'VirusTotal API connection error'
            logger.warning(f"VirusTotal connection error for {url}")
            return result
        except Exception as e:
            result['error'] = f"VirusTotal analysis error: {str(e)}"
            logger.error(f"Unexpected error in VirusTotal analysis: {e}", exc_info=True)
            return result
    
    def get_url_report(self, url: str) -> Dict:
        """
        Get existing VirusTotal report for URL (faster, returns cached results).
        
        Args:
            url (str): The URL to check
            
        Returns:
            dict: Analysis result with threat information
        """
        result = {
            'url': url,
            'success': False,
            'malicious_score': 0.5,
            'engine_results': {},
            'detection_summary': '',
            'scan_date': None,
            'error': None,
            'cached': True
        }
        
        if not self.is_configured():
            result['error'] = 'VirusTotal API key not configured'
            logger.warning("VirusTotal report skipped: API key not configured")
            return result
        
        try:
            logger.info(f"Fetching VirusTotal report for: {url}")
            
            # Get URL ID (SHA-256 of the URL)
            url_id = self._get_url_id(url)
            
            # Fetch existing report
            report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            response = requests.get(
                report_url,
                headers=self.headers,
                timeout=self.TIMEOUT
            )
            
            if response.status_code == 404:
                logger.info(f"No VirusTotal report found for {url}")
                result['error'] = 'URL not yet analyzed by VirusTotal'
                return result
            
            if response.status_code != 200:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                result['error'] = f"API error: {response.status_code}"
                return result
            
            # Parse results
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            last_analysis = attributes.get('last_analysis_stats', {})
            
            # Calculate malicious score
            malicious_count = last_analysis.get('malicious', 0)
            total_engines = sum(last_analysis.values())
            
            if total_engines > 0:
                malicious_score = min(malicious_count / max(total_engines, 1), 1.0)
            else:
                malicious_score = 0.0
            
            result['success'] = True
            result['malicious_score'] = malicious_score
            result['engine_results'] = last_analysis
            result['scan_date'] = attributes.get('last_submission_date')
            
            # Generate summary
            summary_parts = []
            if malicious_count > 0:
                summary_parts.append(f"{malicious_count} engines detected as malicious")
            else:
                summary_parts.append("No malicious detection")
            
            if total_engines > 0:
                summary_parts.append(f"out of {total_engines} engines")
            
            result['detection_summary'] = ", ".join(summary_parts)
            
            logger.info(f"VirusTotal report: {result['detection_summary']}")
            logger.info(f"Malicious score: {malicious_score*100:.1f}%")
            
            return result
            
        except Exception as e:
            result['error'] = f"Error fetching report: {str(e)}"
            logger.error(f"Error fetching VirusTotal report: {e}", exc_info=True)
            return result
    
    def _get_url_id(self, url: str) -> str:
        """
        Calculate VirusTotal URL ID (base64url encoded SHA-256).
        
        Args:
            url (str): The URL
            
        Returns:
            str: URL ID for VirusTotal API
        """
        import hashlib
        import base64
        
        sha256 = hashlib.sha256(url.encode()).digest()
        url_id = base64.urlsafe_b64encode(sha256).decode().rstrip('=')
        
        return url_id
    
    def _get_analysis_results(self, analysis_id: str, url: str) -> Dict:
        """
        Get analysis results from VirusTotal.
        
        Args:
            analysis_id (str): Analysis ID from submission
            url (str): Original URL
            
        Returns:
            dict: Analysis results
        """
        result = {
            'url': url,
            'success': False,
            'malicious_score': 0.5,
            'engine_results': {},
            'detection_summary': '',
            'scan_date': None,
            'error': None,
            'cached': False
        }
        
        try:
            # Get analysis status
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            response = requests.get(
                analysis_url,
                headers=self.headers,
                timeout=self.TIMEOUT
            )
            
            if response.status_code != 200:
                logger.warning(f"VirusTotal analysis fetch error: {response.status_code}")
                return result
            
            # Parse response
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            status = attributes.get('status', 'unknown')
            
            logger.info(f"VirusTotal analysis status: {status}")
            
            # Get results if ready
            results = attributes.get('results', {})
            stats = attributes.get('stats', {})
            
            if results or stats:
                malicious_count = stats.get('malicious', 0)
                total_engines = sum(stats.values()) if stats else len(results)
                
                if total_engines > 0:
                    malicious_score = min(malicious_count / max(total_engines, 1), 1.0)
                else:
                    malicious_score = 0.0
                
                result['success'] = True
                result['malicious_score'] = malicious_score
                result['engine_results'] = stats
                
                # Generate summary
                if malicious_count > 0:
                    result['detection_summary'] = f"{malicious_count} engines flagged as malicious"
                else:
                    result['detection_summary'] = "No malicious detections"
                
                logger.info(f"Malicious score: {malicious_score*100:.1f}%")
            else:
                result['detection_summary'] = f"Analysis {status}, results pending"
                logger.info(f"Analysis still processing: {status}")
            
            return result
            
        except Exception as e:
            result['error'] = f"Error getting results: {str(e)}"
            logger.error(f"Error getting VirusTotal results: {e}", exc_info=True)
            return result
