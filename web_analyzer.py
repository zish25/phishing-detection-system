"""
Web Content Analyzer for detecting phishing indicators in webpage content.
Analyzes HTML structure, forms, links, and keywords to detect phishing attempts.
Production-ready web analysis engine.
"""

import logging
import time
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class WebAnalyzer:
    """Analyzes website content for phishing indicators."""
    
    # Suspicious keywords often found in phishing pages
    SUSPICIOUS_KEYWORDS = {
        'login': 5,
        'signin': 5,
        'sign_in': 5,
        'password': 5,
        'verify': 6,
        'confirm': 4,
        'update': 4,
        'secure': 3,
        'account': 3,
        'validate': 5,
        'authenticate': 5,
        'authorize': 4,
        'action_required': 7,
        'urgent': 6,
        'suspicious_activity': 6,
        'click_here': 5,
        'reactivate': 6,
        'restore': 5,
        'banking': 4,
        'credit': 4,
        'paypal': 4,
        'amazon': 3,
        'apple': 3,
        'microsoft': 3,
        'google': 2,  # Lower weight, commonly found in legitimate sites
    }
    
    # Form fields commonly seen in phishing forms
    SUSPICIOUS_FORM_FIELDS = {
        'password': 5,
        'pin': 5,
        'ssn': 6,
        'credit_card': 6,
        'cvv': 6,
        'card_number': 6,
        'email': 2,
        'username': 2,
        'phone': 3,
        'date_of_birth': 4,
    }
    
    # Legitimate domains - links to these are less suspicious
    LEGITIMATE_DOMAINS = {
        'google.com', 'facebook.com', 'twitter.com', 'linkedin.com',
        'github.com', 'stackoverflow.com', 'youtube.com', 'wikipedia.org',
        'github.io', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
        'ajax.googleapis.com', 'code.jquery.com', 'maxcdn.bootstrapcdn.com'
    }
    
    def __init__(self, timeout: int = 10):
        """
        Initialize the web analyzer.
        
        Args:
            timeout (int): Request timeout in seconds
        """
        self.timeout = timeout
        
        # Use a realistic User-Agent to avoid blocking
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def analyze_url(self, url: str) -> Dict:
        """
        Comprehensive analysis of a website URL.
        Extracts real data from the webpage for phishing detection.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Analysis results with real data and risk scores (never returns N/A)
        """
        analysis = {
            'url': url,
            'success': False,
            'risk_score': 0.5,  # Default neutral
            'indicators': [],
            'forms': [],
            'external_links': [],
            'suspicious_links': [],
            'keyword_matches': [],
            'content_preview': '',
            'error': None,
            'extraction_summary': {}  # Track what was extracted
        }
        
        try:
            # Validate URL
            if not self._validate_url(url):
                analysis['error'] = 'Invalid URL format'
                logger.error(f"Invalid URL format: {url}")
                return analysis
            
            # Fetch webpage
            logger.info(f"\n{'='*70}")
            logger.info(f"WEB ANALYSIS START: {url}")
            logger.info(f"{'='*70}")
            
            html_content = self._fetch_webpage(url)
            
            if not html_content:
                analysis['error'] = 'Failed to fetch webpage'
                logger.warning(f"Could not fetch webpage content from {url}")
                return analysis
            
            # Parse HTML
            logger.debug(f"Parsing HTML content ({len(html_content)} bytes)...")
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Get content preview
            analysis['content_preview'] = self._get_content_preview(soup)
            
            # Extract and analyze forms
            logger.debug("Extracting forms...")
            forms = self._extract_forms(soup)
            analysis['forms'] = forms
            analysis['extraction_summary']['forms_found'] = len(forms)
            
            # Extract and analyze links
            logger.debug("Extracting and analyzing links...")
            links = self._extract_links(soup, url)
            analysis['external_links'] = links['external']
            analysis['suspicious_links'] = links['suspicious']
            analysis['extraction_summary']['external_links_found'] = len(links['external'])
            analysis['extraction_summary']['suspicious_links_found'] = len(links['suspicious'])
            
            # Detect keywords
            logger.debug("Detecting suspicious keywords...")
            keywords = self._detect_keywords(soup, html_content)
            analysis['keyword_matches'] = keywords
            analysis['extraction_summary']['keywords_found'] = len(keywords)
            
            # Calculate risk score
            logger.debug("Calculating risk score...")
            risk_score = self._calculate_risk_score(
                forms=forms,
                links=links,
                keywords=keywords,
                content_length=len(html_content)
            )
            
            analysis['risk_score'] = risk_score
            analysis['success'] = True
            analysis['indicators'] = self._generate_indicators(forms, links, keywords)
            
            # Log extraction summary
            logger.info(f"\nEXTRACTION SUMMARY:")
            logger.info(f"  - Forms found: {len(forms)}")
            logger.info(f"  - External links: {len(links['external'])}")
            logger.info(f"  - Suspicious links: {len(links['suspicious'])}")
            logger.info(f"  - Suspicious keywords: {len(keywords)}")
            logger.info(f"  - Risk score: {risk_score*100:.1f}%")
            logger.info(f"{'='*70}\n")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}", exc_info=True)
            analysis['error'] = f"Analysis error: {str(e)}"
            return analysis
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception as e:
            logger.warning(f"URL validation error: {e}")
            return False
    
    def _fetch_webpage(self, url: str) -> Optional[str]:
        """
        Fetch webpage content with retry logic and timeout handling.
        
        Args:
            url (str): The URL to fetch
            
        Returns:
            str: HTML content or None if failed after retries
        """
        max_retries = 2
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True
                )
                response.raise_for_status()
                
                # Limit content size (10MB)
                if len(response.content) > 10 * 1024 * 1024:
                    logger.warning(f"Content too large for {url} ({len(response.content)} bytes)")
                    return None
                
                logger.info(f"Successfully fetched {url} ({len(response.text)} bytes)")
                return response.text
                
            except requests.exceptions.Timeout:
                retry_count += 1
                logger.warning(f"Timeout fetching {url} (attempt {retry_count}/{max_retries})")
                if retry_count < max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                return None
                
            except requests.exceptions.ConnectionError:
                retry_count += 1
                logger.warning(f"Connection error for {url} (attempt {retry_count}/{max_retries})")
                if retry_count < max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                return None
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request error for {url}: {e}")
                return None
            
            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")
                return None
        
        return None
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """
        Extract and analyze forms from webpage for phishing indicators.
        Focuses on login forms with sensitive fields.
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            
        Returns:
            list: Forms with field analysis and risk scoring
        """
        forms = []
        
        try:
            for form_idx, form in enumerate(soup.find_all('form'), 1):
                form_data = {
                    'id': form_idx,
                    'name': form.get('name', f'form_{form_idx}'),
                    'action': form.get('action', '#'),
                    'method': form.get('method', 'POST').upper(),
                    'fields': [],
                    'has_password_field': False,
                    'suspicious_fields_count': 0,
                    'risk_score': 0.0
                }
                
                # Analyze form fields
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    field_name = input_field.get('name', '').lower()
                    field_id = input_field.get('id', '').lower()
                    field_type = input_field.get('type', 'text').lower()
                    placeholder = input_field.get('placeholder', '').lower()
                    
                    field_data = {
                        'name': field_name or field_id or f'{field_type}_field',
                        'type': field_type,
                        'placeholder': placeholder if placeholder else None,
                        'suspicious': False,
                        'reason': None
                    }
                    
                    # Check for suspicious field types and names
                    is_suspicious = False
                    for suspicious_field, weight in self.SUSPICIOUS_FORM_FIELDS.items():
                        if (suspicious_field in field_name or 
                            suspicious_field in field_type or 
                            suspicious_field in field_id or
                            suspicious_field in placeholder):
                            field_data['suspicious'] = True
                            field_data['reason'] = f"Sensitive field: {suspicious_field}"
                            form_data['risk_score'] += (weight * 0.08)
                            is_suspicious = True
                            
                            # Track password fields specifically
                            if suspicious_field == 'password':
                                form_data['has_password_field'] = True
                            
                            break
                    
                    if is_suspicious:
                        form_data['suspicious_fields_count'] += 1
                    
                    form_data['fields'].append(field_data)
                
                # Additional risk factors
                if form_data['suspicious_fields_count'] >= 2:
                    form_data['risk_score'] += 0.25  # Multiple sensitive fields = higher risk
                
                # Check form action for suspicious patterns
                action = form_data['action'].lower()
                if action and action != '#':
                    if 'http' not in action:  # Relative URL might be suspicious
                        form_data['risk_score'] += 0.1
                
                # Only add non-empty forms
                if form_data['fields']:
                    form_data['risk_score'] = min(form_data['risk_score'], 1.0)  # Cap at 1.0
                    forms.append(form_data)
                    logger.debug(f"Form extracted: {form_data['name']} with {len(form_data['fields'])} fields, " +
                               f"risk score: {form_data['risk_score']:.2f}")
                
        except Exception as e:
            logger.error(f"Error extracting forms: {e}", exc_info=True)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Dict:
        """
        Extract and classify links from webpage into internal/external/suspicious.
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            base_url (str): Base URL for resolving relative links
            
        Returns:
            dict: External and suspicious links with full analysis
        """
        links = {
            'internal': [],
            'external': [],
            'suspicious': []
        }
        
        try:
            base_domain = urlparse(base_url).netloc.replace('www.', '')
            all_links_count = 0
            
            for link in soup.find_all('a', href=True):
                href = link.get('href', '').strip()
                link_text = link.get_text(strip=True)[:50]  # First 50 chars
                
                # Skip empty or anchor-only links
                if not href or href.startswith('#'):
                    continue
                
                # Skip mailto and tel links
                if href.startswith(('mailto:', 'tel:')):
                    continue
                
                # Resolve relative URLs
                try:
                    full_url = urljoin(base_url, href)
                except Exception as e:
                    logger.debug(f"Error resolving URL {href}: {e}")
                    continue
                
                link_domain = urlparse(full_url).netloc.replace('www.', '')
                
                # Check if external
                is_external = link_domain != base_domain and link_domain != ''
                
                link_data = {
                    'url': full_url,
                    'text': link_text if link_text else '[No text]',
                    'domain': link_domain,
                    'is_external': is_external
                }
                
                if is_external:
                    # Check for suspicious patterns
                    suspicious_reason = None
                    
                    # Check URL shorteners
                    shorteners = ['bit.ly', 'tinyurl', 'short.link', 'goo.gl', 'ow.ly', 'tiny.cc']
                    for shortener in shorteners:
                        if shortener in full_url.lower():
                            suspicious_reason = f"URL shortener: {shortener}"
                            break
                    
                    # Check for IP addresses in domain
                    if not suspicious_reason:
                        try:
                            parts = urlparse(full_url).netloc.split(':')[0].split('.')
                            if all(part.isdigit() for part in parts) and len(parts) == 4:
                                suspicious_reason = "IP address used instead of domain"
                        except:
                            pass
                    
                    # Check for suspicious keywords in link text
                    if not suspicious_reason:
                        suspicious_keywords = ['click here', 'verify', 'confirm', 'update password', 
                                             'urgent action', 'act now', 'click now']
                        text_lower = link_text.lower()
                        for keyword in suspicious_keywords:
                            if keyword in text_lower:
                                suspicious_reason = f"Suspicious keyword: '{keyword}'"
                                break
                    
                    # Check for mismatch between text and domain
                    if not suspicious_reason and link_text:
                        text_lower = link_text.lower()
                        # If text doesn't match domain and isn't generic, it's suspicious
                        if (text_lower not in link_domain and 
                            link_domain not in text_lower and 
                            text_lower not in ['click', 'here', 'link', 'more', 'learn more', 'read more']):
                            # Only flag if text looks like a domain
                            if '.' in text_lower or '@' in text_lower:
                                suspicious_reason = "Text-domain mismatch (possible spoofing)"
                    
                    link_data['suspicious'] = suspicious_reason is not None
                    if suspicious_reason:
                        link_data['reason'] = suspicious_reason
                        links['suspicious'].append(link_data)
                    
                    links['external'].append(link_data)
                else:
                    links['internal'].append(link_data)
            
            logger.debug(f"Link extraction complete: {len(links['internal'])} internal, " +
                        f"{len(links['external'])} external, {len(links['suspicious'])} suspicious")
            
        except Exception as e:
            logger.error(f"Error extracting links: {e}", exc_info=True)
        
        return links
    
    def _detect_keywords(self, soup: BeautifulSoup, html_content: str) -> List[Dict]:
        """
        Detect suspicious keywords in webpage content.
        Scans HTML text content for phishing indicators.
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            html_content (str): Raw HTML content
            
        Returns:
            list: Found suspicious keywords with frequency and risk scores
        """
        keywords = []
        
        try:
            # Get all text content from page
            text_content = soup.get_text().lower()
            html_lower = html_content.lower()
            
            # Search in all content for keywords
            for keyword, weight in self.SUSPICIOUS_KEYWORDS.items():
                keyword_lower = keyword.lower().replace('_', ' ')
                
                # Count occurrences (case-insensitive)
                count = 0
                search_text = text_content
                
                # Search for variations
                search_terms = [
                    keyword_lower,
                    keyword_lower.replace(' ', '_'),
                    keyword_lower.replace(' ', '-')
                ]
                
                for term in search_terms:
                    count += search_text.count(term)
                
                if count > 0:
                    # Normalize frequency (cap at 100)
                    frequency = min(count, 100)
                    
                    # Calculate score based on weight and frequency
                    score = (weight * frequency) / 10
                    
                    keywords.append({
                        'keyword': keyword_lower.replace('_', ' ').title(),
                        'count': count,
                        'weight': weight,
                        'score': min(score, 10.0)  # Cap at 10
                    })
                    
                    logger.debug(f"Keyword detected: '{keyword_lower}' ({count} times, weight: {weight}, score: {score:.2f})")
            
            # Sort by score descending (most suspicious first)
            keywords.sort(key=lambda x: x['score'], reverse=True)
            
            logger.info(f"Total suspicious keywords detected: {len(keywords)}")
            
        except Exception as e:
            logger.error(f"Error detecting keywords: {e}", exc_info=True)
        
        return keywords
    
    def _get_content_preview(self, soup: BeautifulSoup) -> str:
        """Get preview of webpage content."""
        try:
            # Get title
            title = soup.find('title')
            title_text = title.get_text(strip=True) if title else "[No Title]"
            
            # Get meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            desc_text = meta_desc.get('content', '') if meta_desc else ""
            
            # Get first paragraph
            paragraphs = soup.find_all('p')
            first_para = paragraphs[0].get_text(strip=True)[:100] if paragraphs else ""
            
            preview = f"Title: {title_text}\n"
            if desc_text:
                preview += f"Description: {desc_text}\n"
            if first_para:
                preview += f"Content: {first_para}..."
            
            return preview[:500]  # Limit to 500 chars
            
        except Exception as e:
            logger.debug(f"Error getting content preview: {e}")
            return "[Unable to extract preview]"
    
    def _calculate_risk_score(self, forms: List[Dict], links: Dict, 
                             keywords: List[Dict], content_length: int) -> float:
        """
        Calculate overall risk score based on multiple factors.
        
        Args:
            forms (list): Extracted forms
            links (dict): Extracted links
            keywords (list): Detected keywords
            content_length (int): Length of content
            
        Returns:
            float: Risk score from 0.0 to 1.0
        """
        score = 0.5  # Start at neutral
        
        try:
            # Forms risk (0-0.3)
            if forms:
                form_risk = min(len(forms) * 0.1 + sum(f.get('risk_score', 0) for f in forms) / len(forms), 0.3)
                score += form_risk
            
            # Links risk (0-0.2)
            if links['external']:
                suspicious_ratio = len(links['suspicious']) / len(links['external'])
                score += suspicious_ratio * 0.2
            
            # Keywords risk (0-0.2)
            if keywords:
                keyword_risk = min(sum(k['score'] for k in keywords) / len(keywords) * 0.02, 0.2)
                score += keyword_risk
            
            # Content length anomaly (0-0.1)
            if content_length < 2000:  # Too short might indicate copy-paste phishing
                score += 0.05
            
            # Clamp between 0 and 1
            score = max(0.0, min(1.0, score))
            
        except Exception as e:
            logger.debug(f"Error calculating risk score: {e}")
        
        return score
    
    def _generate_indicators(self, forms: List[Dict], links: Dict, 
                            keywords: List[Dict]) -> List[str]:
        """
        Generate human-readable indicators of phishing.
        
        Args:
            forms (list): Extracted forms
            links (dict): Extracted links
            keywords (list): Detected keywords
            
        Returns:
            list: Indicator messages
        """
        indicators = []
        
        try:
            # Form indicators
            if forms:
                sensitive_forms = [f for f in forms if f.get('risk_score', 0) > 0.3]
                if sensitive_forms:
                    indicators.append(f"⚠️ {len(sensitive_forms)} form(s) with sensitive fields detected")
            
            # Link indicators
            if links['suspicious']:
                indicators.append(f"🔗 {len(links['suspicious'])} suspicious external link(s) found")
            
            if links['external'] and len(links['external']) > 20:
                indicators.append(f"📊 Unusually high number of external links ({len(links['external'])})")
            
            # Keyword indicators
            if keywords:
                top_keywords = keywords[:3]
                keyword_list = ', '.join([f"'{k['keyword']}'" for k in top_keywords])
                indicators.append(f"🔍 Suspicious keywords detected: {keyword_list}")
            
        except Exception as e:
            logger.debug(f"Error generating indicators: {e}")
        
        return indicators
