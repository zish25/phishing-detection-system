"""
Feature extraction utilities for URL analysis.
This module extracts meaningful features from URLs that help identify phishing attempts.
Production-ready with comprehensive error handling and logging.
"""

import re
import logging
from urllib.parse import urlparse, urlunparse
from urllib.request import quote

# Configure logging
logger = logging.getLogger(__name__)

# Trusted domains that are known to be legitimate
TRUSTED_DOMAINS = {
    'github.com', 'github.io',
    'google.com', 'accounts.google.com', 'mail.google.com', 'drive.google.com',
    'microsoft.com', 'office.com', 'outlook.com', 'hotmail.com',
    'amazon.com', 'aws.amazon.com',
    'apple.com', 'icloud.com',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com',
    'linkedin.com',
    'youtube.com',
    'wikipedia.org',
    'stackoverflow.com',
    'reddit.com',
    'github.io',
    'wordpress.com',
    'blogger.com',
    'pinterest.com',
    'dropbox.com',
    'evernote.com',
    'notion.so',
    'slack.com',
    'discord.com',
    'telegram.org',
    'skype.com',
    'zoom.us',
    'webex.com'
}



def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent feature extraction.
    Ensures same URL always produces same features.
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: Normalized URL
    """
    try:
        # Strip whitespace
        url = url.strip()
        
        # Convert to lowercase (case-insensitive)
        url = url.lower()
        
        # Remove fragment (after #)
        if '#' in url:
            url = url.split('#')[0]
        
        # Parse and reconstruct to normalize
        parsed = urlparse(url)
        
        # Ensure scheme is present
        if not parsed.scheme:
            url = 'https://' + url
            parsed = urlparse(url)
        
        # Remove trailing slash from path for consistency
        path = parsed.path.rstrip('/') or '/'
        
        # Reconstruct normalized URL
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            ''  # No fragment
        ))
        
        return normalized
    except Exception as e:
        logger.warning(f"Error normalizing URL: {e}")
        return url.lower().strip()


def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing extracted features, or None if extraction fails
        
    This function is robust and handles edge cases gracefully.
    Features are deterministic - same URL always produces same features.
    """
    # ---- INPUT VALIDATION & NORMALIZATION ----
    if not url or not isinstance(url, str):
        logger.warning(f"Invalid URL input type: {type(url)}")
        return None
    
    # Normalize URL for consistency
    url = normalize_url(url)
    logger.debug(f"Normalized URL for feature extraction: {url}")
    
    if len(url) == 0:
        logger.warning("Empty URL string provided")
        return None
    
    if len(url) > 2048:  # Sanity check: URLs shouldn't be this long
        logger.warning(f"URL exceeds maximum length (2048 chars): {len(url)}")
        return None
    
    features = {}
    
    try:
        # ---- URL PARSING ----
        parsed_url = urlparse(url)
        
        # ---- FEATURE EXTRACTION WITH VALIDATION ----
        # 1. URL Length
        features['url_length'] = len(url)
        
        # 2. Domain Length
        domain = parsed_url.netloc or ""
        features['domain_length'] = len(domain)
        
        # 3. Number of dots
        features['num_dots'] = url.count('.')
        
        # 4. Number of hyphens
        features['num_hyphens'] = url.count('-')
        
        # 5. Number of underscores
        features['num_underscores'] = url.count('_')
        
        # 6. Presence of @ symbol (suspicious in URLs)
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # 7. Presence of HTTPS
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # 8. Number of slashes
        features['num_slashes'] = url.count('/')
        
        # 9. Number of question marks
        features['num_question_marks'] = url.count('?')
        
        # 10. Presence of 'bit.ly' or shortener patterns
        shorteners = ['bit.ly', 'tinyurl', 'short.link', 'goo.gl', 'ow.ly', 'tiny.cc']
        features['has_shortener'] = 1 if any(short in url.lower() for short in shorteners) else 0
        
        # 11. Presence of IP address pattern
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip_address'] = 1 if re.search(ip_pattern, url) else 0
        
        # 12. Number of parameters
        try:
            num_params = len(parsed_url.query.split('&')) if parsed_url.query else 0
            features['num_parameters'] = num_params
        except Exception as e:
            logger.debug(f"Error parsing parameters: {e}")
            features['num_parameters'] = 0
        
        # 13. Presence of double slash in path
        path = parsed_url.path or ""
        features['has_double_slash'] = 1 if '//' in path else 0
        
        # 14. Domain has numbers
        features['domain_has_numbers'] = 1 if re.search(r'\d', domain) else 0
        
        # 15. Presence of suspicious keywords
        # REDUCED IMPACT: Only flag keywords if NOT on trusted domain
        suspicious_keywords = ['signin', 'login', 'verify', 'confirm', 'update', 
                              'secure', 'account', 'alert', 'urgent', 'click', 'action']
        
        # Extract domain for trusted domain check
        domain_lower = domain.lower()
        # Remove www. prefix for consistency
        domain_check = domain_lower.replace('www.', '')
        
        # Check if domain is in trusted list or subdomain of trusted domain
        is_trusted_domain = (
            domain_check in TRUSTED_DOMAINS or
            any(domain_check.endswith('.' + td) for td in TRUSTED_DOMAINS)
        )
        
        # If trusted domain, don't flag keywords as suspicious
        if is_trusted_domain:
            features['has_suspicious_keywords'] = 0
        else:
            features['has_suspicious_keywords'] = 1 if any(keyword in url.lower() for keyword in suspicious_keywords) else 0
        
        # 16. Domain reputation check (new feature)
        # Trusted domains get 0 (safe), others evaluated normally
        features['is_trusted_domain'] = 1 if is_trusted_domain else 0
        
        # 17. Domain legitimacy indicators
        # TLD quality check - legitimate TLDs vs suspicious ones
        legitimate_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.de', '.uk', '.ca', '.au']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.download', '.online', '.review', '.xyz']
        
        has_legitimate_tld = any(domain.lower().endswith(tld) for tld in legitimate_tlds)
        has_suspicious_tld = any(domain.lower().endswith(tld) for tld in suspicious_tlds)
        
        # Score: 1 = has legitimate TLD, 0 = neutral/suspicious
        features['has_legitimate_tld'] = 1 if has_legitimate_tld else 0
        features['has_suspicious_tld'] = 1 if has_suspicious_tld else 0
        
        # 18. Domain age indicators (complex domain patterns)
        # Phishing domains often use separators like hyphens in unusual places
        # Legitimate domains are typically simple: google.com, facebook.com, etc.
        hyphen_count = domain.count('-')
        features['excessive_hyphens'] = 1 if hyphen_count > 2 else 0
        
        # ---- VALIDATION ----
        # Ensure all features are numeric and finite
        for key, value in features.items():
            if not isinstance(value, (int, float)):
                logger.warning(f"Feature {key} is not numeric: {value}")
                features[key] = 0
        
        logger.debug(f"Successfully extracted {len(features)} features from URL: {url}")
        logger.debug(f"Feature values: {features}")
        return features
        
    except Exception as e:
        logger.error(f"Critical error extracting features from URL '{url[:50]}...': {e}", exc_info=True)
        return None


def features_to_array(features):
    """
    Convert feature dictionary to ordered array for model prediction.
    
    Args:
        features (dict): Features dictionary
        
    Returns:
        list: Ordered feature values (guaranteed numeric, never None)
        
    This function is robust and returns valid numeric values even with missing keys.
    """
    feature_order = [
        'url_length', 'domain_length', 'num_dots', 'num_hyphens', 'num_underscores',
        'has_at_symbol', 'has_https', 'num_slashes', 'num_question_marks', 'has_shortener',
        'has_ip_address', 'num_parameters', 'has_double_slash', 'domain_has_numbers',
        'has_suspicious_keywords', 'is_trusted_domain', 'has_legitimate_tld', 
        'has_suspicious_tld', 'excessive_hyphens'
    ]
    
    try:
        # ---- INPUT VALIDATION ----
        if not isinstance(features, dict):
            logger.warning(f"Invalid features type: {type(features)}, expected dict")
            return [0] * len(feature_order)
        
        if len(features) == 0:
            logger.warning("Features dictionary is empty")
            return [0] * len(feature_order)
        
        # ---- CONVERT TO ARRAY ----
        feature_array = []
        
        for key in feature_order:
            value = features.get(key, 0)
            
            # Ensure value is numeric
            try:
                numeric_value = float(value) if value is not None else 0.0
                
                # Handle NaN and infinity
                if not (numeric_value == numeric_value):  # NaN check
                    numeric_value = 0.0
                    logger.debug(f"NaN detected in feature {key}, using 0")
                
                if not (-1e10 < numeric_value < 1e10):  # Sanity bound
                    numeric_value = 0.0
                    logger.debug(f"Feature {key} out of sane bounds, clamping to 0")
                
                feature_array.append(numeric_value)
                
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not convert feature {key}={value} to numeric: {e}")
                feature_array.append(0.0)
        
        if len(feature_array) != len(feature_order):
            logger.error(f"Feature array size mismatch: {len(feature_array)} vs {len(feature_order)}")
            return [0] * len(feature_order)
        
        return feature_array
        
    except Exception as e:
        logger.error(f"Error in features_to_array: {e}", exc_info=True)
        return [0] * len(feature_order)


def get_feature_names():
    """
    Get the names of all features in order.
    
    Returns:
        list: Ordered feature names
    """
    return [
        'URL Length', 'Domain Length', 'Number of Dots', 'Number of Hyphens', 
        'Number of Underscores', 'Has @ Symbol', 'Has HTTPS', 'Number of Slashes',
        'Number of Question Marks', 'Has Shortener', 'Has IP Address', 'Number of Parameters',
        'Has Double Slash', 'Domain Has Numbers', 'Has Suspicious Keywords',
        'Is Trusted Domain', 'Has Legitimate TLD', 'Has Suspicious TLD', 'Excessive Hyphens'
    ]
