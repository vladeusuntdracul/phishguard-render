import re
import requests
import os
from urllib.parse import urlparse, parse_qs
from typing import Dict, List
import logging
import socket
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLAnalyzer:
    """
    Analyze URLs for phishing indicators and reputation
    """
    
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.click', '.download']
        self.legitimate_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
            'paypal.com', 'ebay.com', 'wikipedia.org', 'reddit.com', 'github.com'
        ]
        self.url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link', 'is.gd']
        
        # API key for URL reputation service (if available)
        self.api_key = os.getenv('URL_REPUTATION_API_KEY', '')
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a URL for phishing indicators
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'url': url,
            'risk_score': 0,
            'risk_level': 'Low',
            'indicators': [],
            'domain_info': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Parse the URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            result['domain_info'] = {
                'domain': domain,
                'scheme': parsed_url.scheme,
                'path': parsed_url.path,
                'query': parsed_url.query
            }
            
            # 1. Domain analysis
            domain_score = self._analyze_domain(domain, result)
            
            # 2. URL structure analysis
            structure_score = self._analyze_url_structure(parsed_url, result)
            
            # 3. Check against known indicators
            indicator_score = self._check_phishing_indicators(url, parsed_url, result)
            
            # 4. IP address check
            ip_score = self._check_ip_address(domain, result)
            
            # 5. URL shortener check
            shortener_score = self._check_shortener(domain, result)
            
            # 6. Suspicious parameters check
            param_score = self._check_suspicious_params(parsed_url, result)
            
            # Calculate total risk score
            total_score = domain_score + structure_score + indicator_score + ip_score + shortener_score + param_score
            result['risk_score'] = min(total_score, 100)
            
            # Determine risk level
            if result['risk_score'] >= 70:
                result['risk_level'] = 'High'
            elif result['risk_score'] >= 40:
                result['risk_level'] = 'Medium'
            else:
                result['risk_level'] = 'Low'
            
            # Online reputation check (if API key available)
            if self.api_key:
                reputation_score = self._check_online_reputation(url, result)
                result['risk_score'] = min(result['risk_score'] + reputation_score, 100)
            
            logger.debug(f"URL analysis complete: {url} -> Risk: {result['risk_level']}, Score: {result['risk_score']}")
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            result['indicators'].append(f"Analysis error: {str(e)}")
            result['risk_score'] = 30  # Moderate risk on error
            result['risk_level'] = 'Medium'
        
        return result
    
    def _analyze_domain(self, domain: str, result: Dict) -> int:
        """Analyze domain for suspicious characteristics"""
        score = 0
        
        if not domain:
            return 0
        
        # Check for suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 25
                result['indicators'].append(f"Suspicious top-level domain: {tld}")
                break
        
        # Check for domain spoofing (similar to legitimate domains)
        for legit_domain in self.legitimate_domains:
            if domain != legit_domain and self._is_similar_domain(domain, legit_domain):
                score += 40
                result['indicators'].append(f"Possible domain spoofing of {legit_domain}")
                break
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            score += 15
            result['indicators'].append(f"Excessive subdomains ({subdomain_count})")
        
        # Check for suspicious characters in domain
        if re.search(r'[0-9]{3,}', domain):
            score += 15
            result['indicators'].append("Domain contains suspicious numeric patterns")
        
        # Check for mixed characters (leetspeak)
        if re.search(r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', domain):
            score += 10
            result['indicators'].append("Domain uses suspicious character mixing")
        
        # Check domain length
        if len(domain) > 50:
            score += 10
            result['indicators'].append("Unusually long domain name")
        
        # Check for URL shortener
        if any(shortener in domain for shortener in self.url_shorteners):
            score += 20
            result['indicators'].append("Uses URL shortening service")
        
        return score
    
    def _analyze_url_structure(self, parsed_url, result: Dict) -> int:
        """Analyze URL structure for suspicious patterns"""
        score = 0
        full_url = parsed_url.geturl()
        
        # Check URL length
        if len(full_url) > 200:
            score += 15
            result['indicators'].append("Unusually long URL")
        
        # Check for suspicious path patterns
        suspicious_paths = ['/login', '/verify', '/update', '/secure', '/account', '/banking', '/paypal']
        path = parsed_url.path.lower()
        for susp_path in suspicious_paths:
            if susp_path in path:
                score += 10
                result['indicators'].append(f"Suspicious path component: {susp_path}")
        
        # Check for excessive redirects (indicated by multiple domains in URL)
        if full_url.count('http') > 1:
            score += 25
            result['indicators'].append("URL contains multiple HTTP references")
        
        # Check for encoded characters
        if '%' in full_url and full_url.count('%') > 3:
            score += 15
            result['indicators'].append("URL contains excessive URL encoding")
        
        # Check for suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.zip']
        for ext in suspicious_extensions:
            if parsed_url.path.endswith(ext):
                score += 30
                result['indicators'].append(f"Suspicious file extension: {ext}")
        
        return score
    
    def _check_phishing_indicators(self, url: str, parsed_url, result: Dict) -> int:
        """Check for known phishing indicators"""
        score = 0
        url_lower = url.lower()
        
        # Common phishing keywords
        phishing_keywords = [
            'secure', 'account', 'update', 'verify', 'login', 'banking', 'paypal',
            'amazon', 'microsoft', 'apple', 'google', 'suspended', 'locked'
        ]
        
        keyword_count = sum(1 for keyword in phishing_keywords if keyword in url_lower)
        if keyword_count > 2:
            score += keyword_count * 5
            result['indicators'].append(f"Contains {keyword_count} phishing-related keywords")
        
        # Check for HTTPS in non-root position (fake HTTPS)
        if 'https' in parsed_url.path or 'https' in parsed_url.query:
            score += 20
            result['indicators'].append("Contains 'https' in path or parameters")
        
        # Check for suspicious query parameters
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            suspicious_params = ['redirect', 'return', 'url', 'link', 'goto', 'next']
            for param in suspicious_params:
                if param in query_params:
                    score += 10
                    result['indicators'].append(f"Suspicious parameter: {param}")
        
        return score
    
    def _check_ip_address(self, domain: str, result: Dict) -> int:
        """Check if domain is an IP address"""
        score = 0
        
        # Check for IPv4 address
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, domain):
            score += 30
            result['indicators'].append("Uses IP address instead of domain name")
        
        # Check for IPv6 address
        if ':' in domain and '[' in domain:
            score += 30
            result['indicators'].append("Uses IPv6 address instead of domain name")
        
        return score
    
    def _check_shortener(self, domain: str, result: Dict) -> int:
        """Check if URL uses a shortening service"""
        score = 0
        
        for shortener in self.url_shorteners:
            if shortener in domain:
                score += 20
                result['indicators'].append(f"Uses URL shortener: {shortener}")
                break
        
        return score
    
    def _check_suspicious_params(self, parsed_url, result: Dict) -> int:
        """Check for suspicious parameters that might indicate phishing"""
        score = 0
        
        if not parsed_url.query:
            return 0
        
        try:
            params = parse_qs(parsed_url.query)
            
            # Check for redirect parameters
            redirect_params = ['redirect', 'url', 'return', 'returnurl', 'goto', 'next', 'continue']
            for param_name in params:
                if param_name.lower() in redirect_params:
                    param_values = params[param_name]
                    for value in param_values:
                        if 'http' in value.lower():
                            score += 25
                            result['indicators'].append(f"Redirect parameter contains URL: {param_name}")
            
            # Check for base64 encoded parameters (common in phishing)
            for param_name, param_values in params.items():
                for value in param_values:
                    if len(value) > 20 and self._is_base64_like(value):
                        score += 15
                        result['indicators'].append(f"Parameter appears to be encoded: {param_name}")
            
        except Exception as e:
            logger.warning(f"Error checking URL parameters: {str(e)}")
        
        return score
    
    def _check_online_reputation(self, url: str, result: Dict) -> int:
        """Check URL against online reputation services (placeholder)"""
        # This is a placeholder for actual reputation checking services
        # In a real implementation, you would integrate with services like:
        # - VirusTotal API
        # - Google Safe Browsing API
        # - URLVoid API
        # - etc.
        
        if not self.api_key:
            return 0
        
        try:
            # Placeholder implementation
            logger.info(f"Checking online reputation for: {url}")
            # In real implementation, make API call here
            return 0
        except Exception as e:
            logger.error(f"Error checking online reputation: {str(e)}")
            return 0
    
    def _is_similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are suspiciously similar"""
        # Remove common prefixes
        domain1 = domain1.replace('www.', '')
        domain2 = domain2.replace('www.', '')
        
        # Check for common character substitutions
        substitutions = {
            'o': '0', 'l': '1', 'i': '1', 'e': '3', 's': '5',
            'g': '9', 'a': '@', 'o': 'oo', 'm': 'rn'
        }
        
        # Simple similarity check
        if len(domain1) == len(domain2):
            differences = sum(1 for a, b in zip(domain1, domain2) if a != b)
            if differences == 1:  # One character different
                return True
        
        # Check for character insertion/deletion
        if abs(len(domain1) - len(domain2)) == 1:
            longer = domain1 if len(domain1) > len(domain2) else domain2
            shorter = domain2 if len(domain1) > len(domain2) else domain1
            
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True
        
        return False
    
    def _is_base64_like(self, text: str) -> bool:
        """Check if text looks like base64 encoding"""
        import string
        
        # Base64 alphabet
        base64_chars = string.ascii_letters + string.digits + '+/='
        
        # Check if text contains only base64 characters
        if all(c in base64_chars for c in text):
            # Check if length is appropriate for base64 (multiple of 4)
            if len(text) % 4 == 0:
                return True
        
        return False
