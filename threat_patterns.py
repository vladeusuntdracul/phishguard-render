import re
from typing import List, Dict, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatPatterns:
    """
    Pattern matching for known phishing threats and suspicious content
    """
    
    def __init__(self):
        # Define threat patterns with their descriptions and scores
        self.patterns = {
            'urgency': {
                'patterns': [
                    r'\b(?:urgent|immediately|expires?\s+(?:today|soon)|act\s+now|limited\s+time|final\s+notice|last\s+chance)\b',
                    r'\b(?:don\'?t\s+miss\s+out|time\s+sensitive|expires?\s+in\s+\d+|hurry|rush)\b',
                    r'\b(?:immediate\s+action|respond\s+(?:immediately|asap)|within\s+\d+\s+hours?)\b'
                ],
                'description': 'Uses urgency language to pressure quick action',
                'base_score': 15
            },
            
            'financial_requests': {
                'patterns': [
                    r'\b(?:bank\s+account|credit\s+card|social\s+security|ssn|tax\s+(?:id|refund))\b',
                    r'\b(?:wire\s+transfer|bitcoin|cryptocurrency|paypal|venmo|zelle)\b',
                    r'\b(?:routing\s+number|account\s+number|pin\s+number|cvv|security\s+code)\b',
                    r'\b(?:verify\s+(?:account|identity|payment)|update\s+(?:billing|payment))\b'
                ],
                'description': 'Requests financial or personal information',
                'base_score': 25
            },
            
            'credential_harvesting': {
                'patterns': [
                    r'\b(?:password|username|login|sign\s+in|log\s+in)\b',
                    r'\b(?:verify\s+(?:your\s+)?(?:account|identity|email)|confirm\s+(?:your\s+)?identity)\b',
                    r'\b(?:suspended\s+account|locked\s+account|account\s+(?:suspension|locked?))\b',
                    r'\b(?:security\s+(?:alert|warning|notice)|unusual\s+(?:activity|login))\b'
                ],
                'description': 'Attempts to harvest login credentials',
                'base_score': 20
            },
            
            'fake_prizes': {
                'patterns': [
                    r'\b(?:congratulations?|winner?|selected|chosen|lucky)\b',
                    r'\b(?:won|win|prize|reward|gift|free\s+money|inheritance)\b',
                    r'\b(?:\$[\d,]+(?:\.\d{2})?|\d+\s+(?:million|thousand)\s+dollars?)\b',
                    r'\b(?:lottery|sweepstakes|raffle|contest)\b'
                ],
                'description': 'Fake prize or lottery scam indicators',
                'base_score': 20
            },
            
            'impersonation': {
                'patterns': [
                    r'\b(?:amazon|apple|microsoft|google|paypal|ebay|netflix|facebook)\b',
                    r'\b(?:bank\s+of\s+america|wells\s+fargo|chase|citibank|irs|government)\b',
                    r'\b(?:support\s+team|customer\s+(?:service|support)|security\s+team)\b',
                    r'\b(?:official|authorized|legitimate|trusted)\b'
                ],
                'description': 'Attempts to impersonate legitimate organizations',
                'base_score': 18
            },
            
            'threat_language': {
                'patterns': [
                    r'\b(?:legal\s+action|lawsuit|court|attorney|lawyer)\b',
                    r'\b(?:arrest|warrant|police|investigation|criminal)\b',
                    r'\b(?:penalty|fine|fee|charge|collection\s+agency)\b',
                    r'\b(?:close\s+(?:your\s+)?account|terminate|cancel|suspend)\b'
                ],
                'description': 'Uses threatening language to coerce action',
                'base_score': 22
            },
            
            'romance_scam': {
                'patterns': [
                    r'\b(?:love|beloved|darling|sweetheart|honey|dear)\b',
                    r'\b(?:lonely|widowed?|single|divorced|military|deployed)\b',
                    r'\b(?:trust|faith|god|destiny|fate|soul\s+mate)\b',
                    r'\b(?:emergency|hospital|surgery|accident|stranded)\b'
                ],
                'description': 'Romance scam language patterns',
                'base_score': 15
            },
            
            'business_scams': {
                'patterns': [
                    r'\b(?:business\s+(?:proposal|opportunity)|investment|profit|returns?)\b',
                    r'\b(?:confidential|discreet|private|secret|classified)\b',
                    r'\b(?:transfer|funds?|millions?|estate|inheritance)\b',
                    r'\b(?:partner|partnership|cooperation|collaboration)\b'
                ],
                'description': 'Business email compromise or investment scam',
                'base_score': 18
            },
            
            'tech_support_scam': {
                'patterns': [
                    r'\b(?:computer|pc|laptop|windows|mac|virus|malware)\b',
                    r'\b(?:infected|compromised|hacked|breach|security\s+threat)\b',
                    r'\b(?:tech\s+support|technical\s+support|it\s+support|help\s+desk)\b',
                    r'\b(?:remote\s+(?:access|desktop|connection)|teamviewer|anydesk)\b'
                ],
                'description': 'Technical support scam indicators',
                'base_score': 20
            },
            
            'suspicious_links': {
                'patterns': [
                    r'\b(?:click\s+(?:here|now|immediately)|download\s+(?:now|here))\b',
                    r'\b(?:follow\s+(?:this\s+)?link|visit\s+(?:this\s+)?(?:link|url|website))\b',
                    r'\b(?:open\s+(?:attachment|file)|run\s+(?:this\s+)?(?:file|program))\b',
                    r'\b(?:install|execute|activate|enable)\b'
                ],
                'description': 'Suspicious link or attachment instructions',
                'base_score': 12
            }
        }
        
        # Advanced patterns for more sophisticated detection
        self.advanced_patterns = {
            'domain_spoofing': {
                'pattern': r'(?:payp4l|amazom|microsft|g00gle|app1e)',
                'description': 'Domain name spoofing attempt',
                'base_score': 30
            },
            
            'unicode_spoofing': {
                'pattern': r'[а-я]',  # Cyrillic characters that look like Latin
                'description': 'Unicode character spoofing detected',
                'base_score': 25
            },
            
            'excessive_urgency': {
                'pattern': r'(?:urgent.*urgent|immediate.*immediate|expires.*expires)',
                'description': 'Excessive urgency indicators',
                'base_score': 20
            }
        }
    
    def check_patterns(self, content: str, subject: str = "") -> List[Dict]:
        """
        Check content against known threat patterns
        
        Args:
            content: Message content to analyze
            subject: Subject line to analyze
            
        Returns:
            List of matched patterns with scores and descriptions
        """
        results = []
        combined_text = f"{subject} {content}".lower()
        
        try:
            # Check basic patterns
            for category, pattern_data in self.patterns.items():
                matches = self._check_pattern_category(combined_text, pattern_data)
                if matches > 0:
                    # Calculate score based on number of matches
                    score = min(pattern_data['base_score'] + (matches - 1) * 5, 40)
                    results.append({
                        'category': category,
                        'matches': matches,
                        'score': score,
                        'description': pattern_data['description']
                    })
            
            # Check advanced patterns
            for category, pattern_data in self.advanced_patterns.items():
                if re.search(pattern_data['pattern'], combined_text, re.IGNORECASE):
                    results.append({
                        'category': category,
                        'matches': 1,
                        'score': pattern_data['base_score'],
                        'description': pattern_data['description']
                    })
            
            # Check for pattern combinations (more sophisticated threats)
            combination_results = self._check_pattern_combinations(combined_text)
            results.extend(combination_results)
            
            logger.debug(f"Pattern matching found {len(results)} threats")
            return results
            
        except Exception as e:
            logger.error(f"Error in pattern matching: {str(e)}")
            return []
    
    def _check_pattern_category(self, text: str, pattern_data: Dict) -> int:
        """Check a category of patterns against text"""
        total_matches = 0
        
        for pattern in pattern_data['patterns']:
            try:
                matches = len(re.findall(pattern, text, re.IGNORECASE))
                total_matches += matches
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern}, Error: {str(e)}")
                continue
        
        return total_matches
    
    def _check_pattern_combinations(self, text: str) -> List[Dict]:
        """Check for sophisticated pattern combinations"""
        results = []
        
        try:
            # Combination 1: Urgency + Financial request
            urgency_pattern = r'\b(?:urgent|immediate|expires?|act\s+now)\b'
            financial_pattern = r'\b(?:account|payment|credit|bank|verify)\b'
            
            if re.search(urgency_pattern, text, re.IGNORECASE) and \
               re.search(financial_pattern, text, re.IGNORECASE):
                results.append({
                    'category': 'urgency_financial_combo',
                    'matches': 1,
                    'score': 25,
                    'description': 'Combines urgency with financial requests'
                })
            
            # Combination 2: Impersonation + Credential harvesting
            impersonation_pattern = r'\b(?:amazon|apple|microsoft|paypal|bank)\b'
            credential_pattern = r'\b(?:login|password|verify|account|suspended)\b'
            
            if re.search(impersonation_pattern, text, re.IGNORECASE) and \
               re.search(credential_pattern, text, re.IGNORECASE):
                results.append({
                    'category': 'impersonation_credential_combo',
                    'matches': 1,
                    'score': 30,
                    'description': 'Impersonates legitimate service while requesting credentials'
                })
            
            # Combination 3: Prize + Action required
            prize_pattern = r'\b(?:won|winner?|prize|lottery|selected)\b'
            action_pattern = r'\b(?:click|claim|collect|verify|confirm)\b'
            
            if re.search(prize_pattern, text, re.IGNORECASE) and \
               re.search(action_pattern, text, re.IGNORECASE):
                results.append({
                    'category': 'prize_action_combo',
                    'matches': 1,
                    'score': 22,
                    'description': 'Fake prize requiring immediate action'
                })
            
            # Combination 4: Threat + Financial consequence
            threat_pattern = r'\b(?:legal|court|arrest|fine|penalty)\b'
            financial_consequence_pattern = r'\b(?:pay|payment|charge|fee|money)\b'
            
            if re.search(threat_pattern, text, re.IGNORECASE) and \
               re.search(financial_consequence_pattern, text, re.IGNORECASE):
                results.append({
                    'category': 'threat_financial_combo',
                    'matches': 1,
                    'score': 28,
                    'description': 'Uses threats to demand payment'
                })
            
        except Exception as e:
            logger.warning(f"Error checking pattern combinations: {str(e)}")
        
        return results
    
    def add_custom_pattern(self, category: str, patterns: List[str], description: str, base_score: int):
        """Add custom threat pattern"""
        try:
            # Validate patterns
            for pattern in patterns:
                re.compile(pattern)  # Test if pattern is valid
            
            self.patterns[category] = {
                'patterns': patterns,
                'description': description,
                'base_score': base_score
            }
            
            logger.info(f"Custom pattern category '{category}' added successfully")
            
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {str(e)}")
    
    def get_pattern_categories(self) -> List[str]:
        """Get list of available pattern categories"""
        return list(self.patterns.keys()) + list(self.advanced_patterns.keys())
    
    def get_pattern_details(self, category: str) -> Dict:
        """Get details for a specific pattern category"""
        if category in self.patterns:
            return self.patterns[category]
        elif category in self.advanced_patterns:
            return self.advanced_patterns[category]
        else:
            return {}
    
    def update_pattern_score(self, category: str, new_score: int):
        """Update the base score for a pattern category"""
        if category in self.patterns:
            self.patterns[category]['base_score'] = new_score
            logger.info(f"Updated score for '{category}' to {new_score}")
        elif category in self.advanced_patterns:
            self.advanced_patterns[category]['base_score'] = new_score
            logger.info(f"Updated score for '{category}' to {new_score}")
        else:
            logger.warning(f"Pattern category '{category}' not found")
    
    def disable_pattern(self, category: str):
        """Disable a pattern category"""
        if category in self.patterns:
            self.patterns[category]['disabled'] = True
            logger.info(f"Disabled pattern category '{category}'")
        elif category in self.advanced_patterns:
            self.advanced_patterns[category]['disabled'] = True
            logger.info(f"Disabled pattern category '{category}'")
    
    def enable_pattern(self, category: str):
        """Enable a pattern category"""
        if category in self.patterns:
            self.patterns[category]['disabled'] = False
            logger.info(f"Enabled pattern category '{category}'")
        elif category in self.advanced_patterns:
            self.advanced_patterns[category]['disabled'] = False
            logger.info(f"Enabled pattern category '{category}'")
    
    def analyze_text_complexity(self, text: str) -> Dict:
        """Analyze text complexity and writing patterns"""
        analysis = {
            'word_count': 0,
            'sentence_count': 0,
            'avg_word_length': 0,
            'capital_ratio': 0,
            'punctuation_ratio': 0,
            'suspicious_indicators': []
        }
        
        try:
            if not text:
                return analysis
            
            # Basic metrics
            words = text.split()
            analysis['word_count'] = len(words)
            analysis['sentence_count'] = len(re.split(r'[.!?]+', text))
            
            if words:
                analysis['avg_word_length'] = sum(len(word) for word in words) / len(words)
            
            # Character analysis
            if text:
                capitals = sum(1 for c in text if c.isupper())
                analysis['capital_ratio'] = capitals / len(text)
                
                punctuation = sum(1 for c in text if c in '.,!?;:')
                analysis['punctuation_ratio'] = punctuation / len(text)
            
            # Suspicious indicators
            if analysis['capital_ratio'] > 0.3:
                analysis['suspicious_indicators'].append('Excessive capitalization')
            
            if analysis['punctuation_ratio'] > 0.1:
                analysis['suspicious_indicators'].append('Excessive punctuation')
            
            if analysis['sentence_count'] > 0 and analysis['word_count'] / analysis['sentence_count'] > 50:
                analysis['suspicious_indicators'].append('Very long sentences')
            
            # Check for repeated characters
            if re.search(r'(.)\1{4,}', text):
                analysis['suspicious_indicators'].append('Repeated characters')
            
            # Check for mixed scripts
            if re.search(r'[а-я]', text) and re.search(r'[a-z]', text):
                analysis['suspicious_indicators'].append('Mixed character scripts')
            
        except Exception as e:
            logger.warning(f"Error analyzing text complexity: {str(e)}")
        
        return analysis
