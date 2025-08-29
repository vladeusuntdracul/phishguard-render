import re
import nltk
import spacy
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
from ml_model import PhishingClassifier
from url_analyzer import URLAnalyzer
from threat_patterns import ThreatPatterns

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('vader_lexicon', quiet=True)
except:
    pass

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    # Fallback to basic processing if spaCy model not available
    nlp = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDetector:
    """
    Main phishing detection engine that coordinates various analysis modules
    """
    
    def __init__(self):
        self.ml_classifier = PhishingClassifier()
        self.url_analyzer = URLAnalyzer()
        self.threat_patterns = ThreatPatterns()
        self.sensitivity = 0.7
        self.custom_patterns = {}
        self.url_checking_enabled = True
        
        logger.info("PhishingDetector initialized successfully")
    
    def analyze_message(self, content: str, sender: str = "", subject: str = "") -> Dict[str, Any]:
        """
        Analyze a message/email for phishing indicators
        
        Args:
            content: Message content
            sender: Sender email address
            subject: Subject line
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            # Initialize result structure
            result = {
                'risk_level': 'Low',
                'confidence_score': 0.0,
                'threats': [],
                'indicators': [],
                'urls': [],
                'timestamp': datetime.now().isoformat()
            }
            
            if not content.strip():
                result['indicators'].append("Empty or blank message content")
                return result
            
            # 1. Text-based analysis
            text_score, text_threats, text_indicators = self._analyze_text(content, subject)
            result['threats'].extend(text_threats)
            result['indicators'].extend(text_indicators)
            
            # 2. Sender analysis
            sender_score, sender_threats, sender_indicators = self._analyze_sender(sender)
            result['threats'].extend(sender_threats)
            result['indicators'].extend(sender_indicators)
            
            # 3. URL analysis
            url_score, url_threats, urls_data = self._analyze_urls(content)
            result['threats'].extend(url_threats)
            result['urls'] = urls_data
            
            # 4. Machine learning classification
            ml_score = self._ml_classify(content, sender, subject)
            
            # 5. Pattern matching
            pattern_score, pattern_threats = self._pattern_matching(content, subject)
            result['threats'].extend(pattern_threats)
            
            # Calculate overall confidence score
            scores = [text_score, sender_score, url_score, ml_score, pattern_score]
            weights = [0.25, 0.15, 0.25, 0.25, 0.10]
            
            result['confidence_score'] = sum(score * weight for score, weight in zip(scores, weights))
            
            # Determine risk level based on confidence and sensitivity
            if result['confidence_score'] >= (80 * self.sensitivity):
                result['risk_level'] = 'High'
            elif result['confidence_score'] >= (50 * self.sensitivity):
                result['risk_level'] = 'Medium'
            else:
                result['risk_level'] = 'Low'
            
            # Add meta information
            if result['confidence_score'] > 90:
                result['indicators'].append("Very high confidence phishing attempt detected")
            elif result['confidence_score'] > 70:
                result['indicators'].append("High probability phishing characteristics found")
            
            logger.info(f"Message analysis complete. Risk: {result['risk_level']}, Score: {result['confidence_score']:.1f}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing message: {str(e)}")
            return {
                'risk_level': 'Unknown',
                'confidence_score': 0.0,
                'threats': [{'type': 'Analysis Error', 'description': f'Error during analysis: {str(e)}'}],
                'indicators': ['Analysis could not be completed'],
                'urls': [],
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_text(self, content: str, subject: str = "") -> tuple:
        """Analyze text content for phishing indicators"""
        score = 0
        threats = []
        indicators = []
        
        combined_text = f"{subject} {content}".lower()
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediate', 'expires today', 'act now', 'limited time', 
                        'expires soon', 'final notice', 'last chance', 'don\'t miss out']
        urgency_count = sum(1 for word in urgency_words if word in combined_text)
        if urgency_count > 0:
            score += min(urgency_count * 15, 40)
            threats.append({
                'type': 'Urgency Language',
                'description': f'Contains {urgency_count} urgency indicators'
            })
            indicators.append(f"Uses urgent language ({urgency_count} indicators found)")
        
        # Financial/credential requests
        financial_words = ['bank account', 'credit card', 'password', 'login', 'verify account',
                          'social security', 'tax refund', 'wire transfer', 'bitcoin', 'cryptocurrency']
        financial_count = sum(1 for word in financial_words if word in combined_text)
        if financial_count > 0:
            score += min(financial_count * 12, 35)
            threats.append({
                'type': 'Credential/Financial Request',
                'description': f'Requests sensitive information ({financial_count} indicators)'
            })
            indicators.append(f"Requests sensitive information ({financial_count} types)")
        
        # Suspicious phrases
        suspicious_phrases = ['click here immediately', 'verify your account', 'suspended account',
                            'confirm your identity', 'update payment', 'security alert']
        suspicious_count = sum(1 for phrase in suspicious_phrases if phrase in combined_text)
        if suspicious_count > 0:
            score += min(suspicious_count * 10, 30)
            indicators.append(f"Contains suspicious phrases ({suspicious_count} found)")
        
        # Grammar/spelling analysis
        if self._poor_grammar_check(content):
            score += 15
            indicators.append("Poor grammar or spelling detected")
        
        # Emotional manipulation
        emotion_words = ['congratulations', 'winner', 'selected', 'lucky', 'free money', 'inheritance']
        emotion_count = sum(1 for word in emotion_words if word in combined_text)
        if emotion_count > 0:
            score += min(emotion_count * 8, 25)
            indicators.append(f"Uses emotional manipulation ({emotion_count} indicators)")
        
        return min(score, 100), threats, indicators
    
    def _analyze_sender(self, sender: str) -> tuple:
        """Analyze sender information"""
        score = 0
        threats = []
        indicators = []
        
        if not sender:
            return 0, threats, indicators
        
        sender_lower = sender.lower()
        
        # Check for spoofed domains
        legitimate_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                            'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
                            'paypal.com', 'ebay.com']
        
        spoofed_patterns = ['g-mail', 'gmai1', 'yahooo', 'outlok', 'microsft', 'payp4l', 'amazom']
        for pattern in spoofed_patterns:
            if pattern in sender_lower:
                score += 40
                threats.append({
                    'type': 'Domain Spoofing',
                    'description': f'Suspicious domain pattern detected: {pattern}'
                })
                indicators.append(f"Suspicious sender domain: {pattern}")
                break
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc']
        for tld in suspicious_tlds:
            if sender_lower.endswith(tld):
                score += 25
                indicators.append(f"Suspicious top-level domain: {tld}")
                break
        
        # Random characters in domain
        if re.search(r'[0-9]{3,}', sender) or len(re.findall(r'[a-z]{1}[0-9]{1}', sender)) > 2:
            score += 20
            indicators.append("Sender domain contains suspicious character patterns")
        
        # Check for display name spoofing
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            actual_email = sender.split('<')[1].split('>')[0]
            
            if display_name and actual_email:
                # Check if display name suggests one service but email is from another
                if any(service in display_name.lower() for service in ['paypal', 'amazon', 'apple', 'microsoft']) and \
                   not any(service in actual_email.lower() for service in ['paypal', 'amazon', 'apple', 'microsoft']):
                    score += 35
                    threats.append({
                        'type': 'Display Name Spoofing',
                        'description': f'Display name "{display_name}" doesn\'t match email domain'
                    })
                    indicators.append("Display name spoofing detected")
        
        return min(score, 100), threats, indicators
    
    def _analyze_urls(self, content: str) -> tuple:
        """Analyze URLs in the content"""
        score = 0
        threats = []
        urls_data = []
        
        if not self.url_checking_enabled:
            return 0, threats, urls_data
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            url_analysis = self.url_analyzer.analyze_url(url)
            urls_data.append(url_analysis)
            
            if url_analysis['risk_score'] > 70:
                score += 40
                threats.append({
                    'type': 'Malicious URL',
                    'description': f'High-risk URL detected: {url}'
                })
            elif url_analysis['risk_score'] > 40:
                score += 20
                threats.append({
                    'type': 'Suspicious URL',
                    'description': f'Potentially suspicious URL: {url}'
                })
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link']
        for url in urls:
            if any(shortener in url for shortener in shorteners):
                score += 15
                threats.append({
                    'type': 'URL Shortener',
                    'description': f'Uses URL shortener which can hide destination: {url}'
                })
        
        return min(score, 100), threats, urls_data
    
    def _ml_classify(self, content: str, sender: str, subject: str) -> float:
        """Use machine learning model for classification"""
        try:
            prediction = self.ml_classifier.predict(content, sender, subject)
            return prediction * 100  # Convert to percentage
        except Exception as e:
            logger.warning(f"ML classification failed: {str(e)}")
            return 0.0
    
    def _pattern_matching(self, content: str, subject: str) -> tuple:
        """Match against known phishing patterns"""
        score = 0
        threats = []
        
        # Use threat patterns module
        pattern_results = self.threat_patterns.check_patterns(content, subject)
        
        for result in pattern_results:
            score += result['score']
            threats.append({
                'type': 'Pattern Match',
                'description': result['description']
            })
        
        # Check custom patterns
        combined_text = f"{subject} {content}".lower()
        for pattern_name, pattern_data in self.custom_patterns.items():
            if re.search(pattern_data['regex'], combined_text, re.IGNORECASE):
                score += 20
                threats.append({
                    'type': 'Custom Pattern',
                    'description': f"Matches custom pattern '{pattern_name}': {pattern_data['description']}"
                })
        
        return min(score, 100), threats
    
    def _poor_grammar_check(self, text: str) -> bool:
        """Basic grammar/spelling check"""
        # Simple heuristics for poor grammar
        sentences = text.split('.')
        
        # Check for excessive capitalization
        if sum(1 for c in text if c.isupper()) / len(text) > 0.3:
            return True
        
        # Check for repeated punctuation
        if re.search(r'[!]{2,}|[?]{2,}|[.]{3,}', text):
            return True
        
        # Check for common misspellings
        misspellings = ['recieve', 'occured', 'seperate', 'definately', 'loose' + 'instead of lose']
        return any(word in text.lower() for word in misspellings)
    
    def set_sensitivity(self, sensitivity: float):
        """Set detection sensitivity (0.1 to 1.0)"""
        self.sensitivity = max(0.1, min(1.0, sensitivity))
        logger.info(f"Detection sensitivity set to {self.sensitivity}")
    
    def enable_url_checking(self):
        """Enable URL reputation checking"""
        self.url_checking_enabled = True
        logger.info("URL checking enabled")
    
    def disable_url_checking(self):
        """Disable URL reputation checking"""
        self.url_checking_enabled = False
        logger.info("URL checking disabled")
    
    def add_custom_pattern(self, name: str, regex: str, description: str):
        """Add custom threat detection pattern"""
        try:
            # Test the regex
            re.compile(regex)
            self.custom_patterns[name] = {
                'regex': regex,
                'description': description
            }
            logger.info(f"Custom pattern '{name}' added successfully")
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {str(e)}")
    
    def retrain_model(self):
        """Retrain the machine learning model"""
        try:
            self.ml_classifier.retrain()
            logger.info("Model retrained successfully")
        except Exception as e:
            logger.error(f"Model retraining failed: {str(e)}")
            raise
