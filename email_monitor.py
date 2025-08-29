import imaplib
import email
import time
import ssl
from typing import Dict, List, Optional
import logging
from datetime import datetime, timedelta
import threading
from email_parser import EmailParser
from phishing_detector import PhishingDetector
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailMonitor:
    """
    Automatically monitor email accounts for incoming messages and detect threats
    """
    
    def __init__(self):
        self.email_parser = EmailParser()
        self.phishing_detector = PhishingDetector()
        self.connections = {}
        self.monitoring_active = False
        self.monitor_thread = None
        self.detected_threats = []
        
        # Configuration
        self.check_interval = 30  # seconds
        self.max_messages_per_check = 10
        
    def add_email_account(self, account_name: str, email_address: str, 
                         password: str, imap_server: str, port: int = 993) -> bool:
        """
        Add an email account for monitoring
        
        Args:
            account_name: Friendly name for the account
            email_address: Email address
            password: Email password or app password
            imap_server: IMAP server address
            port: IMAP port (default 993 for SSL)
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Test connection
            context = ssl.create_default_context()
            with imaplib.IMAP4_SSL(imap_server, port, ssl_context=context) as mail:
                mail.login(email_address, password)
                mail.select('INBOX')
                
            # Store connection details
            self.connections[account_name] = {
                'email': email_address,
                'password': password,
                'server': imap_server,
                'port': port,
                'last_check': datetime.now(),
                'last_uid': None
            }
            
            logger.info(f"Email account '{account_name}' added successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add email account '{account_name}': {str(e)}")
            return False
    
    def remove_email_account(self, account_name: str):
        """Remove an email account from monitoring"""
        if account_name in self.connections:
            del self.connections[account_name]
            logger.info(f"Email account '{account_name}' removed")
        else:
            logger.warning(f"Email account '{account_name}' not found")
    
    def start_monitoring(self):
        """Start automatic email monitoring"""
        if self.monitoring_active:
            logger.warning("Email monitoring is already active")
            return
        
        if not self.connections:
            logger.warning("No email accounts configured for monitoring")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Email monitoring started")
    
    def stop_monitoring(self):
        """Stop automatic email monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("Email monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                for account_name, config in self.connections.items():
                    if not self.monitoring_active:
                        break
                    
                    self._check_account(account_name, config)
                
                # Wait before next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(self.check_interval)
    
    def _check_account(self, account_name: str, config: Dict):
        """Check a specific email account for new messages"""
        try:
            context = ssl.create_default_context()
            with imaplib.IMAP4_SSL(config['server'], config['port'], ssl_context=context) as mail:
                mail.login(config['email'], config['password'])
                mail.select('INBOX')
                
                # Search for new messages since last check
                search_criteria = 'UNSEEN'
                if config['last_check']:
                    # Search for messages since last check
                    date_str = config['last_check'].strftime('%d-%b-%Y')
                    search_criteria = f'SINCE {date_str} UNSEEN'
                
                _, message_numbers = mail.search(None, search_criteria)
                
                if message_numbers[0]:
                    message_list = message_numbers[0].split()
                    
                    # Limit number of messages to process
                    recent_messages = message_list[-self.max_messages_per_check:]
                    
                    for msg_num in recent_messages:
                        if not self.monitoring_active:
                            break
                        
                        self._process_message(mail, msg_num, account_name, config['email'])
                
                # Update last check time
                config['last_check'] = datetime.now()
                
        except Exception as e:
            logger.error(f"Error checking account '{account_name}': {str(e)}")
    
    def _process_message(self, mail, msg_num: bytes, account_name: str, email_address: str):
        """Process a single email message"""
        try:
            # Fetch the message
            _, msg_data = mail.fetch(msg_num, '(RFC822)')
            email_body = msg_data[0][1]
            
            if isinstance(email_body, bytes):
                email_content = email_body.decode('utf-8', errors='ignore')
            else:
                email_content = str(email_body)
            
            # Parse the email
            parsed_email = self.email_parser.parse_email(email_content)
            
            # Analyze for threats
            analysis_result = self.phishing_detector.analyze_message(
                content=parsed_email['body'],
                sender=parsed_email['sender'],
                subject=parsed_email['subject']
            )
            
            # If threat detected, store and log
            if analysis_result['risk_level'] in ['Medium', 'High']:
                threat_info = {
                    'account_name': account_name,
                    'account_email': email_address,
                    'timestamp': datetime.now().isoformat(),
                    'sender': parsed_email['sender'],
                    'subject': parsed_email['subject'],
                    'risk_level': analysis_result['risk_level'],
                    'confidence_score': analysis_result['confidence_score'],
                    'threats': analysis_result['threats'],
                    'indicators': analysis_result['indicators'],
                    'message_preview': parsed_email['body'][:200] + '...' if len(parsed_email['body']) > 200 else parsed_email['body']
                }
                
                self.detected_threats.append(threat_info)
                
                # Log the detection
                logger.warning(f"THREAT DETECTED in {account_name}: {analysis_result['risk_level']} risk - {parsed_email['subject']}")
                
                # Optional: Mark as read or move to specific folder
                # mail.store(msg_num, '+FLAGS', '\\Seen')
                
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
    
    def get_detected_threats(self, hours_back: int = 24) -> List[Dict]:
        """Get detected threats from the last specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        recent_threats = [
            threat for threat in self.detected_threats
            if datetime.fromisoformat(threat['timestamp']) >= cutoff_time
        ]
        
        return recent_threats
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'active': self.monitoring_active,
            'accounts_configured': len(self.connections),
            'total_threats_detected': len(self.detected_threats),
            'check_interval': self.check_interval,
            'accounts': list(self.connections.keys())
        }
    
    def configure_settings(self, check_interval: int = None, max_messages: int = None):
        """Configure monitoring settings"""
        if check_interval is not None:
            self.check_interval = max(10, check_interval)  # Minimum 10 seconds
            
        if max_messages is not None:
            self.max_messages_per_check = max(1, max_messages)
        
        logger.info(f"Settings updated: check_interval={self.check_interval}s, max_messages={self.max_messages_per_check}")
    
    def test_email_connection(self, email_address: str, password: str, 
                            imap_server: str, port: int = 993) -> Dict:
        """Test email connection without adding to monitoring"""
        result = {
            'success': False,
            'message': '',
            'inbox_count': 0
        }
        
        try:
            context = ssl.create_default_context()
            with imaplib.IMAP4_SSL(imap_server, port, ssl_context=context) as mail:
                mail.login(email_address, password)
                mail.select('INBOX')
                
                # Get inbox message count
                _, message_count = mail.search(None, 'ALL')
                result['inbox_count'] = len(message_count[0].split()) if message_count[0] else 0
                
                result['success'] = True
                result['message'] = 'Connection successful'
                
        except Exception as e:
            result['message'] = f"Connection failed: {str(e)}"
        
        return result


class SMSMonitor:
    """
    Monitor SMS messages (placeholder for SMS API integration)
    """
    
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.detected_threats = []
        self.monitoring_active = False
        
        # SMS API configuration (would need actual service)
        self.sms_api_key = os.getenv('SMS_API_KEY', '')
        self.phone_number = os.getenv('MONITOR_PHONE_NUMBER', '')
    
    def configure_sms_monitoring(self, api_key: str, phone_number: str):
        """Configure SMS monitoring (placeholder)"""
        self.sms_api_key = api_key
        self.phone_number = phone_number
        logger.info("SMS monitoring configured")
    
    def start_sms_monitoring(self):
        """Start SMS monitoring (placeholder)"""
        if not self.sms_api_key or not self.phone_number:
            logger.warning("SMS API key and phone number required for SMS monitoring")
            return False
        
        logger.info("SMS monitoring would start here (requires SMS service integration)")
        return True
    
    def analyze_sms(self, message: str, sender: str = "") -> Dict:
        """Analyze an SMS message for phishing"""
        return self.phishing_detector.analyze_message(
            content=message,
            sender=sender,
            subject="SMS Message"
        )


class RealTimeAlerts:
    """
    Handle real-time alerts for detected threats
    """
    
    def __init__(self):
        self.alert_callbacks = []
        self.alert_methods = {
            'email': False,
            'desktop': False,
            'webhook': False
        }
    
    def add_alert_callback(self, callback_func):
        """Add a callback function for threat alerts"""
        self.alert_callbacks.append(callback_func)
    
    def send_threat_alert(self, threat_info: Dict):
        """Send alert for detected threat"""
        for callback in self.alert_callbacks:
            try:
                callback(threat_info)
            except Exception as e:
                logger.error(f"Error in alert callback: {str(e)}")
    
    def configure_email_alerts(self, smtp_server: str, smtp_port: int, 
                             username: str, password: str, recipient: str):
        """Configure email alerts (placeholder)"""
        logger.info("Email alerts configured")
    
    def configure_desktop_notifications(self, enabled: bool = True):
        """Configure desktop notifications"""
        self.alert_methods['desktop'] = enabled
        logger.info(f"Desktop notifications {'enabled' if enabled else 'disabled'}")
    
    def configure_webhook_alerts(self, webhook_url: str):
        """Configure webhook alerts"""
        self.alert_methods['webhook'] = bool(webhook_url)
        logger.info("Webhook alerts configured")