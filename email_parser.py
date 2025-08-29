import email
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
from typing import Dict, List, Optional
import logging
from datetime import datetime
import quopri
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailParser:
    """
    Parse and extract information from email messages
    """
    
    def __init__(self):
        self.extracted_data = {}
    
    def parse_email(self, email_content: str) -> Dict:
        """
        Parse email content and extract relevant information
        
        Args:
            email_content: Raw email content (EML format or plain text)
            
        Returns:
            Dictionary containing parsed email data
        """
        result = {
            'sender': '',
            'recipient': '',
            'subject': '',
            'body': '',
            'headers': {},
            'attachments': [],
            'urls': [],
            'timestamp': '',
            'message_id': '',
            'return_path': '',
            'reply_to': '',
            'content_type': '',
            'encoding': '',
            'suspicious_headers': []
        }
        
        try:
            # Try to parse as email message
            if self._is_email_format(email_content):
                msg = email.message_from_string(email_content)
                result = self._extract_from_email_object(msg)
            else:
                # Treat as plain text
                result['body'] = email_content
                result['content_type'] = 'text/plain'
            
            # Extract URLs from body
            result['urls'] = self._extract_urls(result['body'])
            
            # Analyze headers for suspicious patterns
            result['suspicious_headers'] = self._analyze_headers(result['headers'])
            
            logger.info("Email parsing completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            # Return minimal result with error info
            result['body'] = email_content
            result['parsing_error'] = str(e)
            return result
    
    def _is_email_format(self, content: str) -> bool:
        """Check if content appears to be in email format"""
        # Look for common email headers
        email_headers = [
            'From:', 'To:', 'Subject:', 'Date:', 'Message-ID:',
            'Return-Path:', 'Received:', 'Content-Type:'
        ]
        
        content_upper = content.upper()
        header_count = sum(1 for header in email_headers if header.upper() in content_upper)
        
        # If we find multiple headers, it's likely an email
        return header_count >= 3
    
    def _extract_from_email_object(self, msg) -> Dict:
        """Extract information from email.message.Message object"""
        result = {
            'sender': '',
            'recipient': '',
            'subject': '',
            'body': '',
            'headers': {},
            'attachments': [],
            'urls': [],
            'timestamp': '',
            'message_id': '',
            'return_path': '',
            'reply_to': '',
            'content_type': '',
            'encoding': '',
            'suspicious_headers': []
        }
        
        try:
            # Extract headers
            result['headers'] = dict(msg.items())
            
            # Extract basic information
            result['sender'] = self._decode_header(msg.get('From', ''))
            result['recipient'] = self._decode_header(msg.get('To', ''))
            result['subject'] = self._decode_header(msg.get('Subject', ''))
            result['timestamp'] = msg.get('Date', '')
            result['message_id'] = msg.get('Message-ID', '')
            result['return_path'] = msg.get('Return-Path', '')
            result['reply_to'] = msg.get('Reply-To', '')
            result['content_type'] = msg.get_content_type()
            
            # Extract body content
            result['body'] = self._extract_body(msg)
            
            # Extract attachments info
            result['attachments'] = self._extract_attachments_info(msg)
            
            return result
            
        except Exception as e:
            logger.error(f"Error extracting from email object: {str(e)}")
            result['parsing_error'] = str(e)
            return result
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header that might be encoded"""
        if not header_value:
            return ''
        
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding)
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            
            return decoded_string
            
        except Exception as e:
            logger.warning(f"Error decoding header '{header_value}': {str(e)}")
            return header_value
    
    def _extract_body(self, msg) -> str:
        """Extract body content from email message"""
        body_text = ''
        
        try:
            if msg.is_multipart():
                # Handle multipart messages
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    # Skip attachments
                    if "attachment" in content_disposition:
                        continue
                    
                    # Extract text content
                    if content_type == "text/plain":
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                body_text += payload.decode(charset, errors='ignore')
                            else:
                                body_text += str(payload)
                        except Exception as e:
                            logger.warning(f"Error decoding text part: {str(e)}")
                    
                    elif content_type == "text/html":
                        # Extract text from HTML (basic extraction)
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                html_content = payload.decode(charset, errors='ignore')
                            else:
                                html_content = str(payload)
                            
                            # Simple HTML tag removal
                            text_from_html = self._strip_html_tags(html_content)
                            body_text += text_from_html
                        except Exception as e:
                            logger.warning(f"Error decoding HTML part: {str(e)}")
            
            else:
                # Handle single part messages
                content_type = msg.get_content_type()
                charset = msg.get_content_charset() or 'utf-8'
                
                try:
                    payload = msg.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body_text = payload.decode(charset, errors='ignore')
                    else:
                        body_text = str(payload)
                    
                    # If it's HTML, strip tags
                    if content_type == "text/html":
                        body_text = self._strip_html_tags(body_text)
                        
                except Exception as e:
                    logger.warning(f"Error decoding message payload: {str(e)}")
                    # Fallback to raw payload
                    body_text = str(msg.get_payload())
            
        except Exception as e:
            logger.error(f"Error extracting body: {str(e)}")
            # Fallback to string representation
            body_text = str(msg)
        
        return body_text.strip()
    
    def _strip_html_tags(self, html_content: str) -> str:
        """Remove HTML tags and extract text content"""
        try:
            # Remove HTML tags using regex
            clean_text = re.sub(r'<[^>]+>', ' ', html_content)
            
            # Replace HTML entities
            html_entities = {
                '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
                '&#39;': "'", '&nbsp;': ' ', '&hellip;': '...'
            }
            
            for entity, replacement in html_entities.items():
                clean_text = clean_text.replace(entity, replacement)
            
            # Clean up whitespace
            clean_text = re.sub(r'\s+', ' ', clean_text)
            
            return clean_text.strip()
            
        except Exception as e:
            logger.warning(f"Error stripping HTML tags: {str(e)}")
            return html_content
    
    def _extract_attachments_info(self, msg) -> List[Dict]:
        """Extract information about attachments"""
        attachments = []
        
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    if "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            # Decode filename if necessary
                            filename = self._decode_header(filename)
                            
                            attachment_info = {
                                'filename': filename,
                                'content_type': part.get_content_type(),
                                'size': len(str(part.get_payload()))
                            }
                            
                            # Check for suspicious file types
                            suspicious_extensions = [
                                '.exe', '.scr', '.bat', '.com', '.pif', '.jar',
                                '.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm'
                            ]
                            
                            for ext in suspicious_extensions:
                                if filename.lower().endswith(ext):
                                    attachment_info['suspicious'] = True
                                    attachment_info['warning'] = f"Potentially dangerous file type: {ext}"
                                    break
                            
                            attachments.append(attachment_info)
            
        except Exception as e:
            logger.warning(f"Error extracting attachment info: {str(e)}")
        
        return attachments
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text content"""
        if not text:
            return []
        
        # URL pattern (basic)
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        try:
            urls = re.findall(url_pattern, text)
            # Remove duplicates while preserving order
            unique_urls = list(dict.fromkeys(urls))
            return unique_urls
            
        except Exception as e:
            logger.warning(f"Error extracting URLs: {str(e)}")
            return []
    
    def _analyze_headers(self, headers: Dict) -> List[str]:
        """Analyze headers for suspicious patterns"""
        suspicious_indicators = []
        
        try:
            # Check for missing or suspicious headers
            if not headers.get('Message-ID'):
                suspicious_indicators.append("Missing Message-ID header")
            
            if not headers.get('Date'):
                suspicious_indicators.append("Missing Date header")
            
            # Check for suspicious Return-Path
            return_path = headers.get('Return-Path', '')
            sender = headers.get('From', '')
            if return_path and sender:
                # Extract domain from both
                return_domain = self._extract_domain_from_email(return_path)
                sender_domain = self._extract_domain_from_email(sender)
                
                if return_domain and sender_domain and return_domain != sender_domain:
                    suspicious_indicators.append(f"Return-Path domain ({return_domain}) differs from sender domain ({sender_domain})")
            
            # Check for suspicious Received headers
            received_headers = [v for k, v in headers.items() if k.lower() == 'received']
            if len(received_headers) < 2:
                suspicious_indicators.append("Insufficient Received headers")
            
            # Check for suspicious Reply-To
            reply_to = headers.get('Reply-To', '')
            if reply_to and sender:
                if reply_to.lower() != sender.lower():
                    suspicious_indicators.append("Reply-To address differs from sender")
            
            # Check for suspicious User-Agent or X-Mailer
            user_agent = headers.get('User-Agent', '') or headers.get('X-Mailer', '')
            suspicious_agents = ['mass', 'bulk', 'spam', 'bot']
            if any(agent in user_agent.lower() for agent in suspicious_agents):
                suspicious_indicators.append(f"Suspicious mail client: {user_agent}")
            
            # Check for suspicious X-Originating-IP
            orig_ip = headers.get('X-Originating-IP', '')
            if orig_ip and self._is_suspicious_ip(orig_ip):
                suspicious_indicators.append(f"Suspicious originating IP: {orig_ip}")
            
        except Exception as e:
            logger.warning(f"Error analyzing headers: {str(e)}")
        
        return suspicious_indicators
    
    def _extract_domain_from_email(self, email_addr: str) -> Optional[str]:
        """Extract domain from email address"""
        try:
            # Handle format like "Name <email@domain.com>"
            if '<' in email_addr and '>' in email_addr:
                email_addr = email_addr.split('<')[1].split('>')[0]
            
            # Extract domain part
            if '@' in email_addr:
                return email_addr.split('@')[1].lower()
                
        except Exception:
            pass
        
        return None
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            # Remove angle brackets if present
            ip = ip.strip('<>')
            
            # Check for private/local IP ranges (these might be suspicious in headers)
            private_ranges = [
                '192.168.', '10.', '172.16.', '127.', '169.254.'
            ]
            
            for private_range in private_ranges:
                if ip.startswith(private_range):
                    return True
            
            # Check for common VPN/proxy IP ranges (this would require a more comprehensive list)
            # This is a simplified check
            suspicious_ranges = ['185.', '95.', '46.']  # Common VPN ranges (simplified)
            for susp_range in suspicious_ranges:
                if ip.startswith(susp_range):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def parse_multiple_emails(self, email_contents: List[str]) -> List[Dict]:
        """Parse multiple email messages"""
        results = []
        
        for i, content in enumerate(email_contents):
            try:
                result = self.parse_email(content)
                result['email_index'] = i
                results.append(result)
            except Exception as e:
                logger.error(f"Error parsing email {i}: {str(e)}")
                results.append({
                    'email_index': i,
                    'parsing_error': str(e),
                    'body': content[:200] + '...' if len(content) > 200 else content
                })
        
        return results
