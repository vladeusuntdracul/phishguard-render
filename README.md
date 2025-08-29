# Intelligent Phishing Detection System

An advanced phishing detection system built with Streamlit that provides both manual analysis and automatic monitoring capabilities for emails and messages.

## Features

### Manual Analysis
- **Email/Message Analysis**: Paste content or upload EML files for immediate threat assessment
- **Real-time Risk Scoring**: Machine learning-based confidence scoring with threat categorization
- **URL Analysis**: Comprehensive URL reputation checking and suspicious link detection
- **Pattern Matching**: Advanced regex-based detection of known phishing patterns
- **Interactive Dashboard**: Visual analytics and threat history tracking

### Automatic Monitoring
- **Real-time Email Monitoring**: Connect email accounts via IMAP for continuous scanning
- **Multi-Account Support**: Monitor multiple email accounts simultaneously
- **SMS Integration Framework**: Ready for SMS monitoring via API providers
- **Instant Alerts**: Configurable notifications for detected threats
- **Background Processing**: Non-intrusive monitoring that runs in the background

### Security Features
- **Multi-layered Detection**: Combines ML, pattern matching, and heuristic analysis
- **Threat Intelligence**: Built-in patterns for common phishing tactics
- **Sender Reputation**: Analysis of sender domains and spoofing attempts
- **Content Analysis**: Deep text analysis including urgency detection and social engineering patterns

## Project Structure

```
phishing_detection_system/
├── app.py                     # Main Streamlit application
├── phishing_detector.py       # Core detection engine
├── ml_model.py               # Machine learning classifier
├── email_parser.py           # Email parsing and processing
├── email_monitor.py          # Automatic monitoring system
├── url_analyzer.py           # URL reputation analysis
├── threat_patterns.py        # Pattern matching rules
├── .streamlit/
│   └── config.toml           # Streamlit configuration
├── pyproject.toml            # Python dependencies
└── project_dependencies.txt  # Dependency list for deployment
```

## Installation

### Requirements
- Python 3.8 or higher
- Internet connection for ML model downloads
- Email account credentials for automatic monitoring

### Dependencies
```
streamlit>=1.28.0
pandas>=1.5.0
plotly>=5.0.0
scikit-learn>=1.0.0
nltk>=3.8
spacy>=3.4.0
requests>=2.28.0
```

### Local Installation
1. Extract the project files
2. Install dependencies:
   ```bash
   pip install -r project_dependencies.txt
   ```
3. Download NLTK data:
   ```python
   import nltk
   nltk.download('punkt')
   nltk.download('stopwords')
   nltk.download('vader_lexicon')
   ```
4. Run the application:
   ```bash
   streamlit run app.py --server.port 5000
   ```

## Usage

### Manual Analysis
1. Open the application in your browser
2. Navigate to "Message Analysis"
3. Paste email content or upload an EML file
4. Click "Analyze Message" to get threat assessment

### Automatic Monitoring
1. Go to "Auto Monitor" page
2. Add your email account credentials
3. Test the connection
4. Start monitoring
5. Configure alerts as needed

### Supported Email Providers
- Gmail (use App Password)
- Outlook/Hotmail
- Yahoo Mail
- Any IMAP-enabled email service

## Configuration

### Email Monitoring Setup
1. **Gmail**: Enable 2FA and generate an App Password
2. **Outlook**: Use regular password or App Password
3. **Yahoo**: Generate App Password in account settings
4. **Custom IMAP**: Provide server details and credentials

### Alert Configuration
- Desktop notifications
- Email alerts to alternate address
- Webhook integrations for external systems

## Security Notes

- Email credentials are stored in memory only during the session
- No data is transmitted outside your local environment
- All analysis happens locally using the built-in ML model
- Consider using app-specific passwords instead of main account passwords

## Deployment Options

### Local Development
Run directly with Streamlit for development and testing.

### Cloud Deployment
- **Replit**: Direct deployment with built-in environment
- **Heroku**: Use Procfile and requirements.txt
- **AWS/GCP**: Deploy as containerized application
- **Railway/Render**: Simple cloud deployment

### Docker Deployment
Create a Dockerfile for containerized deployment across any platform.

## Advanced Features

### Custom Pattern Addition
Add custom threat patterns through the System Settings page for organization-specific threats.

### Model Retraining
The ML model can be retrained with new data to improve detection accuracy.

### API Integration
Framework ready for integration with external threat intelligence services.

## Troubleshooting

### Email Connection Issues
- Verify IMAP is enabled in email account settings
- Use app-specific passwords for Gmail/Outlook
- Check firewall and network restrictions

### Performance Optimization
- Adjust monitoring interval based on email volume
- Limit maximum messages processed per check
- Configure appropriate alert thresholds

## License

This project is provided as-is for educational and security research purposes.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review email provider documentation for IMAP setup
3. Verify all dependencies are properly installed