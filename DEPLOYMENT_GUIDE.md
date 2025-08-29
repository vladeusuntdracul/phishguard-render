# Deployment Guide for Phishing Detection System

This guide provides comprehensive instructions for deploying the Phishing Detection System across different platforms.

## Quick Deployment Options

### Option 1: Replit (Recommended - Easiest)

1. **Create New Repl**
   - Go to [Replit.com](https://replit.com)
   - Click "Create Repl"
   - Choose "Python" template
   - Name your project

2. **Upload Project Files**
   - Upload all project files to your Repl
   - The system will automatically detect and install dependencies

3. **Configure and Run**
   - The app will automatically start on port 5000
   - Click "Run" button or use the command: `streamlit run app.py --server.port 5000`

4. **Deploy to Public**
   - Click the "Deploy" button in Replit
   - Choose "Autoscale" deployment
   - Your app will be available at a public URL

### Option 2: Local Development

1. **Prerequisites**
   ```bash
   python --version  # Should be 3.8+
   pip --version     # Should be available
   ```

2. **Installation**
   ```bash
   # Extract project files
   # Navigate to project directory
   cd phishing_detection_system
   
   # Create virtual environment (recommended)
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r project_dependencies.txt
   
   # Download required NLTK data
   python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('vader_lexicon')"
   ```

3. **Run Application**
   ```bash
   streamlit run app.py --server.port 5000
   ```

4. **Access Application**
   - Open browser to `http://localhost:5000`

### Option 3: Cloud Platforms

#### Heroku Deployment

1. **Create Heroku App**
   ```bash
   # Install Heroku CLI
   # Login to Heroku
   heroku login
   
   # Create new app
   heroku create your-phishing-detector
   ```

2. **Prepare Files**
   Create `Procfile`:
   ```
   web: streamlit run app.py --server.port $PORT --server.address 0.0.0.0
   ```
   
   Create `runtime.txt`:
   ```
   python-3.11.0
   ```

3. **Deploy**
   ```bash
   git init
   git add .
   git commit -m "Initial deployment"
   git push heroku main
   ```

#### Railway Deployment

1. **Connect Repository**
   - Go to [Railway.app](https://railway.app)
   - Connect your GitHub repository
   - Railway auto-detects Python and deploys

2. **Configure**
   - Set start command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`
   - Railway handles the rest automatically

#### Render Deployment

1. **Create Web Service**
   - Go to [Render.com](https://render.com)
   - Create new "Web Service"
   - Connect repository

2. **Configure**
   - Build Command: `pip install -r project_dependencies.txt`
   - Start Command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`

### Option 4: Docker Deployment

1. **Create Dockerfile**
   ```dockerfile
   FROM python:3.11-slim
   
   WORKDIR /app
   
   COPY project_dependencies.txt .
   RUN pip install -r project_dependencies.txt
   
   # Download NLTK data
   RUN python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('vader_lexicon')"
   
   COPY . .
   
   EXPOSE 5000
   
   CMD ["streamlit", "run", "app.py", "--server.port", "5000", "--server.address", "0.0.0.0"]
   ```

2. **Build and Run**
   ```bash
   # Build image
   docker build -t phishing-detector .
   
   # Run container
   docker run -p 5000:5000 phishing-detector
   ```

3. **Deploy to Cloud**
   - Push to Docker Hub
   - Deploy to AWS ECS, Google Cloud Run, or Azure Container Instances

## Configuration for Different Environments

### Environment Variables

For production deployments, set these environment variables:

```bash
# Optional: URL reputation API key
URL_REPUTATION_API_KEY=your_api_key_here

# Optional: SMS monitoring
SMS_API_KEY=your_sms_api_key
MONITOR_PHONE_NUMBER=+1234567890

# Streamlit configuration
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_SERVER_PORT=5000
STREAMLIT_SERVER_ADDRESS=0.0.0.0
```

### Security Considerations

1. **API Keys**
   - Store sensitive keys as environment variables
   - Never commit API keys to version control
   - Use platform-specific secret management

2. **Email Credentials**
   - Recommend app-specific passwords
   - Implement secure credential storage
   - Consider OAuth 2.0 for production

3. **Network Security**
   - Use HTTPS in production
   - Implement proper firewall rules
   - Consider VPN for email connections

## Platform-Specific Setup

### Gmail Integration
1. Enable 2-Factor Authentication
2. Generate App Password:
   - Google Account → Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
   - Use this password in the application

### Outlook/Hotmail Integration
1. Enable IMAP in Outlook settings
2. Use account password or generate app password
3. Server: `outlook.office365.com`, Port: `993`

### Yahoo Mail Integration
1. Generate App Password:
   - Yahoo Account → Security → Generate app password
2. Server: `imap.mail.yahoo.com`, Port: `993`

## Performance Optimization

### For High Volume Email Accounts
```python
# Recommended settings in Auto Monitor
check_interval = 60  # Check every minute instead of 30 seconds
max_messages_per_check = 5  # Process fewer messages per check
```

### Memory Management
- For cloud deployments with limited memory
- Consider processing emails in batches
- Implement email archiving for old threats

### Monitoring Recommendations
- Start with one email account
- Monitor application logs for errors
- Set up health checks for production

## Troubleshooting Common Issues

### Import Errors
```bash
# If modules not found
pip install --upgrade streamlit pandas plotly scikit-learn nltk spacy requests

# Download spacy model (optional)
python -m spacy download en_core_web_sm
```

### Email Connection Issues
1. **"Authentication failed"**
   - Use app-specific passwords
   - Check IMAP is enabled
   - Verify server settings

2. **"Connection timeout"**
   - Check firewall settings
   - Verify network connectivity
   - Try different port (143 for non-SSL)

3. **"SSL errors"**
   - Update certificates
   - Try with SSL disabled (port 143)

### Memory Issues
```bash
# For limited memory environments
export STREAMLIT_SERVER_MAX_UPLOAD_SIZE=10
export STREAMLIT_SERVER_MAX_MESSAGE_SIZE=10
```

## Production Checklist

- [ ] Set up HTTPS/SSL certificates
- [ ] Configure environment variables
- [ ] Set up monitoring and logging
- [ ] Implement backup strategy for threat history
- [ ] Configure alert systems
- [ ] Set up health checks
- [ ] Test email integrations
- [ ] Document access credentials securely
- [ ] Set up automatic restarts
- [ ] Configure resource limits

## Support and Maintenance

### Regular Maintenance
- Update threat patterns monthly
- Review and update ML model
- Monitor system performance
- Update dependencies for security patches

### Scaling Considerations
- For multiple users: implement user authentication
- For enterprise: consider database backend
- For high volume: implement queue system for email processing

This deployment guide covers all major platforms and scenarios. Choose the option that best fits your technical requirements and infrastructure preferences.