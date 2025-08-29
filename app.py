import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import os
from phishing_detector import PhishingDetector
from email_parser import EmailParser
from email_monitor import EmailMonitor, SMSMonitor, RealTimeAlerts
import storage

# Initialize session state
if 'detector' not in st.session_state:
    import os
    storage.init_db(os.getenv('PHISHGUARD_DB_PATH', '/tmp/phishguard.db'))
    st.session_state.detector = PhishingDetector()
if 'threat_history' not in st.session_state:
    st.session_state.threat_history = []
if 'processed_messages' not in st.session_state:
    st.session_state.processed_messages = 0
if 'email_monitor' not in st.session_state:
    st.session_state.email_monitor = EmailMonitor()
if 'sms_monitor' not in st.session_state:
    st.session_state.sms_monitor = SMSMonitor()
if 'alerts' not in st.session_state:
    st.session_state.alerts = RealTimeAlerts()

st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Intelligent Phishing Detection System")
st.markdown("Advanced threat detection for emails and messages using machine learning")

# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Select Page", ["Dashboard", "Message Analysis", "Threat History", "Auto Monitor", "System Settings"])

if page == "Dashboard":
    # Dashboard metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Messages Processed", st.session_state.processed_messages)
    
    with col2:
        high_risk_count = sum(1 for threat in st.session_state.threat_history if threat.get('risk_level') == 'High')
        st.metric("High Risk Threats", high_risk_count, delta=None if high_risk_count == 0 else f"+{high_risk_count}")
    
    with col3:
        medium_risk_count = sum(1 for threat in st.session_state.threat_history if threat.get('risk_level') == 'Medium')
        st.metric("Medium Risk Threats", medium_risk_count)
    
    with col4:
        low_risk_count = sum(1 for threat in st.session_state.threat_history if threat.get('risk_level') == 'Low')
        st.metric("Low Risk Threats", low_risk_count)
    
    # Risk distribution chart
    if st.session_state.threat_history:
        st.subheader("📊 Threat Risk Distribution")
        risk_counts = {'High': high_risk_count, 'Medium': medium_risk_count, 'Low': low_risk_count}
        
        fig = px.pie(
            values=list(risk_counts.values()),
            names=list(risk_counts.keys()),
            title="Risk Level Distribution",
            color_discrete_map={'High': '#ff4444', 'Medium': '#ffaa00', 'Low': '#00aa00'}
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Timeline of threats
        st.subheader("📈 Threat Timeline")
        if len(st.session_state.threat_history) > 0:
            df = pd.DataFrame(st.session_state.threat_history)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            fig = px.scatter(
                df, 
                x='timestamp', 
                y='confidence_score',
                color='risk_level',
                hover_data=['subject', 'sender'],
                title="Threat Detection Timeline",
                color_discrete_map={'High': '#ff4444', 'Medium': '#ffaa00', 'Low': '#00aa00'}
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threats detected yet. Start analyzing messages to see dashboard data.")

elif page == "Message Analysis":
    st.header("📧 Message/Email Analysis")
    
    # Input method selection
    input_method = st.radio("Choose input method:", ["Paste Text", "Upload Email File"])
    
    if input_method == "Paste Text":
        # Text input for message content
        st.subheader("Enter Message Content")
        
        col1, col2 = st.columns(2)
        with col1:
            sender_email = st.text_input("Sender Email (optional)")
        with col2:
            subject = st.text_input("Subject Line (optional)")
        
        message_content = st.text_area("Message Content", height=200, placeholder="Paste the email or message content here...")
        
        if st.button("🔍 Analyze Message", type="primary"):
            if message_content:
                with st.spinner("Analyzing message for threats..."):
                    result = st.session_state.detector.analyze_message(
                        content=message_content,
                        sender=sender_email,
                        subject=subject
                    )
                    
                    # Display results
                    st.subheader("🎯 Analysis Results")
                    
                    # Risk level badge
                    risk_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                    st.markdown(f"**Risk Level:** {risk_color[result['risk_level']]} {result['risk_level']}")
                    st.progress(result['confidence_score'] / 100)
                    st.markdown(f"**Confidence Score:** {result['confidence_score']:.1f}%")
                    
                    # Detected threats
                    if result['threats']:
                        st.subheader("⚠️ Detected Threats")
                        for threat in result['threats']:
                            st.warning(f"**{threat['type']}:** {threat['description']}")
                    
                    # Suspicious indicators
                    if result['indicators']:
                        st.subheader("🔍 Suspicious Indicators")
                        for indicator in result['indicators']:
                            st.info(f"• {indicator}")
                    
                    # URL analysis
                    if result['urls']:
                        st.subheader("🌐 URL Analysis")
                        url_df = pd.DataFrame(result['urls'])
                        st.dataframe(url_df, use_container_width=True)
                    
                    # Save to history
                    threat_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'sender': sender_email or 'Unknown',
                        'subject': subject or 'No Subject',
                        'content_preview': message_content[:100] + '...' if len(message_content) > 100 else message_content,
                        'risk_level': result['risk_level'],
                        'confidence_score': result['confidence_score'],
                        'threats': result['threats'],
                        'indicators': result['indicators']
                    }
                    st.session_state.threat_history.append(threat_entry)
                    st.session_state.processed_messages += 1
                    
                    st.success("✅ Analysis complete! Results saved to threat history.")
            else:
                st.error("Please enter message content to analyze.")
    
    elif input_method == "Upload Email File":
        st.subheader("Upload Email File")
        uploaded_file = st.file_uploader("Choose an email file", type=['eml', 'msg', 'txt'])
        
        if uploaded_file is not None:
            try:
                # Read file content
                if uploaded_file.type == "text/plain":
                    content = str(uploaded_file.read(), "utf-8")
                else:
                    content = str(uploaded_file.read(), "utf-8", errors='ignore')
                
                # Parse email if it's an EML file
                email_parser = EmailParser()
                if uploaded_file.name.endswith('.eml'):
                    parsed_email = email_parser.parse_email(content)
                    sender_email = parsed_email.get('sender', '')
                    subject = parsed_email.get('subject', '')
                    message_content = parsed_email.get('body', content)
                else:
                    sender_email = ''
                    subject = ''
                    message_content = content
                
                st.text_area("Parsed Content", value=message_content, height=200, disabled=True)
                
                if st.button("🔍 Analyze Uploaded Email", type="primary"):
                    with st.spinner("Analyzing email for threats..."):
                        result = st.session_state.detector.analyze_message(
                            content=message_content,
                            sender=sender_email,
                            subject=subject
                        )
                        
                        # Display results (same as above)
                        st.subheader("🎯 Analysis Results")
                        
                        risk_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                        st.markdown(f"**Risk Level:** {risk_color[result['risk_level']]} {result['risk_level']}")
                        st.progress(result['confidence_score'] / 100)
                        st.markdown(f"**Confidence Score:** {result['confidence_score']:.1f}%")
                        
                        if result['threats']:
                            st.subheader("⚠️ Detected Threats")
                            for threat in result['threats']:
                                st.warning(f"**{threat['type']}:** {threat['description']}")
                        
                        if result['indicators']:
                            st.subheader("🔍 Suspicious Indicators")
                            for indicator in result['indicators']:
                                st.info(f"• {indicator}")
                        
                        if result['urls']:
                            st.subheader("🌐 URL Analysis")
                            url_df = pd.DataFrame(result['urls'])
                            st.dataframe(url_df, use_container_width=True)
                        
                        # Save to history
                        threat_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'sender': sender_email or 'Unknown',
                            'subject': subject or uploaded_file.name,
                            'content_preview': message_content[:100] + '...' if len(message_content) > 100 else message_content,
                            'risk_level': result['risk_level'],
                            'confidence_score': result['confidence_score'],
                            'threats': result['threats'],
                            'indicators': result['indicators']
                        }
                        st.session_state.threat_history.append(threat_entry)
                        st.session_state.processed_messages += 1
                        
                        st.success("✅ Analysis complete! Results saved to threat history.")
                        
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")

elif page == "Threat History":
    st.header("📜 Threat History")
    
    if st.session_state.threat_history:
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            risk_filter = st.selectbox("Filter by Risk Level", ["All", "High", "Medium", "Low"])
        with col2:
            days_back = st.selectbox("Show threats from last", [1, 7, 30, 90, 365])
        
        # Filter data
        filtered_history = st.session_state.threat_history.copy()
        
        if risk_filter != "All":
            filtered_history = [t for t in filtered_history if t['risk_level'] == risk_filter]
        
        # Filter by date
        cutoff_date = datetime.now() - timedelta(days=days_back)
        filtered_history = [
            t for t in filtered_history 
            if datetime.fromisoformat(t['timestamp']) >= cutoff_date
        ]
        
        if filtered_history:
            st.markdown(f"**Showing {len(filtered_history)} threats**")
            
            # Display threats
            for i, threat in enumerate(reversed(filtered_history)):
                with st.expander(
                    f"{threat['risk_level']} Risk - {threat['subject']} - {threat['timestamp'][:16]}",
                    expanded=False
                ):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Sender:** {threat['sender']}")
                        st.markdown(f"**Subject:** {threat['subject']}")
                        st.markdown(f"**Confidence:** {threat['confidence_score']:.1f}%")
                    with col2:
                        st.markdown(f"**Timestamp:** {threat['timestamp']}")
                        st.markdown(f"**Risk Level:** {threat['risk_level']}")
                    
                    st.markdown("**Content Preview:**")
                    st.text(threat['content_preview'])
                    
                    if threat['threats']:
                        st.markdown("**Detected Threats:**")
                        for t in threat['threats']:
                            st.markdown(f"- {t['type']}: {t['description']}")
                    
                    if threat['indicators']:
                        st.markdown("**Suspicious Indicators:**")
                        for indicator in threat['indicators']:
                            st.markdown(f"- {indicator}")
        else:
            st.info("No threats found matching the selected filters.")
        
        # Export functionality
        if st.button("📥 Export Threat History"):
            df = pd.DataFrame(st.session_state.threat_history)
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"threat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No threat history available. Start analyzing messages to build threat history.")

elif page == "Auto Monitor":
    st.header("📡 Automatic Message Monitoring")
    
    # Get monitoring status
    monitor_status = st.session_state.email_monitor.get_monitoring_status()
    
    # Display current status
    col1, col2, col3 = st.columns(3)
    with col1:
        status_color = "🟢" if monitor_status['active'] else "🔴"
        st.metric("Monitoring Status", f"{status_color} {'Active' if monitor_status['active'] else 'Inactive'}")
    with col2:
        st.metric("Email Accounts", monitor_status['accounts_configured'])
    with col3:
        st.metric("Threats Detected", monitor_status['total_threats_detected'])
    
    # Tabs for different monitoring types
    tab1, tab2, tab3 = st.tabs(["📧 Email Monitoring", "📱 SMS Monitoring", "🚨 Alert Settings"])
    
    with tab1:
        st.subheader("Email Account Configuration")
        
        # Add new email account
        with st.expander("Add Email Account", expanded=len(monitor_status['accounts']) == 0):
            st.markdown("**Connect your email account for automatic monitoring**")
            
            col1, col2 = st.columns(2)
            with col1:
                account_name = st.text_input("Account Name", placeholder="e.g., Personal Gmail")
                email_address = st.text_input("Email Address", placeholder="your.email@gmail.com")
            with col2:
                password = st.text_input("Password/App Password", type="password", 
                                       help="Use app password for Gmail/Outlook")
                
            col1, col2 = st.columns(2)
            with col1:
                imap_server = st.selectbox("Email Provider", [
                    "Gmail (imap.gmail.com)",
                    "Outlook/Hotmail (outlook.office365.com)", 
                    "Yahoo (imap.mail.yahoo.com)",
                    "Custom"
                ])
                
                if imap_server == "Custom":
                    imap_server = st.text_input("IMAP Server", placeholder="imap.example.com")
                else:
                    imap_server = imap_server.split("(")[1].split(")")[0]
            
            with col2:
                port = st.number_input("Port", value=993, min_value=1, max_value=65535)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🧪 Test Connection"):
                    if all([account_name, email_address, password, imap_server]):
                        with st.spinner("Testing connection..."):
                            test_result = st.session_state.email_monitor.test_email_connection(
                                email_address, password, imap_server, port
                            )
                            
                            if test_result['success']:
                                st.success(f"✅ Connection successful! Found {test_result['inbox_count']} messages in inbox.")
                            else:
                                st.error(f"❌ {test_result['message']}")
                    else:
                        st.error("Please fill in all fields")
            
            with col2:
                if st.button("➕ Add Account", type="primary"):
                    if all([account_name, email_address, password, imap_server]):
                        with st.spinner("Adding account..."):
                            success = st.session_state.email_monitor.add_email_account(
                                account_name, email_address, password, imap_server, port
                            )
                            
                            if success:
                                st.success(f"✅ Account '{account_name}' added successfully!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to add account. Please check your credentials.")
                    else:
                        st.error("Please fill in all fields")
        
        # Display configured accounts
        if monitor_status['accounts']:
            st.subheader("Configured Email Accounts")
            for account in monitor_status['accounts']:
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.text(f"📧 {account}")
                with col2:
                    if st.button(f"Remove", key=f"remove_{account}"):
                        st.session_state.email_monitor.remove_email_account(account)
                        st.rerun()
        
        # Monitoring controls
        st.subheader("Monitoring Controls")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if not monitor_status['active']:
                if st.button("🚀 Start Monitoring", type="primary"):
                    if monitor_status['accounts_configured'] > 0:
                        st.session_state.email_monitor.start_monitoring()
                        st.success("✅ Email monitoring started!")
                        st.rerun()
                    else:
                        st.error("Please add at least one email account first")
            else:
                if st.button("⏹️ Stop Monitoring"):
                    st.session_state.email_monitor.stop_monitoring()
                    st.success("✅ Email monitoring stopped!")
                    st.rerun()
        
        with col2:
            check_interval = st.number_input("Check Interval (seconds)", 
                                           value=monitor_status['check_interval'], 
                                           min_value=10, max_value=3600)
        
        with col3:
            if st.button("⚙️ Update Settings"):
                st.session_state.email_monitor.configure_settings(check_interval=check_interval)
                st.success("Settings updated!")
        
        # Recent detected threats from monitoring
        recent_threats = st.session_state.email_monitor.get_detected_threats(hours_back=24)
        if recent_threats:
            st.subheader("🚨 Recent Threats Detected (24 hours)")
            for threat in recent_threats[-5:]:  # Show last 5
                with st.expander(f"{threat['risk_level']} Risk - {threat['subject']}", expanded=False):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Account:** {threat['account_name']}")
                        st.markdown(f"**Sender:** {threat['sender']}")
                        st.markdown(f"**Risk Level:** {threat['risk_level']}")
                    with col2:
                        st.markdown(f"**Detected:** {threat['timestamp'][:19]}")
                        st.markdown(f"**Confidence:** {threat['confidence_score']:.1f}%")
                    
                    st.markdown("**Message Preview:**")
                    st.text(threat['message_preview'])
                    
                    if threat['threats']:
                        st.markdown("**Threats:**")
                        for t in threat['threats']:
                            st.markdown(f"- {t['type']}: {t['description']}")
    
    with tab2:
        st.subheader("SMS Message Monitoring")
        st.info("📱 SMS monitoring requires integration with SMS service providers like Twilio, TextMagic, or similar services.")
        
        # SMS configuration
        with st.expander("Configure SMS Monitoring"):
            sms_provider = st.selectbox("SMS Provider", [
                "Twilio", "TextMagic", "Custom API", "Not Configured"
            ])
            
            if sms_provider != "Not Configured":
                api_key = st.text_input("API Key", type="password")
                phone_number = st.text_input("Phone Number to Monitor", placeholder="+1234567890")
                
                if st.button("Configure SMS Monitoring"):
                    if api_key and phone_number:
                        st.session_state.sms_monitor.configure_sms_monitoring(api_key, phone_number)
                        st.success("SMS monitoring configured!")
                    else:
                        st.error("Please provide API key and phone number")
            else:
                st.markdown("""
                **To enable SMS monitoring:**
                1. Sign up with an SMS service provider
                2. Get API credentials
                3. Configure webhook endpoints
                4. Enter credentials above
                """)
        
        # Manual SMS analysis
        st.subheader("Manual SMS Analysis")
        sms_content = st.text_area("SMS Message Content", height=100)
        sms_sender = st.text_input("Sender Number (optional)")
        
        if st.button("Analyze SMS"):
            if sms_content:
                with st.spinner("Analyzing SMS..."):
                    result = st.session_state.sms_monitor.analyze_sms(sms_content, sms_sender)
                    
                    risk_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
                    st.markdown(f"**Risk Level:** {risk_color[result['risk_level']]} {result['risk_level']}")
                    st.progress(result['confidence_score'] / 100)
                    st.markdown(f"**Confidence Score:** {result['confidence_score']:.1f}%")
                    
                    if result['threats']:
                        st.subheader("⚠️ Detected Threats")
                        for threat in result['threats']:
                            st.warning(f"**{threat['type']}:** {threat['description']}")
            else:
                st.error("Please enter SMS content to analyze")
    
    with tab3:
        st.subheader("🚨 Alert Configuration")
        
        # Real-time alerts
        st.markdown("**Configure how you want to be notified of threats:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            desktop_alerts = st.checkbox("Desktop Notifications", value=True)
            email_alerts = st.checkbox("Email Alerts")
            webhook_alerts = st.checkbox("Webhook Alerts")
        
        with col2:
            alert_threshold = st.selectbox("Alert Threshold", ["High Risk Only", "Medium & High Risk", "All Risks"])
            sound_alerts = st.checkbox("Sound Notifications")
        
        if email_alerts:
            st.subheader("Email Alert Settings")
            with st.expander("Configure Email Alerts"):
                alert_email = st.text_input("Alert Email Address")
                smtp_server = st.text_input("SMTP Server", value="smtp.gmail.com")
                smtp_port = st.number_input("SMTP Port", value=587)
                smtp_username = st.text_input("SMTP Username")
                smtp_password = st.text_input("SMTP Password", type="password")
                
                if st.button("Save Email Alert Settings"):
                    if alert_email and smtp_username and smtp_password:
                        st.session_state.alerts.configure_email_alerts(
                            smtp_server, smtp_port, smtp_username, smtp_password, alert_email
                        )
                        st.success("Email alert settings saved!")
                    else:
                        st.error("Please fill in all email settings")
        
        if webhook_alerts:
            st.subheader("Webhook Alert Settings")
            webhook_url = st.text_input("Webhook URL", placeholder="https://your-webhook-url.com/alerts")
            
            if st.button("Save Webhook Settings"):
                if webhook_url:
                    st.session_state.alerts.configure_webhook_alerts(webhook_url)
                    st.success("Webhook settings saved!")
                else:
                    st.error("Please provide webhook URL")
        
        # Test alerts
        st.subheader("Test Alerts")
        if st.button("🧪 Send Test Alert"):
            test_threat = {
                'risk_level': 'High',
                'subject': 'Test Phishing Email',
                'sender': 'test@suspicious-domain.com',
                'confidence_score': 95.0,
                'timestamp': datetime.now().isoformat()
            }
            
            st.session_state.alerts.send_threat_alert(test_threat)
            st.success("Test alert sent!")

elif page == "System Settings":
    st.header("⚙️ System Settings")
    
    # Model settings
    st.subheader("🤖 Machine Learning Model")
    
    col1, col2 = st.columns(2)
    with col1:
        sensitivity = st.slider("Detection Sensitivity", 0.1, 1.0, 0.7, 0.1)
        st.session_state.detector.set_sensitivity(sensitivity)
    
    with col2:
        auto_update = st.checkbox("Auto-update model", value=True)
        if auto_update:
            st.info("Model will learn from new threat patterns automatically")
    
    # Threat patterns
    st.subheader("🎯 Threat Pattern Management")
    
    # Add custom patterns
    with st.expander("Add Custom Threat Pattern"):
        pattern_name = st.text_input("Pattern Name")
        pattern_regex = st.text_input("Regular Expression Pattern")
        pattern_description = st.text_area("Description")
        
        if st.button("Add Pattern"):
            if pattern_name and pattern_regex:
                try:
                    st.session_state.detector.add_custom_pattern(pattern_name, pattern_regex, pattern_description)
                    st.success(f"Pattern '{pattern_name}' added successfully!")
                except Exception as e:
                    st.error(f"Error adding pattern: {str(e)}")
            else:
                st.error("Please provide both pattern name and regex.")
    
    # URL reputation settings
    st.subheader("🌐 URL Analysis Settings")
    
    check_url_reputation = st.checkbox("Enable URL reputation checking", value=True)
    if check_url_reputation:
        st.session_state.detector.enable_url_checking()
        
        # API key for URL reputation service (if available)
        api_key = st.text_input("URL Reputation API Key (optional)", type="password")
        if api_key:
            os.environ['URL_REPUTATION_API_KEY'] = api_key
    
    # System maintenance
    st.subheader("🧹 System Maintenance")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Retrain Model"):
            with st.spinner("Retraining model..."):
                try:
                    st.session_state.detector.retrain_model()
                    st.success("Model retrained successfully!")
                except Exception as e:
                    st.error(f"Error retraining model: {str(e)}")
    
    with col2:
        if st.button("🗑️ Clear History"):
            if st.checkbox("Confirm deletion"):
                st.session_state.threat_history = []
                st.session_state.processed_messages = 0
                st.success("Threat history cleared!")
                st.rerun()
    
    # Export/Import settings
    st.subheader("💾 Data Management")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📤 Export Settings"):
            settings = {
                'sensitivity': sensitivity,
                'auto_update': auto_update,
                'check_url_reputation': check_url_reputation,
                'threat_history_count': len(st.session_state.threat_history)
            }
            st.download_button(
                label="Download Settings JSON",
                data=json.dumps(settings, indent=2),
                file_name=f"phishing_detector_settings_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )
    
    with col2:
        uploaded_settings = st.file_uploader("Import Settings", type=['json'])
        if uploaded_settings is not None:
            try:
                settings = json.loads(uploaded_settings.read())
                st.success("Settings imported successfully!")
                st.json(settings)
            except Exception as e:
                st.error(f"Error importing settings: {str(e)}")

# Footer
st.markdown("---")
st.markdown("🛡️ **Phishing Detection System** - Protecting your communications with advanced AI")
