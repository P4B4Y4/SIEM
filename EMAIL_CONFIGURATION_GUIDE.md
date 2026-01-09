# Email Configuration Guide

## Overview

The SIEM system now includes a complete web-based email configuration interface for managing alert notifications. All email settings can be configured through the web UI without touching code.

## Access Email Settings

**URL:** `http://localhost/SIEM/pages/email-settings.php`

**Requirements:**
- Must be logged in as admin user
- Access via navigation menu: Settings → Email

## Configuration Sections

### 1. SMTP Server Settings

Configure your email server connection:

**SMTP Host**
- Example: `smtp.gmail.com`, `smtp.office365.com`, `mail.company.com`
- Your email provider's SMTP server address

**SMTP Port**
- Usually `587` (TLS) or `465` (SSL)
- Check with your email provider

**SMTP Username**
- Your email address or username
- Example: `your-email@gmail.com`

**SMTP Password**
- Your email password or app password
- For Gmail: Use [App Password](https://myaccount.google.com/apppasswords)
- For Office 365: Use your regular password

### 2. Email Settings

**From Email Address**
- Email address alerts will be sent from
- Example: `siem@company.com`
- Should be a valid email address

**From Name**
- Display name in alert emails
- Example: `SIEM Alert System`
- Shows in recipient's email client

**Use SMTP**
- Check if you have SMTP credentials
- Uncheck to use PHP mail() function
- SMTP is recommended for reliability

**Enable Email Notifications**
- Check to automatically send emails for alerts
- Uncheck to disable email notifications
- Can be toggled anytime

### 3. Alert Recipients by Severity

**Critical Alert Recipients**
- Emails for severity: Critical
- One email per line
- Example:
  ```
  soc@company.com
  manager@company.com
  ciso@company.com
  ```

**Warning Alert Recipients**
- Emails for severity: Warning
- One email per line
- Example:
  ```
  soc@company.com
  analyst@company.com
  ```

**Informational Alert Recipients**
- Emails for severity: Informational
- One email per line
- Example:
  ```
  logs@company.com
  audit@company.com
  ```

## Testing Configuration

### Test SMTP Connection

1. Click "Test SMTP Connection" button
2. System will attempt to connect to your SMTP server
3. Success message confirms configuration
4. Error message shows what's wrong

### Send Test Email

1. Enter your email address in "Test Email Address" field
2. Click "Send Test Email" button
3. Check your inbox for test alert
4. Verify email formatting and content

**Test Email Contains:**
- Sample alert with all details
- HTML formatted email
- Recommended actions
- Escalation instructions

## Provider-Specific Setup

### Gmail

1. **Enable 2-Factor Authentication** (if not already enabled)
   - Go to [Google Account](https://myaccount.google.com)
   - Security → 2-Step Verification

2. **Generate App Password**
   - Go to [App Passwords](https://myaccount.google.com/apppasswords)
   - Select "Mail" and "Windows Computer"
   - Copy the 16-character password

3. **Configure in SIEM**
   - SMTP Host: `smtp.gmail.com`
   - SMTP Port: `587`
   - Username: Your Gmail address
   - Password: 16-character app password
   - Check "Use SMTP"

### Office 365

1. **Configure in SIEM**
   - SMTP Host: `smtp.office365.com`
   - SMTP Port: `587`
   - Username: Your Office 365 email
   - Password: Your Office 365 password
   - Check "Use SMTP"

2. **Test Connection**
   - Click "Test SMTP Connection"
   - If fails, check credentials

### Custom SMTP Server

1. **Get SMTP Details from IT**
   - SMTP server address
   - Port number (usually 587 or 465)
   - Username and password
   - Whether TLS/SSL is required

2. **Configure in SIEM**
   - Enter all details
   - Check "Use SMTP"
   - Test connection

## Email Notification Workflow

```
Alert Generated
    ↓
Check Alert Severity
    ↓
    ├─ CRITICAL → Send to critical_recipients
    ├─ WARNING → Send to warning_recipients
    └─ INFORMATIONAL → Send to info_recipients
    ↓
Format HTML Email
    ↓
Send via SMTP/mail()
    ↓
Recipient Receives Alert Email
```

## Email Content

Each alert email includes:

**Header Section**
- Alert title with severity indicator
- Color-coded by severity level

**Details Section**
- Alert ID
- Severity and alert level
- Timestamp
- Computer name
- Event source
- Category
- Anomaly status

**Detection Details**
- Reason for alert
- What was detected

**Recommended Actions**
- Highlighted in blue box
- Specific actions to take

**Escalation Instructions**
- Color-coded by severity
- Clear action required
- Timeline for response

**Footer**
- Timestamp
- Link to SIEM dashboard
- Do not reply notice

## Troubleshooting

### "SMTP Connection Failed"

**Check:**
1. SMTP host is correct
2. SMTP port is correct (usually 587)
3. Username and password are correct
4. Firewall allows outbound SMTP
5. Email provider allows SMTP connections

**Solutions:**
- Try port 465 instead of 587
- Check if SMTP requires TLS/SSL
- Verify credentials with email provider
- Check firewall rules for outbound port

### "Failed to Send Email"

**Check:**
1. SMTP connection is working (test first)
2. Email addresses are valid
3. From email address is valid
4. Email provider allows sending

**Solutions:**
- Test SMTP connection first
- Verify recipient email addresses
- Check email provider's sending limits
- Review email provider's security settings

### "Test Email Not Received"

**Check:**
1. Check spam/junk folder
2. Verify recipient email address
3. Check SMTP connection is working
4. Verify "From" email address is valid

**Solutions:**
- Add SIEM email to contacts
- Check spam filter settings
- Whitelist SIEM email address
- Try different recipient email

## Security Best Practices

1. **Use App Passwords**
   - Don't use your actual password
   - Use app-specific passwords
   - Easier to revoke if compromised

2. **Use TLS/SSL**
   - Port 587 (TLS) is more secure
   - Port 465 (SSL) also acceptable
   - Avoid unencrypted SMTP

3. **Restrict Recipients**
   - Only add necessary email addresses
   - Use distribution lists for teams
   - Review recipients regularly

4. **Monitor Email Sending**
   - Check email provider's logs
   - Monitor for failed sends
   - Review delivery reports

5. **Secure Credentials**
   - Don't share SMTP password
   - Use strong passwords
   - Change passwords regularly

## Configuration File

Settings are stored in: `config/email_settings.json`

**Format:**
```json
{
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_user": "your-email@gmail.com",
  "smtp_pass": "app-password",
  "from_email": "siem@company.com",
  "from_name": "SIEM Alert System",
  "use_smtp": true,
  "enable_notifications": true,
  "critical_recipients": "soc@company.com\nmanager@company.com",
  "warning_recipients": "soc@company.com",
  "info_recipients": "logs@company.com"
}
```

## API Integration

Email settings can also be configured via API:

**Get Settings:**
```bash
GET /api/email-settings.php?action=get_settings
```

**Update Settings:**
```bash
POST /api/email-settings.php?action=update_settings
```

**Send Test Email:**
```bash
POST /api/email-settings.php?action=send_test
```

## Features

✅ **Web-Based Configuration** - No code editing required
✅ **SMTP Support** - Full SMTP authentication
✅ **PHP mail() Fallback** - Works without SMTP
✅ **Connection Testing** - Verify settings before saving
✅ **Test Email** - Send sample alert to verify
✅ **Severity-Based Recipients** - Different emails per severity
✅ **HTML Email Templates** - Professional formatted emails
✅ **Secure Storage** - Settings stored in JSON file
✅ **Easy Management** - Intuitive web interface

## Status

✅ **COMPLETE & READY TO USE**

Email configuration is fully functional through the web UI. No manual configuration required!

## Next Steps

1. Visit: `http://localhost/SIEM/pages/email-settings.php`
2. Enter your SMTP details
3. Click "Test SMTP Connection"
4. Send a test email
5. Configure alert recipients
6. Enable notifications
7. Start receiving alert emails!
