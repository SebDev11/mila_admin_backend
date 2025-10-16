const nodemailer = require('nodemailer');

// Configuration
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'tombillpore@gmail.com';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.EMAIL || '';
const SMTP_PASS = process.env.EMAIL_PASSWORD || '';
const APP_NAME = process.env.APP_NAME || 'Admin Panel';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

/**
 * Create email transporter
 */
const createTransporter = () => {
  // If SMTP credentials are not configured, return null
  if (!SMTP_USER || !SMTP_PASS) {
    console.warn('⚠️  Email not configured. Set SMTP_USER and SMTP_PASS in .env');
    return null;
  }

  return nodemailer.createTransport({
    host: SMTP_HOST,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
};

/**
 * HTML email template for admin notification
 */
const getAdminEmailTemplate = (data) => {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>New Registration Request</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden;">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                🔔 New Registration Request
              </h1>
              <p style="margin: 10px 0 0 0; color: #e0e7ff; font-size: 14px;">
                ${APP_NAME}
              </p>
            </td>
          </tr>
          
          <!-- Content -->
          <tr>
            <td style="padding: 40px 30px;">
              
              <!-- Info Box -->
              <div style="background-color: #f8fafc; border-radius: 8px; padding: 24px; margin-bottom: 30px; border-left: 4px solid #667eea;">
                <h2 style="margin: 0 0 20px 0; color: #1e293b; font-size: 18px; font-weight: 600;">
                  User Details
                </h2>
                <table width="100%" cellpadding="8" cellspacing="0">
                  <tr>
                    <td style="color: #64748b; font-size: 14px; font-weight: 500; width: 140px;">Username:</td>
                    <td style="color: #1e293b; font-size: 14px; font-weight: 600;">${data.username}</td>
                  </tr>
                  <tr>
                    <td style="color: #64748b; font-size: 14px; font-weight: 500;">Email:</td>
                    <td style="color: #1e293b; font-size: 14px; font-weight: 600;">${data.email}</td>
                  </tr>
                  <tr>
                    <td style="color: #64748b; font-size: 14px; font-weight: 500;">Date:</td>
                    <td style="color: #1e293b; font-size: 14px;">${new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' })}</td>
                  </tr>
                </table>
              </div>
              
              <!-- Verification Code Box -->
              <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 12px; padding: 30px; text-align: center; margin-bottom: 30px; box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);">
                <p style="margin: 0 0 12px 0; color: #e0e7ff; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                  Verification Code
                </p>
                <div style="background-color: rgba(255,255,255,0.15); backdrop-filter: blur(10px); border-radius: 8px; padding: 20px; display: inline-block;">
                  <p style="margin: 0; color: #ffffff; font-size: 36px; font-weight: 700; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                    ${data.verificationCode}
                  </p>
                </div>
                <p style="margin: 16px 0 0 0; color: #e0e7ff; font-size: 12px;">
                  Valid for 24 hours • Expires ${new Date(Date.now() + 24 * 60 * 60 * 1000).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' })}
                </p>
              </div>
              
              <!-- Action Required Box -->
              <div style="background-color: #fef3c7; border-radius: 8px; padding: 20px; margin-bottom: 30px; border-left: 4px solid #f59e0b;">
                <p style="margin: 0; color: #92400e; font-size: 14px; line-height: 1.6;">
                  <strong style="color: #78350f;">⚡ Action Required:</strong><br>
                  A new user is requesting access to the admin panel. Please review their details and approve in the admin dashboard.
                </p>
              </div>
              
              <!-- CTA Button -->
              <div style="text-align: center; margin-bottom: 30px;">
                <a href="${FRONTEND_URL}/pending-registrations" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">
                  Review Pending Registrations →
                </a>
              </div>
              
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="background-color: #f8fafc; padding: 24px 30px; border-top: 1px solid #e2e8f0;">
              <p style="margin: 0; color: #64748b; font-size: 12px; line-height: 1.6; text-align: center;">
                This is an automated notification from <strong>${APP_NAME}</strong>.<br>
                <span style="color: #94a3b8;">© ${new Date().getFullYear()} ${APP_NAME}. All rights reserved.</span>
              </p>
            </td>
          </tr>
          
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;
};

/**
 * HTML email template for user approval confirmation
 */
const getUserApprovalEmailTemplate = (data) => {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Account Approved</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <tr>
            <td style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                ✅ Account Approved!
              </h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 40px 30px;">
              <p style="color: #1e293b; font-size: 16px; margin: 0 0 20px 0;">
                Hello <strong>${data.username}</strong>,
              </p>
              <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;">
                Great news! Your admin panel account has been approved and activated.
              </p>
              <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 30px 0;">
                You can now login and access all admin features.
              </p>
              <div style="text-align: center; margin-bottom: 30px;">
                <a href="${FRONTEND_URL}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 15px;">
                  Login to Admin Panel →
                </a>
              </div>
              <p style="color: #64748b; font-size: 13px; margin: 0;">
                Best regards,<br>
                <strong>${APP_NAME} Team</strong>
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color: #f8fafc; padding: 20px 30px; border-top: 1px solid #e2e8f0; text-align: center;">
              <p style="margin: 0; color: #94a3b8; font-size: 11px;">
                © ${new Date().getFullYear()} ${APP_NAME}. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;
};

/**
 * Generate a 6-digit verification code
 */
const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Send admin notification email with verification code
 */
const sendAdminNotification = async (registrationData, verificationCode) => {
  try {
    // Always log to console for debugging
    console.log('\n' + '═'.repeat(60));
    console.log('🔔 NEW REGISTRATION REQUEST');
    console.log('═'.repeat(60));
    console.log(`👤 Username: ${registrationData.username}`);
    console.log(`📧 Email: ${registrationData.email}`);
    console.log(`📅 Date: ${new Date().toLocaleString()}`);
    console.log(`🔑 Verification Code: ${verificationCode}`);
    console.log(`⏰ Expires: ${new Date(Date.now() + 24 * 60 * 60 * 1000).toLocaleString()}`);
    console.log('═'.repeat(60));

    // Try to send email
    const transporter = createTransporter();
    
    if (!transporter) {
      console.log('⚠️  Email not configured. Set SMTP_USER and SMTP_PASS in .env');
      console.log('ℹ️  Code is available in admin UI at: /pending-registrations');
      console.log('═'.repeat(60) + '\n');
      return { success: true, method: 'console' };
    }

    const mailOptions = {
      from: `"${APP_NAME}" <${SMTP_USER}>`,
      to: ADMIN_EMAIL,
      subject: `🔔 New Admin Panel Registration Request`,
      html: getAdminEmailTemplate({ ...registrationData, verificationCode }),
      text: `
          NEW REGISTRATION REQUEST - ${APP_NAME}
          ${'='.repeat(60)}

          USER DETAILS:
          Username: ${registrationData.username}
          Email: ${registrationData.email}
          Date: ${new Date().toLocaleString()}

          VERIFICATION CODE: ${verificationCode}
          (Valid for 24 hours)

          ACTION REQUIRED:
          A new user is requesting admin panel access.
          Please review and approve in the admin dashboard.

          Admin Dashboard: ${FRONTEND_URL}/pending-registrations

          ${'='.repeat(60)}
        © ${new Date().getFullYear()} ${APP_NAME}
              `,
      priority: 'high',
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent successfully to: ${ADMIN_EMAIL}`);
    console.log('═'.repeat(60) + '\n');
    
    return { 
      success: true, 
      method: 'email',
      messageId: info.messageId,
      to: ADMIN_EMAIL
    };
    
  } catch (error) {
    console.error('❌ Error sending email:', error.message);
    console.log('ℹ️  Code is still available in admin UI');
    console.log('═'.repeat(60) + '\n');
    return { 
      success: true,
      method: 'console',
      error: error.message 
    };
  }
};

/**
 * HTML email template for password reset
 */
const getPasswordResetEmailTemplate = (resetUrl, expiryMinutes = 60) => {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Your Password</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden;">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                🔐 Reset Your Password
              </h1>
              <p style="margin: 10px 0 0 0; color: #e0e7ff; font-size: 14px;">
                ${APP_NAME}
              </p>
            </td>
          </tr>
          
          <!-- Content -->
          <tr>
            <td style="padding: 40px 30px;">
              
              <p style="color: #1e293b; font-size: 16px; margin: 0 0 20px 0;">
                Hello,
              </p>
              
              <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;">
                We received a request to reset your password for your ${APP_NAME} account. If you didn't make this request, you can safely ignore this email.
              </p>
              
              <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 30px 0;">
                To reset your password, click the button below:
              </p>
              
              <!-- CTA Button -->
              <div style="text-align: center; margin-bottom: 30px;">
                <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">
                  Reset My Password
                </a>
              </div>
              
              <!-- Or copy link -->
              <div style="background-color: #f8fafc; border-radius: 8px; padding: 20px; margin-bottom: 30px; border-left: 4px solid #667eea;">
                <p style="margin: 0 0 10px 0; color: #64748b; font-size: 13px; font-weight: 600;">
                  Or copy and paste this link into your browser:
                </p>
                <p style="margin: 0; color: #475569; font-size: 13px; word-break: break-all;">
                  <a href="${resetUrl}" style="color: #667eea; text-decoration: none;">${resetUrl}</a>
                </p>
              </div>
              
              <!-- Security warning -->
              <div style="background-color: #fef3c7; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid #f59e0b;">
                <p style="margin: 0; color: #92400e; font-size: 13px; line-height: 1.6;">
                  <strong style="color: #78350f;">🔒 Security Notice:</strong><br>
                  This link will expire in ${expiryMinutes} minutes and can only be used once. If you didn't request a password reset, please ignore this email or contact support if you're concerned about your account's security.
                </p>
              </div>
              
              <p style="color: #64748b; font-size: 13px; margin: 0;">
                Best regards,<br>
                <strong>${APP_NAME} Team</strong>
              </p>
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="background-color: #f8fafc; padding: 24px 30px; border-top: 1px solid #e2e8f0;">
              <p style="margin: 0; color: #64748b; font-size: 12px; line-height: 1.6; text-align: center;">
                This is an automated message from <strong>${APP_NAME}</strong>.<br>
                <span style="color: #94a3b8;">© ${new Date().getFullYear()} ${APP_NAME}. All rights reserved.</span>
              </p>
            </td>
          </tr>
          
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;
};

/**
 * Send approval confirmation to user (optional)
 */
const sendApprovalNotification = async (userData) => {
  try {
    const transporter = createTransporter();
    if (!transporter) {
      console.log(`⚠️  Email not configured. Cannot send approval notification to ${userData.email}`);
      return { success: false, error: 'Email not configured' };
    }

    const mailOptions = {
      from: `"${APP_NAME}" <${SMTP_USER}>`,
      to: userData.email,
      subject: `✅ Your ${APP_NAME} Account Has Been Approved`,
      html: getUserApprovalEmailTemplate(userData),
      text: `Hello ${userData.username},\n\nGreat news! Your admin panel account has been approved and activated.\n\nYou can now login at: ${FRONTEND_URL}\n\nBest regards,\n${APP_NAME} Team`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Approval notification sent to: ${userData.email}`);
    return { success: true };
  } catch (error) {
    console.error('Error sending approval notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send password reset email
 */
const sendPasswordResetEmail = async (user, resetToken) => {
  try {
    // Generate reset URL with token
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Always log to console for debugging
    console.log('\n' + '═'.repeat(60));
    console.log('🔐 PASSWORD RESET REQUEST');
    console.log('═'.repeat(60));
    console.log(`👤 User: ${user.username} (${user.email})`);
    console.log(`📅 Date: ${new Date().toLocaleString()}`);
    console.log(`🔗 Reset URL: ${resetUrl}`);
    console.log(`🔑 Reset Token: ${resetToken}`);
    console.log(`⏰ Expires: ${new Date(Date.now() + 60 * 60 * 1000).toLocaleString()}`);
    console.log('═'.repeat(60));

    // Try to send email
    const transporter = createTransporter();
    
    if (!transporter) {
      console.log('⚠️  Email not configured. Set SMTP_USER and SMTP_PASS in .env');
      console.log('ℹ️  Reset link is shown above. Provide it to the user.');
      console.log('═'.repeat(60) + '\n');
      return { success: true, method: 'console', resetUrl };
    }

    const mailOptions = {
      from: `"${APP_NAME}" <${SMTP_USER}>`,
      to: user.email,
      subject: `🔐 Reset Your ${APP_NAME} Password`,
      html: getPasswordResetEmailTemplate(resetUrl, 60),
      text: `
PASSWORD RESET REQUEST - ${APP_NAME}
${'='.repeat(60)}

Hello ${user.username},

We received a request to reset your password for your ${APP_NAME} account.

To reset your password, click the link below or copy it into your browser:
${resetUrl}

This link will expire in 1 hour and can only be used once.

If you didn't request this password reset, you can safely ignore this email.

Best regards,
${APP_NAME} Team

${'='.repeat(60)}
© ${new Date().getFullYear()} ${APP_NAME}
      `,
      priority: 'high',
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Password reset email sent successfully to: ${user.email}`);
    console.log('═'.repeat(60) + '\n');
    
    return { 
      success: true, 
      method: 'email',
      messageId: info.messageId,
      to: user.email,
      resetUrl
    };
    
  } catch (error) {
    console.error('❌ Error sending password reset email:', error.message);
    console.log('ℹ️  Reset link is still valid and shown above');
    console.log('═'.repeat(60) + '\n');
    return { 
      success: true,
      method: 'console',
      error: error.message,
      resetUrl: `${FRONTEND_URL}/reset-password?token=${resetToken}`
    };
  }
};

module.exports = {
  sendAdminNotification,
  sendApprovalNotification,
  sendPasswordResetEmail,
  generateVerificationCode,
};

