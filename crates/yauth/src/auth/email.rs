use lettre::message::header::ContentType;
use lettre::transport::smtp::client::Tls;
use lettre::{Message, SmtpTransport, Transport};
use tracing::info;

#[derive(Clone)]
pub struct EmailService {
    smtp_host: String,
    smtp_port: u16,
    from_address: String,
    app_url: String,
}

impl EmailService {
    pub fn new(smtp_host: String, smtp_port: u16, from_address: String, app_url: String) -> Self {
        Self {
            smtp_host,
            smtp_port,
            from_address,
            app_url,
        }
    }

    fn send(&self, to: &str, subject: &str, body: String) -> Result<(), String> {
        let email = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|e| format!("Invalid from address: {}", e))?,
            )
            .to(to
                .parse()
                .map_err(|e| format!("Invalid to address: {}", e))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body)
            .map_err(|e| format!("Failed to build email: {}", e))?;

        let transport = SmtpTransport::builder_dangerous(&self.smtp_host)
            .port(self.smtp_port)
            .tls(Tls::None)
            .build();

        transport
            .send(&email)
            .map_err(|e| format!("Failed to send email: {}", e))?;

        Ok(())
    }

    pub fn send_verification_email(&self, to: &str, token: &str) -> Result<(), String> {
        let verify_url = format!("{}/verify-email?token={}", self.app_url, token);

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Verify your email address</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Thanks for signing up! Please click the button below to verify your email address.
  </p>
  <div style="margin: 30px 0;">
    <a href="{verify_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Verify Email
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{verify_url}" style="color: #18181b;">{verify_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 24 hours. If you didn't create an account, you can ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Verify your email address", body)?;

        info!(
            event = "yauth.email.verification_sent",
            to = to,
            "Verification email sent"
        );
        Ok(())
    }

    pub fn send_magic_link_email(&self, to: &str, token: &str) -> Result<(), String> {
        let magic_url = format!("{}/auth/magic-link/verify?token={}", self.app_url, token);

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Sign in to your account</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Click the button below to sign in. This link will expire in 5 minutes.
  </p>
  <div style="margin: 30px 0;">
    <a href="{magic_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Sign In
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{magic_url}" style="color: #18181b;">{magic_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    If you didn't request this link, you can safely ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Sign in to your account", body)?;

        info!(
            event = "yauth.email.magic_link_sent",
            to = to,
            "Magic link email sent"
        );
        Ok(())
    }

    pub fn send_password_reset_email(&self, to: &str, token: &str) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.app_url, token);

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Reset your password</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    We received a request to reset your password. Click the button below to choose a new password.
  </p>
  <div style="margin: 30px 0;">
    <a href="{reset_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Reset Password
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{reset_url}" style="color: #18181b;">{reset_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 1 hour. If you didn't request a password reset, you can ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Reset your password", body)?;

        info!(
            event = "yauth.email.password_reset_sent",
            to = to,
            "Password reset email sent"
        );
        Ok(())
    }

    pub fn send_unlock_email(&self, to: &str, unlock_url: &str) -> Result<(), String> {
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Unlock your account</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Your account has been locked due to too many failed login attempts.
    Click the button below to unlock your account.
  </p>
  <div style="margin: 30px 0;">
    <a href="{unlock_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Unlock Account
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{unlock_url}" style="color: #18181b;">{unlock_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Unlock your account", body)?;
        Ok(())
    }
}
