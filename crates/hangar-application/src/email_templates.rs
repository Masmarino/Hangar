//! Subject/text/HTML builders for outbound notifications, sharing one HTML shell. Styles are inline and layout uses `<table>` — email clients don't reliably support stylesheets or
//! `flex`/`grid`. The logo is referenced as `cid:{LOGO_CID}`, not a regular URL, since `SmtpEmailSender` embeds the image bytes under that same id.

pub struct EmailContent {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// `SmtpEmailSender` attaches the actual image bytes tagged with this same id.
pub const LOGO_CID: &str = "hangar-logo";

const PRIMARY: &str = "#0d1ed3";
const TEXT_PRIMARY: &str = "#1f2937";
const TEXT_SECONDARY: &str = "#6b7280";

fn shell(preheader: &str, body_html: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Hangar</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f4f5f7; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <span style="display:none; font-size:1px; color:#f4f5f7; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">{preheader}</span>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7; padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" style="max-width:480px; background-color:#ffffff; border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1);" cellpadding="0" cellspacing="0">
            <tr>
              <td style="padding:32px 32px 24px; text-align:center; border-bottom:1px solid #e5e7eb;">
                <img src="cid:{LOGO_CID}" alt="Hangar" width="220" style="display:block; width:220px; max-width:100%; height:auto; margin:0 auto;" />
              </td>
            </tr>
            <tr>
              <td style="padding:32px; font-size:14px; line-height:1.6; color:{TEXT_PRIMARY};">
                {body_html}
              </td>
            </tr>
            <tr>
              <td style="padding:20px 32px; background-color:#f9fafb; text-align:center;">
                <p style="margin:0; font-size:12px; color:{TEXT_SECONDARY};">Cet email a été envoyé automatiquement par votre instance Hangar.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"#
    )
}

fn button(href: &str, label: &str) -> String {
    format!(
        r#"<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px 0;"><tr><td style="border-radius:8px; background-color:{PRIMARY};"><a href="{href}" style="display:inline-block; padding:12px 24px; font-size:14px; font-weight:600; color:#ffffff; text-decoration:none;">{label}</a></td></tr></table>"#
    )
}

pub fn account_created(username: &str, activation_url: &str) -> EmailContent {
    let text = format!(
        "Bonjour {username},\n\n\
         Un compte Hangar a été créé pour vous. Pour l'activer et choisir votre mot de passe, \
         cliquez sur le lien suivant dans les 24 heures :\n\n\
         {activation_url}\n\n\
         Passé ce délai, le lien expirera et vous devrez demander à un administrateur de vous \
         renvoyer une invitation."
    );
    let body_html = format!(
        r#"<p style="margin:0 0 16px;">Bonjour <strong>{username}</strong>,</p>
<p style="margin:0 0 16px;">Un compte Hangar a été créé pour vous. Pour l'activer et choisir votre mot de passe, cliquez sur le bouton ci-dessous.</p>
{button}
<p style="margin:16px 0 0; font-size:13px; color:{TEXT_SECONDARY};">Ce lien expire dans 24 heures. Passé ce délai, demandez à un administrateur de vous renvoyer une invitation.</p>"#,
        button = button(activation_url, "Activer mon compte"),
    );
    EmailContent { subject: "Votre compte Hangar".to_string(), text, html: shell("Activez votre compte Hangar", &body_html) }
}

pub fn password_changed(username: &str) -> EmailContent {
    let text = format!(
        "Bonjour {username},\n\n\
         Le mot de passe de votre compte Hangar vient d'être modifié.\n\n\
         Si vous êtes à l'origine de ce changement, aucune action n'est nécessaire.\n\n\
         Si vous n'êtes pas à l'origine de ce changement, contactez immédiatement un \
         administrateur de votre instance Hangar."
    );
    let body_html = format!(
        r#"<p style="margin:0 0 16px;">Bonjour <strong>{username}</strong>,</p>
<p style="margin:0 0 16px;">Le mot de passe de votre compte Hangar vient d'être modifié.</p>
<p style="margin:0 0 16px;">Si vous êtes à l'origine de ce changement, aucune action n'est nécessaire.</p>
<p style="margin:0; padding:12px 16px; background-color:#fef3c7; border-radius:8px; color:#92400e;">Si vous n'êtes <strong>pas</strong> à l'origine de ce changement, contactez immédiatement un administrateur de votre instance Hangar.</p>"#
    );
    EmailContent { subject: "Votre mot de passe Hangar a été modifié".to_string(), text, html: shell("Votre mot de passe a été modifié", &body_html) }
}

pub fn mfa_enrolled(username: &str, method: &str) -> EmailContent {
    let text = format!(
        "Bonjour {username},\n\n\
         Une nouvelle méthode de double authentification vient d'être ajoutée à votre compte \
         Hangar : {method}.\n\n\
         Si vous êtes à l'origine de cet ajout, aucune action n'est nécessaire.\n\n\
         Si vous n'êtes pas à l'origine de cet ajout, contactez immédiatement un administrateur \
         de votre instance Hangar."
    );
    let body_html = format!(
        r#"<p style="margin:0 0 16px;">Bonjour <strong>{username}</strong>,</p>
<p style="margin:0 0 16px;">Une nouvelle méthode de double authentification vient d'être ajoutée à votre compte Hangar : <strong>{method}</strong>.</p>
<p style="margin:0 0 16px;">Si vous êtes à l'origine de cet ajout, aucune action n'est nécessaire.</p>
<p style="margin:0; padding:12px 16px; background-color:#fef3c7; border-radius:8px; color:#92400e;">Si vous n'êtes <strong>pas</strong> à l'origine de cet ajout, contactez immédiatement un administrateur de votre instance Hangar.</p>"#
    );
    EmailContent { subject: "Nouvelle méthode de double authentification ajoutée".to_string(), text, html: shell("Nouvelle méthode de double authentification", &body_html) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_created_includes_the_activation_link_in_both_bodies() {
        let content = account_created("florian", "https://hangar.example.com/activate?token=abc");
        assert!(content.text.contains("https://hangar.example.com/activate?token=abc"));
        assert!(content.html.contains("https://hangar.example.com/activate?token=abc"));
        assert!(content.html.contains("florian"));
        assert!(content.html.starts_with("<!doctype html>"));
    }

    #[test]
    fn password_changed_mentions_the_username_in_both_bodies() {
        let content = password_changed("florian");
        assert!(content.text.contains("florian"));
        assert!(content.html.contains("florian"));
        assert!(content.html.contains("modifié"));
    }

    #[test]
    fn mfa_enrolled_mentions_the_method_in_both_bodies() {
        let content = mfa_enrolled("florian", "une clé d'accès (passkey)");
        assert!(content.text.contains("une clé d'accès (passkey)"));
        assert!(content.html.contains("une clé d'accès (passkey)"));
    }
}
