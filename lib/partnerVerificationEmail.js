const { inlineLogo, escapeHTML, verificationLayout } = require('./partnerEmailBranding');

function verificationEmail({ code, expiresInSeconds }) {
  const minutes = Math.floor(expiresInSeconds / 60);
  return {
    subject: 'Your Zippi Partner Preview code',
    // Keep the existing fallback copy unchanged for plain-text mail clients.
    text: `Your Zippi verification code is:\n\n${code}\n\nThis code expires in ${minutes} minutes.\n\nIf you didn’t request this code, you can ignore this email.`,
    html: verificationLayout(`<tr><td class="pad" style="padding:0 40px;">
<h1 class="headline" style="margin:0 0 20px;color:#f7f5ef;font-size:38px;line-height:44px;letter-spacing:-1.2px;font-weight:700;">Your verification code</h1>
<p style="margin:0;color:#c8c6bf;font-size:16px;line-height:26px;">Enter this code in Zippi to activate your Partner Preview.</p>
<table role="presentation" width="100%"><tr><td style="padding:28px 0 18px;">
<table role="presentation" width="100%"><tr><td class="verification-code" align="center" style="padding:25px 10px;background-color:#3b3529;border:1px solid #927443;border-radius:12px;color:#f4cc78;font-family:Consolas,Menlo,monospace;font-size:44px;font-weight:700;line-height:60px;letter-spacing:10px;white-space:nowrap;">${escapeHTML(code)}</td></tr></table>
</td></tr></table>
<p style="margin:0 0 28px;color:#e7b858;font-size:14px;line-height:23px;">This code expires in ${escapeHTML(minutes)} minutes.</p>
<p style="margin:0;padding:24px 0;border-top:1px solid #4b4b4e;border-bottom:1px solid #4b4b4e;color:#c8c6bf;font-size:14px;line-height:24px;">If you didn't request this code, you can safely ignore this email.</p>
</td></tr>
`),
    attachments: [inlineLogo()],
  };
}
module.exports = { verificationEmail };
