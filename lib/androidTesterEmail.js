const { normalizeEmail } = require('./partnerAccess');
const { escapeHTML, verificationLayout } = require('./partnerEmailBranding');
const { ANDROID_TEST_URL, ANDROID_INVITATION_URL, ANDROID_EMAIL_LOGO_URL } = require('./androidTesterLinks');
function androidTesterEmail(address) {
  const email = normalizeEmail(address);
  const subject = "You're invited to preview Zippi on Android";
  const steps = [
    'Open the Google Play invitation using the Google Account associated with this email.',
    'Join the test and install Zippi.',
    'Open Zippi and go to Account → Partner Preview.',
    `Enter ${email} (the email that received this invitation) and tap Continue.`,
    'Enter the six-digit verification code sent to your email.',
  ];
  const html = verificationLayout(`<tr><td class="pad" style="padding:0 40px;">
<h1 style="color:#f7f5ef;font-size:32px;line-height:40px;">${subject}</h1>
<ol style="color:#c8c6bf;font-size:16px;line-height:26px;padding-left:22px;">${steps.map(step => `<li style="padding-bottom:12px;">${escapeHTML(step)}</li>`).join('')}</ol>
<p style="padding:20px 0 30px;"><a href="${ANDROID_INVITATION_URL}" style="display:inline-block;background:#e7b858;color:#181818;text-decoration:none;font-weight:bold;padding:16px 24px;border-radius:10px;">Join Android Test</a></p>
</td></tr>`).replace('<title>Your verification code</title>', `<title>${subject}</title>`)
    .replace('Enter your verification code in Zippi to activate your Partner Preview.', 'Your invitation to try Zippi on Android.')
    .replace('src="cid:zippi-bunny"', `src="${ANDROID_EMAIL_LOGO_URL}"`);
  return { subject, html, text: `${subject}\n\n${steps.map((step, i) => `${i + 1}. ${step}`).join('\n')}\n\nJoin Android Test:\n${ANDROID_INVITATION_URL}\n\nNeed help? Contact support@heyzippi.com.\n\nThe Zippi Team\nZippi Technologies` };
}
module.exports = { androidTesterEmail, ANDROID_TEST_URL };
