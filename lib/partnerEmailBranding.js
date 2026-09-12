const fs = require('node:fs');
const path = require('node:path');
const welcomeHTML = fs.readFileSync(path.join(__dirname, 'emailTemplates/partnerWelcome.html'), 'utf8');
const logo = fs.readFileSync(path.join(__dirname, '../admin/public/zippi-logo-nano.png')).toString('base64');
const inlineLogo = () => ({filename:'zippi-bunny.png',content:logo,content_type:'image/png',content_id:'zippi-bunny'});
const escapeHTML = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

// Reuse the already approved email chrome, responsive styles, logo and closing.
// No recipient-provided content is interpolated into this layout.
function verificationLayout(content) {
  const bodyStart = welcomeHTML.indexOf('<tr><td class="pad" style="padding:0 40px;">');
  const footerStart = welcomeHTML.indexOf('<tr><td class="pad footer"');
  if (bodyStart < 0 || footerStart < bodyStart) throw new Error('partner_email_layout_invalid');
  const header = welcomeHTML.slice(0, bodyStart)
    .replace("<title>You're invited to preview Zippi</title>", '<title>Your verification code</title>')
    .replace('Your private invitation to a more natural way to search for travel.', 'Enter your verification code in Zippi to activate your Partner Preview.')
    .replace('</style>', '@media screen and (max-width:620px) { .verification-code { font-size:34px !important; letter-spacing:6px !important; } }\n</style>');
  const footer = welcomeHTML.slice(footerStart)
    .replace('If you have any questions accessing your preview, contact ', 'Need help? Contact ')
    .replace('Thanks for exploring Zippi.<br>', '');
  return header + content + footer;
}
module.exports = { inlineLogo, escapeHTML, verificationLayout };
