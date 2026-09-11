const fs = require("node:fs");
const path = require("node:path");
const partnerWelcomeHTML = fs.readFileSync(path.join(__dirname, "emailTemplates/partnerWelcome.html"), "utf8");
const partnerWelcomeText = fs.readFileSync(path.join(__dirname, "emailTemplates/partnerWelcome.txt"), "utf8");
const partnerLogo = fs.readFileSync(path.join(__dirname, "../admin/public/zippi-logo-nano.png")).toString("base64");

const { normalizeEmail } = require("./partnerAccess");
const escapeHTML = value => value.replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

function invitationInstructions(platform, invitedEmail) {
  if (platform === "ios") {
    const email = normalizeEmail(invitedEmail);
    return {
      subject: "You're invited to preview Zippi",
      text: partnerWelcomeText.replace("{{INVITED_EMAIL}}", () => email),
      html: partnerWelcomeHTML.replace("{{INVITED_EMAIL}}", () => escapeHTML(email)),
      // Inline content avoids dependence on admin asset hosting or remote image requests.
      attachments: [{ filename: "zippi-bunny.png", content: partnerLogo, content_type: "image/png", content_id: "zippi-bunny" }],
    };
  }
  const steps = platform === "ios"
    ? "1. Install Apple's TestFlight app: https://apps.apple.com/app/testflight/id899247664\n2. Look for your TestFlight invitation email and accept it. Apple may take a little time to send it.\n3. Install Zippi in TestFlight."
    : "1. Open https://play.google.com/apps/testing/com.heyzippi.app using your Google account.\n2. Choose to become a tester, then follow the Google Play link to install Zippi. Availability depends on your country and device.";
  return { subject: "You're invited to preview Zippi",
    text: `You're invited to preview Zippi!\n\n${steps}\n4. Open Zippi. When asked for Partner Preview access, enter the same email address that received this invitation and verify your code.\n\nThis is a preview build. We'd love to hear what works well and what could be better. Send feedback to support@heyzippi.com.\n\nThanks for trying Zippi!` };
}
module.exports = { invitationInstructions };
