function invitationInstructions(platform) {
  const steps = platform === "ios"
    ? "1. Install Apple's TestFlight app: https://apps.apple.com/app/testflight/id899247664\n2. Look for your TestFlight invitation email and accept it. Apple may take a little time to send it.\n3. Install Zippi in TestFlight."
    : "1. Open https://play.google.com/apps/testing/com.heyzippi.app using your Google account.\n2. Choose to become a tester, then follow the Google Play link to install Zippi. Availability depends on your country and device.";
  return { subject: "You're invited to preview Zippi",
    text: `You're invited to preview Zippi!\n\n${steps}\n4. Open Zippi. When asked for Partner Preview access, enter the same email address that received this invitation and verify your code.\n\nThis is a preview build. We'd love to hear what works well and what could be better. Send feedback to support@heyzippi.com.\n\nThanks for trying Zippi!` };
}
module.exports = { invitationInstructions };
