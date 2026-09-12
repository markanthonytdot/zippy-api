const path = require('node:path');

const ANDROID_TEST_URL = 'https://play.google.com/apps/internaltest/4701051442738255142';
const ANDROID_INVITATION_URL = 'https://admin.heyzippi.com/android-test';
const ANDROID_EMAIL_LOGO_URL = 'https://admin.heyzippi.com/email-assets/zippi-logo-v1.png';

// Public email destinations, with no recipient data, authentication or configurable redirect.
function registerAndroidTesterPublicRoutes(app) {
  app.get('/android-test', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300');
    res.redirect(302, ANDROID_TEST_URL);
  });
  app.get('/email-assets/zippi-logo-v1.png', (_req, res) => {
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.sendFile(path.join(__dirname, '../admin/public/zippi-logo-nano.png'), {
      maxAge: '1y', immutable: true,
    });
  });
}

module.exports = { ANDROID_TEST_URL, ANDROID_INVITATION_URL, ANDROID_EMAIL_LOGO_URL, registerAndroidTesterPublicRoutes };
