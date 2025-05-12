const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client();

const verifyGoogleToken = async (token) => {
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: null, // optional: specify your Google Client ID
  });
  return ticket.getPayload();
};

module.exports = verifyGoogleToken;
