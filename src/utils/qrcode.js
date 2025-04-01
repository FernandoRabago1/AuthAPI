const { authenticator } = require('otplib');
const qrcode = require('qrcode');

async function generateQRCode(email, secret) {
  const uri = authenticator.keyuri(email, 'manfra.io', secret);
  return await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });
}

module.exports = { generateQRCode };
