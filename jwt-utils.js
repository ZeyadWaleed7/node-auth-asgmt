const { SignJWT, jwtVerify } = require('jose');

const SECRET_KEY = 'my_secret'; 

async function signJWT(payload) {
  const encodedSecret = Buffer.from(SECRET_KEY);
  
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d') 
    .sign(encodedSecret);

  return token;
}

async function verifyJWT(token) {
  const encodedSecret = Buffer.from(SECRET_KEY);
  
  try {
    const { payload } = await jwtVerify(token, encodedSecret);
    return payload;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

module.exports = { signJWT, verifyJWT };