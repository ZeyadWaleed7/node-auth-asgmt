const crypto = require('crypto');

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const iterations = 100000;
    const keyLength = 64; 
    const digest = 'sha512';
    const hashedPassword = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest).toString('hex');
    
    return { salt, hashedPassword };
}

function verifyPassword(password, salt, storedHash) {
    const iterations = 100000;
    const keyLength = 64;
    const digest = 'sha512';
    const hash = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest).toString('hex');
    
    return hash === storedHash;
}

module.exports = { hashPassword, verifyPassword };
