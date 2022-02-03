const crypto = require('crypto');

function CreatePasswordHash(password) {
    const salt = crypto.randomBytes(32).toString('hex');
    console.log("i created you hash and namak" + salt);
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

    const passwordhash = {
        passsalt: salt,
        passhash: hash
    };
    return passwordhash;
}

function Validate(password, salt, hash) {
    const phash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    console.log("you called me from verify callback i am validating your password");
    if(phash === hash) return true
    return false;
}

module.exports.passCreate = CreatePasswordHash;
module.exports.validate = Validate;