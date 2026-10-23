// Vulnerable JavaScript Test Code

// استبدل السطر الرابع بهذا:
const API_SECRET_TOKEN = "my_dummy_secret_key_12345";
// 2. Code Injection / Insecure Execution
function executeUserData(userInput) {
    // Dangerous eval usage
    eval(userInput);
}

// 3. Weak Cryptography
const crypto = require('crypto');
function hashPassword(password) {
    // Using weak MD5 hash
    return crypto.createHash('md5').update(password).digest('hex');
}
