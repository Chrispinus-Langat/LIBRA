const bcrypt = require('bcryptjs');
const pw = process.argv[2];
if (!pw || pw.length < 8) { console.error('Usage: npm run hash -- "your passcode" (at least 8 characters)'); process.exit(1); }
console.log(bcrypt.hashSync(pw, 12));
