const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

async function main() {
  console.log('🔐 Creating .env file for Authentication Server\n');
  
  // Generate secure session secret
  const sessionSecret = crypto.randomBytes(64).toString('hex');
  
  let envContent = `# Authentication Server Configuration
PORT=3001
SESSION_SECRET=${sessionSecret}

`;

  // Default users setup (you can modify these)
  const users = [
    {
      username: 'admin',
      password: 'admin123',
      keyFile: null
    },
    {
      username: 'Tobias Reiper',
      password: 'Ort-Myre', 
      keyFile: 'private_key.pem' // Your key file
    }
  ];

  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    console.log(`\n👤 Processing user ${i + 1}: ${user.username}`);
    
    const hashedPassword = await bcrypt.hash(user.password, 12);
    
    envContent += `# User ${i + 1}\n`;
    envContent += `USER_${i + 1}_USERNAME=${user.username}\n`;
    envContent += `USER_${i + 1}_PASSWORD=${hashedPassword}\n`;
    
    if (user.keyFile) {
      const keyFilePath = path.join(__dirname, user.keyFile);
      if (fs.existsSync(keyFilePath)) {
        const fileBuffer = fs.readFileSync(keyFilePath);
        const keyHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        envContent += `USER_${i + 1}_KEY_HASH=${keyHash}\n`;
        console.log(`✅ Key file hash added for ${user.username}`);
      } else {
        console.log(`⚠️  Key file not found: ${user.keyFile}`);
        console.log(`📁 Looking in: ${keyFilePath}`);
      }
    }
    
    envContent += '\n';
  }

  // Write .env file
  fs.writeFileSync('.env', envContent);
  
  console.log('\n✅ .env file created successfully!');
  console.log('\n📋 Generated configuration:');
  console.log('   Server Port: 3001');
  console.log('   Session Secret: Generated');
  console.log(`   Users: ${users.map(u => u.username).join(', ')}`);
  console.log('\n🔐 Default credentials:');
  users.forEach(user => {
    console.log(`   ${user.username} / ${user.password} ${user.keyFile ? '+ key file' : ''}`);
  });
  console.log('\n⚠️  SECURITY NOTES:');
  console.log('   - Change default passwords in production!');
  console.log('   - Keep .env file secure and never commit it');
  console.log('   - Use strong unique passwords');
  console.log('   - Consider using different key files for each user');
  
  rl.close();
}

// Check if bcryptjs is available
try {
  require('bcryptjs');
  main().catch(console.error);
} catch (error) {
  console.log('❌ bcryptjs is required. Install it with:');
  console.log('   npm install bcryptjs');
  process.exit(1);
}