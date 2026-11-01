require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool } = require('../src/db');

(async () => {
  const name = process.env.HR_NAME || 'HR Admin';
  const username = (process.env.HR_USERNAME || 'hr').trim().toLowerCase();
  const password = process.env.HR_PASSWORD;
  if (!password || password.length < 8) {
    console.error('Set HR_PASSWORD (at least 8 characters) in .env first.');
    process.exit(1);
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (name, username, password_hash, role)
       VALUES ($1, $2, $3, 'hr')
       ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, name = EXCLUDED.name, role = 'hr', active = TRUE`,
      [name, username, hash]
    );
    console.log(`HR login ready. Username: ${username}`);
  } catch (e) {
    console.error('Seed failed:', e.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
