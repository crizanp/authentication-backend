const { Client } = require('pg');

const client = new Client({
  host: "45.115.219.189",
  user: "apinepalishram_user",
  port: 5432,
  password: "Sriiaiskn", 
  database: "apinepalishram_web",
});

client.connect(err => {
  if (err) {
    console.error('Connection error:', err.stack);
  } else {
    console.log('Connected to database');
    
    client.query('SELECT * FROM users', (err, res) => {
      if (err) {
        console.log('Query error:', err.message);
      } else {
        console.log('Query result:', res.rows);
      }

      client.end();
    });
  }
});
