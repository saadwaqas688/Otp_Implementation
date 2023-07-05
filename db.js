const { Pool } = require('pg');

const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "postgres",
    password: "Aa@132599",
  port: 5432 // Default PostgreSQL port
});

module.exports = {
  query: (text, params, callback) => {
    return pool.query(text, params, callback);
  }
};
