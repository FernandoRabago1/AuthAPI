// src/models/user.model.js
const pool = require('../db/postgres');

/**
 * Busca un usuario por su email.
 * @param {string} email 
 * @returns {Promise<Object|null>}
 */
async function findOneByEmail(email) {
  const result = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
  return result.rows[0] || null;
}

/**
 * Busca un usuario por su ID.
 * @param {number} id 
 * @returns {Promise<Object|null>}
 */
async function findOneById(id) {
  const result = await pool.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [id]);
  return result.rows[0] || null;
}

/**
 * Inserta un nuevo usuario en la base de datos.
 * Se agrega la columna identityVerificationStatus con valor por defecto "Not verified".
 * @param {Object} userData 
 * @param {string} userData.name
 * @param {string} userData.email
 * @param {string} userData.password
 * @param {string} userData.role
 * @param {boolean} userData.twofaEnable
 * @param {string|null} userData.twofaSecret
 * @returns {Promise<Object>}
 */
async function insertUser({ name, email, password, role, twofaEnable, twofaSecret }) {
  const query = `
    INSERT INTO users (name, email, password, role, "2faEnable", "2faSecret", identityVerificationStatus)
    VALUES ($1, $2, $3, $4, $5, $6, 'Not verified')
    RETURNING *
  `;
  const values = [name, email, password, role, twofaEnable, twofaSecret];
  const result = await pool.query(query, values);
  return result.rows[0];
}

/**
 * Actualiza los campos de un usuario.
 * @param {number} id
 * @param {Object} fields - Un objeto con los campos a actualizar.
 * @returns {Promise<Object|null>}
 */
async function updateUser(id, fields) {
  const setClauses = [];
  const values = [];
  let i = 1;
  for (const key in fields) {
    setClauses.push(`"${key}" = $${i}`);
    values.push(fields[key]);
    i++;
  }
  values.push(id);
  const query = `UPDATE users SET ${setClauses.join(', ')} WHERE id = $${i} RETURNING *`;
  const result = await pool.query(query, values);
  return result.rows[0] || null;
}

module.exports = {
  findOneByEmail,
  findOneById,
  insertUser,
  updateUser
};
