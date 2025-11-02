DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS usersecure;
DROP TABLE IF EXISTS products;
-- DROP TABLE IF EXISTS comments;

-- User table
CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

-- User table for secure registration
CREATE TABLE usersecure (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  hash TEXT NOT NULL
);

-- Products table
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  sku TEXT UNIQUE,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Comments table
--CREATE TABLE comments (
--    id INTEGER PRIMARY KEY,
--    content TEXT NOT NULL
--);

-- Seed products (sample rows for demo)
INSERT INTO products (name, description, price, sku) VALUES ('Red Widget', 'A great red widget', 9.99, 'RW-001');
INSERT INTO products (name, description, price, sku) VALUES ('Blue Widget', 'A great blue widget', 12.50, 'BW-002');
INSERT INTO products (name, description, price, sku) VALUES ('Green Thing', 'Useful green thing', 7.25, 'GT-003');
INSERT INTO products (name, description, price, sku) VALUES ('Yellow Gadget', 'Bright and small', 15.00, 'YG-004');
INSERT INTO products (name, description, price, sku) VALUES ('Black Clock', 'Loose black clock', 19.25, 'GT-005');
INSERT INTO products (name, description, price, sku) VALUES ('White Pants', 'Vintage white pants', 1.00, 'YG-006');