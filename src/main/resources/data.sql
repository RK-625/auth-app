-- Clear existing data (optional, but good for testing variety)
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE `user->roles`;
TRUNCATE TABLE roles;
TRUNCATE TABLE users;
SET FOREIGN_KEY_CHECKS = 1;

-- Roles initialization (UUIDs as strings for compatibility, MySQL will convert if BINARY(16))
-- Note: Replace UUID_TO_BIN('...') with just '...' if your driver/version handles string to binary conversion automatically.
INSERT INTO roles (id, role_name) VALUES 
(UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440000'), 'ROLE_ROOT'),
(UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440001'), 'ROLE_ADMIN'),
(UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002'), 'ROLE_USER');

-- Users initialization (password is 'password' encoded with BCrypt)
-- Root User
INSERT INTO users (user_id, user_email, user_name, password, enabled, provider, created_at, updated_at) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440000'), 'root@authapp.com', 'Root Administrator', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.TVuHOnu', true, 'LOCAL', NOW(), NOW());

-- Admin User
INSERT INTO users (user_id, user_email, user_name, password, enabled, provider, created_at, updated_at) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440001'), 'admin@authapp.com', 'System Admin', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.TVuHOnu', true, 'LOCAL', NOW(), NOW());

-- Google User
INSERT INTO users (user_id, user_email, user_name, password, enabled, provider, image, created_at, updated_at) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440002'), 'john.doe@gmail.com', 'John Doe', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.TVuHOnu', true, 'GOOGLE', 'https://lh3.googleusercontent.com/a/placeholder', NOW(), NOW());

-- GitHub User
INSERT INTO users (user_id, user_email, user_name, password, enabled, provider, image, created_at, updated_at) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440003'), 'jane.smith@github.com', 'Jane Smith', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.TVuHOnu', true, 'GITHUB', 'https://avatars.githubusercontent.com/u/placeholder', NOW(), NOW());

-- Disabled User
INSERT INTO users (user_id, user_email, user_name, password, enabled, provider, created_at, updated_at) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440004'), 'disabled@authapp.com', 'Disabled Account', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.TVuHOnu', false, 'LOCAL', NOW(), NOW());

-- User -> Roles Assignment
-- Root gets all roles
INSERT INTO `user->roles` (user_id, role_id) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440000'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440000')),
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440000'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440001')),
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440000'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002'));

-- Admin gets ADMIN and USER
INSERT INTO `user->roles` (user_id, role_id) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440001'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440001')),
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440001'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002'));

-- Others get just USER
INSERT INTO `user->roles` (user_id, role_id) VALUES 
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440002'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002')),
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440003'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002')),
(UUID_TO_BIN('110e8400-e29b-41d4-a716-446655440004'), UUID_TO_BIN('550e8400-e29b-41d4-a716-446655440002'));
