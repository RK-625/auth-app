-- -----------------------------------------------------------------------------
-- Authentication Application Data Seeding (Legacy Ref)
-- -----------------------------------------------------------------------------
-- This file is kept for schema reference. 
-- SEEDING IS NOW MANAGED PROGRAMMATICALLY BY DataSeeder.java
-- -----------------------------------------------------------------------------

-- --- 1. CLEANUP ---
-- SET FOREIGN_KEY_CHECKS = 0;
-- TRUNCATE TABLE `user->roles`;
-- TRUNCATE TABLE roles;
-- TRUNCATE TABLE users;
-- SET FOREIGN_KEY_CHECKS = 1;

-- Data seeding moved to com.substring.authapp.config.DataSeeder
