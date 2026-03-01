-- ============================================
-- NORMALIZED & SECURED DATABASE SCHEMA
-- For: infosec_lab (Student Management System)
-- ============================================
-- This file creates the database from scratch.
-- Safe to import in phpMyAdmin — tables are dropped
-- in the correct order to avoid FK constraint errors.
-- ============================================
-- FIXES APPLIED:
--   1. Password column: VARCHAR(100) → VARCHAR(255) for bcrypt
--   2. Admin password hashed (password_hash with PASSWORD_DEFAULT)
--   3. Added email column to users table
--   4. Added role column (ENUM) for access control
--   5. Normalized: courses table created
--   6. Foreign keys: students → courses, students → users
--   7. login_attempts table for security audit logging
--   8. Indexes on frequently queried columns
-- ============================================

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `infosec_lab` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `infosec_lab`;

-- ============================================
-- DROP TABLES (child → parent order to avoid FK errors)
-- ============================================
DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `students`;
DROP TABLE IF EXISTS `courses`;
DROP TABLE IF EXISTS `users`;

-- ============================================
-- 1. USERS TABLE (authentication + roles)
--    Password = VARCHAR(255) for bcrypt hashes
--    Role = ENUM for access control
--    Email = required for contact/recovery
-- ============================================
CREATE TABLE `users` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(50) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `role` ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `username` (`username`),
    UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================
-- 2. COURSES TABLE (normalized from students)
--    Eliminates duplicate storage of course_code
--    and course_description per student row
-- ============================================
CREATE TABLE `courses` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `course_code` VARCHAR(50) NOT NULL,
    `course_description` VARCHAR(255) DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `course_code` (`course_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================
-- 3. STUDENTS TABLE (with foreign keys)
--    course_id → courses.id  (referential integrity)
--    created_by → users.id   (audit who added the record)
-- ============================================
CREATE TABLE `students` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `student_id` VARCHAR(50) NOT NULL,
    `fullname` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `course_id` INT(11) DEFAULT NULL,
    `created_by` INT(11) DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `student_id` (`student_id`),
    KEY `fk_student_course` (`course_id`),
    KEY `fk_student_created_by` (`created_by`),
    CONSTRAINT `fk_student_course` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE SET NULL,
    CONSTRAINT `fk_student_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================
-- 4. LOGIN ATTEMPTS TABLE (audit logging)
--    Tracks every login attempt: username, IP,
--    timestamp, and whether it succeeded
-- ============================================
CREATE TABLE `login_attempts` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(50) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `attempted_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `success` TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    KEY `idx_username` (`username`),
    KEY `idx_attempted_at` (`attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================
-- INSERT DEFAULT ADMIN USER
-- Password: admin123 (hashed with bcrypt via password_hash)
-- Hash: password_hash('admin123', PASSWORD_DEFAULT)
-- ============================================
INSERT INTO `users` (`username`, `password`, `email`, `role`) VALUES
('admin', '$2y$10$Ohpxkwg1Rx2eoR7oMqHus.q/ppCAxsOyvO5TLgfdGEkSD2pHRK.5.', 'admin@example.com', 'admin');

-- ============================================
-- INSERT SAMPLE COURSES
-- ============================================
INSERT INTO `courses` (`course_code`, `course_description`) VALUES
('BSIT', 'Bachelor of Science in Information Technology'),
('BSCS', 'Bachelor of Science in Computer Science'),
('BSIS', 'Bachelor of Science in Information Systems');

-- ============================================
-- BACKUP STRATEGY NOTES:
-- 1. Daily backup:  mysqldump -u root infosec_lab > backup_YYYY-MM-DD.sql
-- 2. Store backups outside web root (e.g., C:\backups\)
-- 3. Retention: 7 daily, 4 weekly, 12 monthly
-- 4. Test restore monthly: mysql -u root infosec_lab < backup_file.sql
-- ============================================
