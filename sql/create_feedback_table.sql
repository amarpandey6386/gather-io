-- Run this SQL to create the feedback table

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    name VARCHAR(100),
    email VARCHAR(100),
    feedback_type ENUM('bug', 'feature', 'improvement', 'general') DEFAULT 'general',
    message TEXT NOT NULL,
    rating INT CHECK (rating >= 1 AND rating <= 5),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_created_at (created_at),
    INDEX idx_feedback_type (feedback_type)
);
