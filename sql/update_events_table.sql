-- Run this SQL to add event details columns to selected_events table

ALTER TABLE selected_events
ADD COLUMN event_venue VARCHAR(255) AFTER event_status,
ADD COLUMN event_date DATE AFTER event_venue,
ADD COLUMN event_time TIME AFTER event_date,
ADD COLUMN event_description TEXT AFTER event_time,
ADD COLUMN max_participants INT DEFAULT 100 AFTER event_description,
ADD COLUMN registration_deadline DATE AFTER max_participants;

-- Table for event participants
CREATE TABLE IF NOT EXISTS event_participants (
    participant_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    student_id INT NOT NULL,
    student_name VARCHAR(100) NOT NULL,
    student_email VARCHAR(100) NOT NULL,
    student_phone VARCHAR(20),
    participation_type ENUM('participant', 'volunteer') DEFAULT 'participant',
    additional_info TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES selected_events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE KEY unique_participation (event_id, student_id),
    INDEX idx_event (event_id),
    INDEX idx_student (student_id)
);
