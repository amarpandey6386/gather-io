-- Run this SQL to update event_status enum to include 'live' and 'closed'

ALTER TABLE selected_events 
MODIFY COLUMN event_status ENUM('upcoming', 'live', 'closed') DEFAULT 'upcoming';
