# SQL Database Setup Files

This folder contains all SQL scripts needed to set up the EventHub database.

## Setup Order

Run these SQL files in the following order:

### 1. Core Tables (Run First)
These should already exist in your database:
- `users` table
- `clubs` table
- `ideas` table
- `votes` table
- `selected_events` table

### 2. Feature Tables (Run in Order)

#### Notifications System
```bash
mysql -u your_username -p your_database_name < create_notifications_table.sql
```
Creates the `notifications` table for event notifications to students.

#### Club Membership System
```bash
mysql -u your_username -p your_database_name < create_club_memberships_table.sql
```
Creates:
- `club_membership_requests` table
- `club_members` table

#### Event Details & Participants
```bash
mysql -u your_username -p your_database_name < update_events_table.sql
```
Adds columns to `selected_events` table:
- `event_venue`
- `event_date`
- `event_time`
- `event_description`
- `max_participants`
- `registration_deadline`

Creates `event_participants` table for event registrations.

#### Event Lifecycle
```bash
mysql -u your_username -p your_database_name < update_event_status.sql
```
Updates `event_status` enum to include: 'upcoming', 'live', 'closed'

#### Feedback System
```bash
mysql -u your_username -p your_database_name < create_feedback_table.sql
```
Creates the `feedback` table for user feedback collection.

## Quick Setup (All at Once)

To run all SQL files at once:

```bash
cd sql
mysql -u your_username -p your_database_name < create_notifications_table.sql
mysql -u your_username -p your_database_name < create_club_memberships_table.sql
mysql -u your_username -p your_database_name < update_events_table.sql
mysql -u your_username -p your_database_name < update_event_status.sql
mysql -u your_username -p your_database_name < create_feedback_table.sql
```

## File Descriptions

| File | Purpose |
|------|---------|
| `create_notifications_table.sql` | Event notifications for students |
| `create_club_memberships_table.sql` | Club membership requests and members |
| `update_events_table.sql` | Event details and participant registration |
| `update_event_status.sql` | Event lifecycle states (upcoming/live/closed) |
| `create_feedback_table.sql` | User feedback collection system |

## Notes

- Make sure to replace `your_username` and `your_database_name` with your actual MySQL credentials
- Run these scripts only once to avoid duplicate table errors
- If a table already exists, you may need to drop it first or skip that file
