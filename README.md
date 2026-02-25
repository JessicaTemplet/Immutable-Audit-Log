# Immutable Audit Log Service

A high-integrity activity tracking system designed for compliance and observability. This service captures a complete history of system changes using PostgreSQL.

##  Key Engineering Features

### 1. JSONB for Structural Flexibility
Storing "Before" and "After" states in traditional columns is brittle. I utilized **PostgreSQL JSONB** columns, which allow for schema-less data storage while maintaining the ability to index and query specific keys within the JSON.

### 2. Optimized Indexing Strategy
Audit logs grow indefinitely. I implemented **GIN (Generalized Inverted Index) and B-Tree indexes** on the `resource_id` and `actor_id` to ensure that searching for the history of a specific object remains sub-second even with millions of rows.

### 3. Transactional Integrity
Logs are written within the same database transaction as the business change, ensuring that we never have a "ghost change" (a log without a change) or a "silent change" (a change without a log).

##  Tech Stack
* **Language:** Python
* **Database:** PostgreSQL
* **Library:** `psycopg2` (Thread-safe connection pooling)

##  SQL Query Showcase
The repository includes optimized queries for:
* Reconstructing the state of an object at any point in time.
* Identifying "Hot Resources" (objects changed most frequently).
* User activity timelines.
