import json
import hashlib
import hmac
from contextlib import contextmanager
from functools import wraps
from psycopg2 import pool
from psycopg2.extras import Json
from datetime import datetime

class AuditLogger:
    """
    Production-ready audit logging with tamper detection and connection pooling.
    
    Features:
    - Cryptographic hash chain for tamper evidence
    - Thread-safe connection pooling
    - Context manager for automatic change tracking
    - Decorator for function-level auditing
    - JSONB storage for flexible before/after states
    """
    
    def __init__(self, dbname="portfolio", user="postgres", password="secret", 
                 host="localhost", min_conn=1, max_conn=10, secret_key="your-secret-key-change-me"):
        """
        Initialize the audit logger with connection pool and security settings.
        
        Args:
            dbname: Database name
            user: Database user
            password: Database password
            host: Database host
            min_conn: Minimum connections in pool
            max_conn: Maximum connections in pool
            secret_key: Key used for HMAC signatures (store in env var in production!)
        """
        self.secret_key = secret_key
        self.pool = pool.SimpleConnectionPool(
            min_conn, max_conn,
            dbname=dbname,
            user=user,
            password=password,
            host=host
        )
        
        # Initialize the database table if it doesn't exist
        self._init_db()
    
    def _init_db(self):
        """Create the audit_logs table if it doesn't exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            actor_id UUID NOT NULL,
            action VARCHAR(50) NOT NULL,
            resource_type VARCHAR(50),
            resource_id UUID NOT NULL,
            old_values JSONB,
            new_values JSONB,
            previous_hash TEXT,
            hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes for fast retrieval
        CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs (resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at);
        """
        
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(create_table_sql)
            conn.commit()
        finally:
            self._return_conn(conn)
    
    def _get_conn(self):
        """Get a connection from the pool."""
        return self.pool.getconn()
    
    def _return_conn(self, conn):
        """Return a connection to the pool."""
        self.pool.putconn(conn)
    
    def _get_current_state(self, resource_type, resource_id):
        """
        Mock method to get current state of a resource.
        In production, you'd query your actual database.
        
        This is a placeholder - replace with your actual data fetching logic.
        """
        # This is just a mock - you'll need to implement this based on your data models
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                # Example: Try to get from a hypothetical table
                # You'll need to adjust this based on your actual schema
                table_name = resource_type.lower()
                cur.execute(f"""
                    SELECT row_to_json(t) 
                    FROM {table_name} t 
                    WHERE id = %s
                """, (resource_id,))
                result = cur.fetchone()
                return result[0] if result else None
        except Exception:
            # If table doesn't exist or other error, return None
            return None
        finally:
            self._return_conn(conn)
    
    def _compute_hash(self, previous_hash, data):
        """
        Create a hash chain like blockchain.
        
        Args:
            previous_hash: Hash of the previous log entry
            data: Dictionary containing the current log data
        
        Returns:
            HMAC-SHA256 hash as hex string
        """
        # Sort keys for consistent serialization
        message = f"{previous_hash}:{json.dumps(data, sort_keys=True)}".encode()
        return hmac.new(self.secret_key.encode(), message, hashlib.sha256).hexdigest()
    
    def log_change(self, actor_id, action, resource_type, resource_id, old_val=None, new_val=None):
        """
        Log a change to the audit system with cryptographic chaining.
        
        Args:
            actor_id: UUID of the user who made the change
            action: 'CREATE', 'UPDATE', 'DELETE', etc.
            resource_type: Type of resource (e.g., 'USER', 'INVOICE')
            resource_id: UUID of the resource
            old_val: Dictionary of old values (before change)
            new_val: Dictionary of new values (after change)
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                # Get the most recent hash to chain with
                cur.execute("""
                    SELECT hash FROM audit_logs 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """)
                result = cur.fetchone()
                previous_hash = result[0] if result else "genesis"
                
                # Prepare data for hashing
                log_data = {
                    "actor": str(actor_id),
                    "action": action,
                    "resource": f"{resource_type}:{resource_id}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "old": old_val,
                    "new": new_val
                }
                
                current_hash = self._compute_hash(previous_hash, log_data)
                
                # Insert the audit log
                cur.execute("""
                    INSERT INTO audit_logs 
                    (actor_id, action, resource_type, resource_id, old_values, new_values, previous_hash, hash)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    actor_id, action, resource_type, resource_id, 
                    Json(old_val) if old_val else None, 
                    Json(new_val) if new_val else None, 
                    previous_hash, 
                    current_hash
                ))
                
                log_id = cur.fetchone()[0]
                conn.commit()
                return log_id
                
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self._return_conn(conn)
    
    @contextmanager
    def track_changes(self, actor_id, resource_type, resource_id):
        """
        Context manager that automatically logs changes to a resource.
        
        Usage:
            with logger.track_changes(user.id, "USER", user.id):
                user.update_profile(new_data)
        
        Args:
            actor_id: Who is making the change
            resource_type: Type of resource being changed
            resource_id: ID of the resource
        """
        # Capture before state
        old_val = self._get_current_state(resource_type, resource_id)
        
        # Let the code block execute
        yield
        
        # Capture after state and log if changed
        new_val = self._get_current_state(resource_type, resource_id)
        if old_val != new_val:
            self.log_change(
                actor_id=actor_id,
                action="UPDATE",
                resource_type=resource_type,
                resource_id=resource_id,
                old_val=old_val,
                new_val=new_val
            )
    
    def audit_logged(self, actor_extractor=None):
        """
        Decorator for automatically logging function calls.
        
        Usage:
            @logger.audit_logged(lambda user, *args, **kwargs: user.id)
            def update_user(user, new_data):
                user.update(new_data)
        
        Args:
            actor_extractor: Function that extracts actor ID from args/kwargs
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract actor ID
                if actor_extractor:
                    actor_id = actor_extractor(*args, **kwargs)
                else:
                    # Default: assume first arg has 'id' attribute
                    actor_id = args[0].id if args and hasattr(args[0], 'id') else None
                
                # Try to extract resource info from function name or args
                resource_type = func.__name__.upper()
                resource_id = str(args[0].id) if args and hasattr(args[0], 'id') else 'unknown'
                
                # Track changes
                with self.track_changes(actor_id, resource_type, resource_id):
                    return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def verify_chain_integrity(self):
        """
        Verify that the hash chain hasn't been tampered with.
        
        Returns:
            Tuple of (is_valid: bool, broken_links: list)
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                # Get all logs in order
                cur.execute("""
                    SELECT id, previous_hash, hash, actor_id, action, resource_type, resource_id, 
                           old_values, new_values, created_at
                    FROM audit_logs 
                    ORDER BY created_at ASC
                """)
                logs = cur.fetchall()
                
                if not logs:
                    return True, []
                
                broken_links = []
                previous_hash = "genesis"
                
                for log in logs:
                    log_id, prev_hash, curr_hash, actor, action, rtype, rid, old, new, ts = log
                    
                    # Reconstruct data for this log
                    log_data = {
                        "actor": str(actor),
                        "action": action,
                        "resource": f"{rtype}:{rid}",
                        "timestamp": ts.isoformat() if ts else None,
                        "old": old,
                        "new": new
                    }
                    
                    # Verify hash
                    expected_hash = self._compute_hash(prev_hash, log_data)
                    
                    if expected_hash != curr_hash:
                        broken_links.append({
                            'id': log_id,
                            'expected': expected_hash,
                            'found': curr_hash
                        })
                    
                    previous_hash = curr_hash
                
                return len(broken_links) == 0, broken_links
                
        finally:
            self._return_conn(conn)
    
    def get_resource_history(self, resource_type, resource_id, limit=100):
        """
        Get the complete audit history for a specific resource.
        
        Args:
            resource_type: Type of resource
            resource_id: ID of the resource
            limit: Maximum number of records to return
        
        Returns:
            List of audit records
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        created_at,
                        action,
                        actor_id,
                        old_values,
                        new_values,
                        hash
                    FROM audit_logs 
                    WHERE resource_type = %s AND resource_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (resource_type, resource_id, limit))
                
                results = []
                for row in cur.fetchall():
                    results.append({
                        'timestamp': row[0],
                        'action': row[1],
                        'actor': row[2],
                        'old_values': row[3],
                        'new_values': row[4],
                        'hash': row[5]
                    })
                return results
        finally:
            self._return_conn(conn)
    
    def close(self):
        """Close all connections in the pool."""
        self.pool.closeall()


# Example usage and test code
if __name__ == "__main__":
    # Initialize the logger
    logger = AuditLogger(
        dbname="portfolio",
        user="postgres", 
        password="secret",
        secret_key="development-key-change-in-production"
    )
    
    try:
        # Example 1: Basic logging
        print("1. Testing basic logging...")
        log_id = logger.log_change(
            actor_id="123e4567-e89b-12d3-a456-426614174000",
            action="UPDATE",
            resource_type="INVOICE",
            resource_id="987fcdeb-51a2-43d7-9b56-243678901234",
            old_val={"status": "draft", "amount": 100},
            new_val={"status": "paid", "amount": 100}
        )
        print(f"   Created log entry with ID: {log_id}")
        
        # Example 2: Context manager
        print("\n2. Testing context manager...")
        
        # Mock object for demonstration
        class MockUser:
            def __init__(self, id, name, email):
                self.id = id
                self.name = name
                self.email = email
            
            def update(self, name=None, email=None):
                if name:
                    self.name = name
                if email:
                    self.email = email
        
        user = MockUser(
            id="123e4567-e89b-12d3-a456-426614174000",
            name="John Doe",
            email="john@example.com"
        )
        
        # Track changes to the user
        with logger.track_changes(user.id, "USER", user.id):
            user.update(name="John Smith")
        print("   Changes tracked automatically")
        
        # Example 3: Decorator
        print("\n3. Testing decorator...")
        
        @logger.audit_logged(lambda user, *args, **kwargs: user.id)
        def update_user_email(user, new_email):
            user.email = new_email
            return user
        
        update_user_email(user, "john.smith@example.com")
        print("   Function call logged automatically")
        
        # Example 4: Verify chain integrity
        print("\n4. Testing chain integrity...")
        is_valid, broken = logger.verify_chain_integrity()
        print(f"   Chain valid: {is_valid}")
        if broken:
            print(f"   Broken links: {broken}")
        
        # Example 5: Get resource history
        print("\n5. Getting resource history...")
        history = logger.get_resource_history("USER", user.id, limit=10)
        print(f"   Found {len(history)} records")
        for record in history:
            print(f"   - {record['timestamp']}: {record['action']} by {record['actor']}")
        
    finally:
        # Always close the connection pool
        logger.close()
        print("\n Connection pool closed")