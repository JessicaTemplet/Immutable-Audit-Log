CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID NOT NULL,          -- Who did it
    action VARCHAR(50) NOT NULL,     -- 'CREATE', 'UPDATE', 'DELETE'
    resource_type VARCHAR(50),       -- 'USER', 'INVOICE', 'SETTING'
    resource_id UUID NOT NULL,       -- ID of the thing changed
    
    -- Using JSONB for flexible but searchable diffs
    old_values JSONB, 
    new_values JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexing for fast retrieval (Portfolio highlight!)
CREATE INDEX idx_audit_resource ON audit_logs (resource_type, resource_id);
CREATE INDEX idx_audit_actor ON audit_logs (actor_id);