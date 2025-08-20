-- Enterprise Database Initialization Script
-- PQC-VPN Enterprise Database Schema

-- Create database if not exists (handled by docker)
-- CREATE DATABASE pqc_vpn_enterprise;

-- Connect to the database
\c pqc_vpn_enterprise;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create enterprise users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    auth_type VARCHAR(20) NOT NULL DEFAULT 'pki', -- 'pki', 'psk', 'hybrid'
    psk_key TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- 'active', 'inactive', 'suspended'
    full_name VARCHAR(255),
    department VARCHAR(100),
    location VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    created_by VARCHAR(64),
    updated_by VARCHAR(64),
    
    -- Enterprise fields
    employee_id VARCHAR(50),
    cost_center VARCHAR(50),
    manager_email VARCHAR(255),
    access_level VARCHAR(20) DEFAULT 'standard', -- 'basic', 'standard', 'premium', 'admin'
    
    CHECK (auth_type IN ('pki', 'psk', 'hybrid')),
    CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    CHECK (access_level IN ('basic', 'standard', 'premium', 'admin'))
);

-- Create connection logs table
CREATE TABLE IF NOT EXISTS connection_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL,
    connection_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    disconnection_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- 'connecting', 'connected', 'disconnected', 'failed'
    ip_address INET,
    client_ip INET,
    tunnel_ip INET,
    auth_type VARCHAR(20),
    pqc_algorithm VARCHAR(50),
    encryption_algorithm VARCHAR(100),
    duration INTEGER, -- seconds
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    
    -- Connection details
    client_version VARCHAR(100),
    client_os VARCHAR(50),
    connection_method VARCHAR(20), -- 'ikev2', 'ikev1'
    
    -- Enterprise audit
    session_id UUID DEFAULT uuid_generate_v4(),
    source_location VARCHAR(100),
    
    CHECK (status IN ('connecting', 'connected', 'disconnected', 'failed', 'timeout'))
);

-- Create certificates table
CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    certificate_type VARCHAR(20) NOT NULL, -- 'ca', 'server', 'client'
    common_name VARCHAR(255) NOT NULL,
    serial_number VARCHAR(100) UNIQUE,
    subject_dn TEXT,
    issuer_dn TEXT,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,
    key_algorithm VARCHAR(50), -- 'rsa', 'ecdsa', 'dilithium2', 'dilithium3', 'dilithium5', 'falcon512', 'falcon1024'
    key_size INTEGER,
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'revoked', 'expired', 'pending'
    revocation_reason VARCHAR(100),
    revoked_at TIMESTAMP WITH TIME ZONE,
    certificate_pem TEXT,
    private_key_encrypted TEXT,
    
    -- Enterprise tracking
    issued_by VARCHAR(64),
    auto_renewal BOOLEAN DEFAULT true,
    renewal_threshold_days INTEGER DEFAULT 30,
    
    CHECK (certificate_type IN ('ca', 'server', 'client')),
    CHECK (status IN ('active', 'revoked', 'expired', 'pending', 'renewed'))
);

-- Create system metrics table
CREATE TABLE IF NOT EXISTS system_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metric_type VARCHAR(50) NOT NULL, -- 'cpu', 'memory', 'disk', 'network', 'vpn'
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(15,6),
    metric_unit VARCHAR(20),
    source_component VARCHAR(50), -- 'hub', 'client', 'database', 'api'
    additional_data JSONB
);

-- Create security events table
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL, -- 'login_success', 'login_failure', 'certificate_issued', 'connection_failed'
    severity VARCHAR(20) DEFAULT 'info', -- 'low', 'medium', 'high', 'critical'
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    source_ip INET,
    user_agent TEXT,
    event_description TEXT NOT NULL,
    event_data JSONB,
    resolved BOOLEAN DEFAULT false,
    resolved_by VARCHAR(64),
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Create configuration table
CREATE TABLE IF NOT EXISTS configuration (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type VARCHAR(20) DEFAULT 'string', -- 'string', 'integer', 'boolean', 'json'
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    category VARCHAR(50), -- 'vpn', 'security', 'monitoring', 'enterprise'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(64)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_auth_type ON users(auth_type);

CREATE INDEX IF NOT EXISTS idx_connection_logs_user_id ON connection_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_client_id ON connection_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_connection_time ON connection_logs(connection_time);
CREATE INDEX IF NOT EXISTS idx_connection_logs_status ON connection_logs(status);
CREATE INDEX IF NOT EXISTS idx_connection_logs_session_id ON connection_logs(session_id);

CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_certificates_serial_number ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_valid_until ON certificates(valid_until);

CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_system_metrics_type ON system_metrics(metric_type);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);

-- Create functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_configuration_updated_at BEFORE UPDATE ON configuration
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default configuration
INSERT INTO configuration (config_key, config_value, config_type, description, category) VALUES
('vpn.pqc_kem_algorithm', 'kyber1024', 'string', 'Default PQC KEM algorithm', 'vpn'),
('vpn.pqc_sig_algorithm', 'dilithium5', 'string', 'Default PQC signature algorithm', 'vpn'),
('vpn.default_auth_type', 'pki', 'string', 'Default authentication type for new users', 'vpn'),
('security.session_timeout', '3600', 'integer', 'Session timeout in seconds', 'security'),
('security.max_failed_logins', '5', 'integer', 'Maximum failed login attempts before lockout', 'security'),
('security.lockout_duration', '1800', 'integer', 'Account lockout duration in seconds', 'security'),
('monitoring.metrics_retention_days', '90', 'integer', 'Number of days to retain metrics', 'monitoring'),
('monitoring.log_retention_days', '365', 'integer', 'Number of days to retain logs', 'monitoring'),
('enterprise.auto_user_provisioning', 'false', 'boolean', 'Enable automatic user provisioning', 'enterprise'),
('enterprise.require_2fa', 'false', 'boolean', 'Require two-factor authentication', 'enterprise')
ON CONFLICT (config_key) DO NOTHING;

-- Insert demo admin user (for demo purposes only)
INSERT INTO users (username, email, auth_type, status, full_name, department, role, access_level) VALUES
('admin', 'admin@enterprise.demo', 'pki', 'active', 'System Administrator', 'IT', 'admin', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Create views for reporting
CREATE OR REPLACE VIEW active_connections AS
SELECT 
    cl.id,
    cl.client_id,
    u.username,
    u.full_name,
    u.department,
    cl.connection_time,
    cl.ip_address,
    cl.auth_type,
    cl.pqc_algorithm,
    cl.encryption_algorithm,
    EXTRACT(EPOCH FROM (NOW() - cl.connection_time))::INTEGER as duration_seconds
FROM connection_logs cl
JOIN users u ON cl.user_id = u.id
WHERE cl.status = 'connected' 
    AND cl.disconnection_time IS NULL
ORDER BY cl.connection_time DESC;

CREATE OR REPLACE VIEW user_connection_summary AS
SELECT 
    u.id,
    u.username,
    u.full_name,
    u.department,
    u.status,
    COUNT(cl.id) as total_connections,
    MAX(cl.connection_time) as last_connection,
    SUM(cl.duration) as total_duration_seconds,
    SUM(cl.bytes_in + cl.bytes_out) as total_bytes
FROM users u
LEFT JOIN connection_logs cl ON u.id = cl.user_id
GROUP BY u.id, u.username, u.full_name, u.department, u.status
ORDER BY total_connections DESC;

CREATE OR REPLACE VIEW security_event_summary AS
SELECT 
    event_type,
    severity,
    COUNT(*) as event_count,
    MAX(timestamp) as latest_event
FROM security_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY event_type, severity
ORDER BY event_count DESC;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pqc_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pqc_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO pqc_admin;

-- Insert initial security event
INSERT INTO security_events (event_type, severity, event_description, event_data) VALUES
('system_init', 'info', 'PQC-VPN Enterprise database initialized', '{"version": "1.0.0", "timestamp": "' || NOW() || '"}');

-- Create database version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version VARCHAR(20) PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_version (version, description) VALUES
('1.0.0', 'Initial enterprise schema with PQC support');

COMMIT;
