-- Assets
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(20) NOT NULL,
    value VARCHAR(255) NOT NULL,
    criticality VARCHAR(10) NOT NULL,
    exposure VARCHAR(10) NOT NULL,
    tags TEXT[],
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    discovered_by VARCHAR(50),
    metadata JSONB DEFAULT '{}'
);

-- Scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    profile VARCHAR(20) NOT NULL,
    scope JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(100),
    findings_count JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'
);

-- Findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id),
    scan_id UUID REFERENCES scans(id),
    source VARCHAR(20) NOT NULL,
    type VARCHAR(30) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(10) NOT NULL,
    confidence NUMERIC(3,2),
    status VARCHAR(20) DEFAULT 'open',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Recommendations
CREATE TABLE recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    priority VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    findings_summary JSONB NOT NULL,
    recommendation JSONB NOT NULL,
    generated_by VARCHAR(50),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Compteur d'enrichissements en attente, utilisé par Discovery/Intelligence
-- pour savoir quand déclencher la corrélation (voir services/intelligence/main.py)
ALTER TABLE scans ADD COLUMN pending_enrichments INTEGER NOT NULL DEFAULT 0;

-- Audit log (append-only)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Append-only au niveau base de données : même un bug applicatif
-- ne peut pas altérer ou supprimer une entrée existante (voir docs/SECURITY.md)
REVOKE UPDATE, DELETE ON audit_log FROM aegis;

-- Clés API du Gateway HTTP
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(100),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- Base locale d'exploits publics (exploit-db), indexée via 'aegis intel update-exploitdb'
CREATE TABLE exploit_db (
    edb_id INTEGER PRIMARY KEY,
    title VARCHAR(500),
    cve_ids TEXT[],
    exploit_type VARCHAR(50),
    platform VARCHAR(50),
    verified BOOLEAN DEFAULT false
);

CREATE INDEX idx_exploit_db_cve_ids ON exploit_db USING GIN (cve_ids);

CREATE TABLE exploit_db_meta (
    id INTEGER PRIMARY KEY,
    last_updated TIMESTAMP WITH TIME ZONE,
    total_entries INTEGER
);
