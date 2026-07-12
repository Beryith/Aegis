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
