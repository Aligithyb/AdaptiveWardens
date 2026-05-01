-- NexoPay Inc. — Additional deception data
-- Supplements the filesystem seeded by database.py.
-- Run AFTER a session is created (session_id must be substituted).

-- Extra directories for a realistic fintech layout
INSERT OR IGNORE INTO filesystem (session_id, path, file_type, permissions, owner, group_name, size)
VALUES
    (:session_id, '/opt/nexopay/migrations',          'directory', '755', 'root',    'nexopay', 0),
    (:session_id, '/opt/nexopay/certs',               'directory', '700', 'root',    'nexopay', 0),
    (:session_id, '/var/lib/postgresql',              'directory', '755', 'postgres','postgres', 0),
    (:session_id, '/var/lib/postgresql/14',           'directory', '755', 'postgres','postgres', 0),
    (:session_id, '/var/lib/postgresql/14/main',      'directory', '700', 'postgres','postgres', 0),
    (:session_id, '/etc/nginx/sites-enabled',         'directory', '755', 'root',    'root',    0),
    (:session_id, '/etc/cron.daily',                  'directory', '755', 'root',    'root',    0);

-- Additional honeytoken and deception files
INSERT OR IGNORE INTO filesystem (session_id, path, file_type, content, permissions, owner, group_name, size)
VALUES
    -- SSL private key for the API TLS cert (honeytoken)
    (:session_id, '/opt/nexopay/certs/nexopay.key', 'file',
     '-----BEGIN EC PRIVATE KEY-----' || char(10) ||
     'MHQCAQEEIOvB5LCTGBqFnXnO4HJQZ+sFake3xNp4ySSL2025ABCDEFGHIJKLaoe' || char(10) ||
     'gBcEFQQkBCGAIADo5c3xNp4ySSLKEY3x8yZ1mNxOpay2025ProductionCertKey' || char(10) ||
     '-----END EC PRIVATE KEY-----' || char(10),
     '600', 'root', 'nexopay', 128),

    -- Nginx site config referencing the app
    (:session_id, '/etc/nginx/sites-enabled/nexopay-api.conf', 'file',
     'server {' || char(10) ||
     '    listen 443 ssl http2;' || char(10) ||
     '    server_name api.nexopay.io;' || char(10) ||
     '    ssl_certificate     /opt/nexopay/certs/nexopay.crt;' || char(10) ||
     '    ssl_certificate_key /opt/nexopay/certs/nexopay.key;' || char(10) ||
     '    location / {' || char(10) ||
     '        proxy_pass http://127.0.0.1:3000;' || char(10) ||
     '        proxy_set_header Host $host;' || char(10) ||
     '        proxy_set_header X-Real-IP $remote_addr;' || char(10) ||
     '    }' || char(10) ||
     '}' || char(10),
     '644', 'root', 'root', 256),

    -- Daily cron job for DB backup
    (:session_id, '/etc/cron.daily/nexopay-backup', 'file',
     '#!/bin/bash' || char(10) ||
     'source /opt/nexopay/config/database.env' || char(10) ||
     'source /opt/nexopay/config/aws.env' || char(10) ||
     'FNAME="/var/backups/nexopay_db_$(date +%F).sql"' || char(10) ||
     'pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > $FNAME' || char(10) ||
     'aws s3 cp $FNAME s3://$S3_BUCKET_BACKUPS/daily/ --sse aws:kms' || char(10) ||
     'find /var/backups -name "nexopay_db_*.sql" -mtime +7 -delete' || char(10),
     '755', 'root', 'root', 256),

    -- Last migration SQL file
    (:session_id, '/opt/nexopay/migrations/latest.sql', 'file',
     '-- Migration: add_idempotency_key_to_transactions' || char(10) ||
     '-- Applied: 2026-04-15' || char(10) ||
     'ALTER TABLE transactions ADD COLUMN IF NOT EXISTS idempotency_key varchar(64) UNIQUE;' || char(10) ||
     'CREATE INDEX IF NOT EXISTS idx_txn_idempotency ON transactions(idempotency_key);' || char(10) ||
     'ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS rate_limit_tier varchar(20) DEFAULT ''standard'';' || char(10),
     '644', 'root', 'nexopay', 256),

    -- Fake customer CSV export (PII bait)
    (:session_id, '/var/backups/customers_export_2026-04-01.csv', 'file',
     'id,email,stripe_customer_id,kyc_status,country,created_at' || char(10) ||
     'u_01HX4KP2QRSTUV,james.hartley@gmail.com,cus_NxP3x4yA1b2c3,verified,US,2025-11-12' || char(10) ||
     'u_01HX4KP2WXYZAB,sarah.chen@techcorp.io,cus_NxP5x6yB2c3d4,verified,US,2025-11-15' || char(10) ||
     'u_01HX4KP3CDEFGH,michael.torres@enterprise.com,cus_NxP7x8yC3d4e5,verified,CA,2025-11-18' || char(10) ||
     'u_01HX4KP3IJKLMN,emily.watson@startup.ai,cus_NxP9x0yD4e5f6,pending,GB,2025-12-01' || char(10) ||
     'u_01HX4KP3OPQRST,david.kim@fintech.co,cus_NxPax1yE5f6g7,verified,KR,2025-12-10' || char(10),
     '640', 'root', 'root', 512),

    -- .env file in a hypothetical deploy workspace
    (:session_id, '/home/deploy/.env', 'file',
     'NODE_ENV=production' || char(10) ||
     'API_PORT=3000' || char(10) ||
     'DB_HOST=db-primary.nexopay.internal' || char(10) ||
     'DB_PASSWORD=Nx!Pr0d_Pg_P@ss_2025_Secure' || char(10) ||
     'REDIS_URL=redis://:r3d1s_nxp_2025_pr0d@cache-01.nexopay.internal:6379/0' || char(10) ||
     'JWT_SECRET=nxp-jwt-pr0d-s3cr3t-2025-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' || char(10),
     '600', 'deploy', 'deploy', 256);
