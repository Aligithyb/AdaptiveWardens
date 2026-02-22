-- Add realistic corporate files to filesystem
-- Run this AFTER a session is created

-- Corporate directories
INSERT OR IGNORE INTO filesystem (session_id, path, file_type, permissions, owner, group_name, size)
VALUES 
    (:session_id, '/var/www/html', 'directory', '755', 'www-data', 'www-data', 0),
    (:session_id, '/opt/company', 'directory', '755', 'root', 'root', 0),
    (:session_id, '/opt/company/configs', 'directory', '700', 'root', 'root', 0),
    (:session_id, '/opt/company/backups', 'directory', '700', 'root', 'root', 0),
    (:session_id, '/home/admin', 'directory', '755', 'admin', 'admin', 0),
    (:session_id, '/home/deploy', 'directory', '755', 'deploy', 'deploy', 0);

-- Realistic corporate files
INSERT OR IGNORE INTO filesystem (session_id, path, file_type, content, permissions, owner, group_name, size)
VALUES
    -- Database config (honeypot - fake credentials)
    (:session_id, '/opt/company/configs/database.conf', 'file', 
     'DB_HOST=localhost\nDB_NAME=company_prod\nDB_USER=dbadmin\nDB_PASS=P@ssw0rd123!\nDB_PORT=5432',
     '600', 'root', 'root', 95),
    
    -- API keys (fake but realistic)
    (:session_id, '/opt/company/configs/api_keys.txt', 'file',
     'STRIPE_KEY=sk_live_51HxY8zKjH...\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
     '600', 'root', 'root', 156),
    
    -- Customer data (fake PII)
    (:session_id, '/opt/company/backups/customers.csv', 'file',
     'id,name,email,phone\n1,John Smith,john.smith@email.com,555-0123\n2,Jane Doe,jane.doe@email.com,555-0124',
     '600', 'root', 'root', 142),
    
    -- Web application
    (:session_id, '/var/www/html/index.php', 'file',
     '<?php\n// Company Portal v2.1\nrequire_once("config.php");\n?>',
     '644', 'www-data', 'www-data', 67),
    
    -- SSH keys
    (:session_id, '/root/.ssh/authorized_keys', 'file',
     'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... root@backup-server',
     '600', 'root', 'root', 394),
    
    -- Bash history with suspicious activity
    (:session_id, '/root/.bash_history', 'file',
     'ls\ncd /opt/company\ncat configs/database.conf\nwget http://updates.internal.com/patch.sh\nchmod +x patch.sh\n./patch.sh',
     '600', 'root', 'root', 145);
