-- views for tableau
-- tableau public can't read sqlite so these get exported to csv from DB Browser

DROP VIEW IF EXISTS tableau_kev;
CREATE VIEW tableau_kev AS
SELECT
    k.cve_id,
    k.vendor,
    k.product,
    COALESCE(g.vendor_group, 'Other (under 5 entries)') AS vendor_group,
    k.vuln_name,
    k.date_added,
    k.due_date,
    k.year_added,
    k.cve_year,
    k.cve_age_years,
    k.fix_window_days,
    k.ransomware_flag,
    k.launch_batch
FROM kev k
LEFT JOIN vendor_group g ON g.vendor = k.vendor;


-- cwe names from cwe.mitre.org, top 10 only
DROP TABLE IF EXISTS cwe_name;
CREATE TABLE cwe_name (cwe TEXT PRIMARY KEY, cwe_name TEXT);
INSERT INTO cwe_name VALUES
('CWE-20', 'Improper input validation'),
('CWE-78', 'OS command injection'),
('CWE-787', 'Out-of-bounds write'),
('CWE-416', 'Use after free'),
('CWE-119', 'Memory buffer overflow'),
('CWE-22', 'Path traversal'),
('CWE-94', 'Code injection'),
('CWE-502', 'Deserialization of untrusted data'),
('CWE-287', 'Improper authentication'),
('CWE-306', 'Missing authentication');

DROP VIEW IF EXISTS tableau_cwe;
CREATE VIEW tableau_cwe AS
SELECT
    c.cve_id,
    c.cwe,
    COALESCE(n.cwe_name, 'Other') AS cwe_name,
    k.vendor,
    k.year_added,
    k.ransomware_flag
FROM kev_cwe c
JOIN kev k ON k.cve_id = c.cve_id
LEFT JOIN cwe_name n ON n.cwe = c.cwe;
