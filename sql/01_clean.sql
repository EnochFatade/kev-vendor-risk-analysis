-- clean up the raw KEV import (kev_raw) and build the tables used later
-- raw file is CISA's known_exploited_vulnerabilities.csv, 1,779 rows

-- notes from looking through the raw data:
-- some vendor/product values have stray spaces ("SimpleHelp ")
-- 175 rows have no cwe, 114 have more than one in the same cell
-- 287 rows were all added 2021-11-03 (catalog launch), flagging those

DROP TABLE IF EXISTS kev;

CREATE TABLE kev AS
SELECT
    cve_id,
    TRIM(vendor) AS vendor,
    TRIM(product) AS product,
    vuln_name,
    date_added,
    due_date,
    CAST(SUBSTR(date_added, 1, 4) AS INTEGER) AS year_added,
    CAST(SUBSTR(cve_id, 5, 4) AS INTEGER) AS cve_year,
    -- age of the CVE when it got listed
    CAST(SUBSTR(date_added, 1, 4) AS INTEGER) - CAST(SUBSTR(cve_id, 5, 4) AS INTEGER) AS cve_age_years,
    CAST(JULIANDAY(due_date) - JULIANDAY(date_added) AS INTEGER) AS fix_window_days,
    CASE WHEN ransomware_use = 'Known' THEN 1 ELSE 0 END AS ransomware_flag,
    CASE WHEN date_added = '2021-11-03' THEN 1 ELSE 0 END AS launch_batch,
    NULLIF(TRIM(cwes), '') AS cwes
FROM kev_raw;


-- vendor groups
-- no category column in the catalog so I assigned these myself,
-- only for vendors with 5 or more entries (53 vendors, about 78% of rows)
-- vendor level only, so Microsoft is all "OS" even though Exchange is in there

DROP TABLE IF EXISTS vendor_group;
CREATE TABLE vendor_group (vendor TEXT PRIMARY KEY, vendor_group TEXT);

INSERT INTO vendor_group VALUES
('Cisco','Network & security appliances'),
('Ivanti','Network & security appliances'),
('Fortinet','Network & security appliances'),
('Citrix','Network & security appliances'),
('SonicWall','Network & security appliances'),
('Palo Alto Networks','Network & security appliances'),
('Zyxel','Network & security appliances'),
('D-Link','Network & security appliances'),
('Juniper','Network & security appliances'),
('F5','Network & security appliances'),
('NETGEAR','Network & security appliances'),
('Sophos','Network & security appliances'),
('TP-Link','Network & security appliances'),
('MikroTik','Network & security appliances'),
('DrayTek','Network & security appliances'),
('Check Point','Network & security appliances'),
('QNAP','Network & security appliances'),
('Mitel','Network & security appliances'),
('Microsoft','OS, browser & endpoint'),
('Apple','OS, browser & endpoint'),
('Google','OS, browser & endpoint'),
('Linux','OS, browser & endpoint'),
('Android','OS, browser & endpoint'),
('Samsung','OS, browser & endpoint'),
('Mozilla','OS, browser & endpoint'),
('Adobe','OS, browser & endpoint'),
('Qualcomm','OS, browser & endpoint'),
('Arm','OS, browser & endpoint'),
('RARLAB','OS, browser & endpoint'),
('GNU','OS, browser & endpoint'),
('Red Hat','OS, browser & endpoint'),
('Trend Micro','OS, browser & endpoint'),
('Plex','OS, browser & endpoint'),
('Oracle','Enterprise apps & servers'),
('Apache','Enterprise apps & servers'),
('VMware','Enterprise apps & servers'),
('Synacor','Enterprise apps & servers'),
('SAP','Enterprise apps & servers'),
('Atlassian','Enterprise apps & servers'),
('SolarWinds','Enterprise apps & servers'),
('Roundcube','Enterprise apps & servers'),
('Zoho','Enterprise apps & servers'),
('Progress','Enterprise apps & servers'),
('IBM','Enterprise apps & servers'),
('WordPress','Enterprise apps & servers'),
('Jenkins','Enterprise apps & servers'),
('GitLab','Enterprise apps & servers'),
('Broadcom','Enterprise apps & servers'),
('PaperCut','Enterprise apps & servers'),
('N-able','Enterprise apps & servers'),
('Langflow','Enterprise apps & servers'),
('Exim','Enterprise apps & servers'),
('Drupal','Enterprise apps & servers');


-- split the cwes column so there is one row per cve + cwe
-- sqlite doesn't have a split function, so recursive cte

DROP TABLE IF EXISTS kev_cwe;

CREATE TABLE kev_cwe AS
WITH RECURSIVE split(cve_id, cwe, rest) AS (
    SELECT cve_id, '', cwes || ','
    FROM kev
    WHERE cwes IS NOT NULL
    UNION ALL
    SELECT cve_id,
        TRIM(SUBSTR(rest, 1, INSTR(rest, ',') - 1)),
        SUBSTR(rest, INSTR(rest, ',') + 1)
    FROM split
    WHERE rest <> ''
)
SELECT cve_id, cwe FROM split WHERE cwe <> '';


-- checks
SELECT COUNT(*), COUNT(DISTINCT cve_id) FROM kev;  -- 1779 / 1779
SELECT COUNT(*) FROM kev WHERE vendor <> TRIM(vendor);  -- 0
SELECT COUNT(*) FROM kev k JOIN vendor_group g ON g.vendor = k.vendor;  -- 1385
SELECT COUNT(*), COUNT(DISTINCT cve_id) FROM kev_cwe;  -- 1735 / 1604
