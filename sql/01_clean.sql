-- 01_clean.sql
-- Source: CISA Known Exploited Vulnerabilities catalog, loaded as-is into kev_raw
-- (DB Browser for SQLite > File > Import > Table from CSV)
-- Pulled 2026-11-10, 1,779 rows.

-- Things I found while profiling the raw file:
--   * 19 rows have leading/trailing spaces in vendor or product ("SimpleHelp " etc)
--   * 175 rows have no CWE listed
--   * 114 rows have more than one CWE in the same cell, comma separated
--   * 287 rows were all added on 2021-11-03, the day the catalog launched.
--     That's a backlog load, not 287 new exploits in one day, so I flag it.

DROP TABLE IF EXISTS kev;

CREATE TABLE kev AS
SELECT
    cve_id,
    TRIM(vendor)                                   AS vendor,
    TRIM(product)                                  AS product,
    vuln_name,
    date_added,
    due_date,
    CAST(SUBSTR(date_added, 1, 4) AS INTEGER)      AS year_added,
    CAST(SUBSTR(cve_id, 5, 4) AS INTEGER)          AS cve_year,
    -- how old the CVE already was when CISA confirmed exploitation
    CAST(SUBSTR(date_added, 1, 4) AS INTEGER)
      - CAST(SUBSTR(cve_id, 5, 4) AS INTEGER)      AS cve_age_years,
    -- days federal agencies were given to fix it
    CAST(JULIANDAY(due_date) - JULIANDAY(date_added) AS INTEGER) AS fix_window_days,
    CASE WHEN ransomware_use = 'Known' THEN 1 ELSE 0 END         AS ransomware_flag,
    CASE WHEN date_added = '2021-11-03' THEN 1 ELSE 0 END        AS launch_batch,
    NULLIF(TRIM(cwes), '')                         AS cwes
FROM kev_raw;


-- Vendor grouping. The catalog has no category field so I built this by hand
-- for every vendor with 5+ entries (53 vendors, 78% of the catalog).
-- It's at vendor level, which is rough: Microsoft sells Exchange as well as
-- Windows, for example. Good enough to compare broad groups, not more than that.

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


-- One row per CVE per CWE, so weakness types can be counted properly.
-- SQLite has no STRING_SPLIT so this walks the comma list with a recursive CTE.

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
SELECT cve_id, cwe
FROM split
WHERE cwe <> '';


-- sanity checks
SELECT COUNT(*) AS kev_rows, COUNT(DISTINCT cve_id) AS distinct_cves FROM kev;   -- should match
SELECT COUNT(*) AS still_untrimmed FROM kev WHERE vendor <> TRIM(vendor);        -- should be 0
SELECT COUNT(*) AS grouped_rows FROM kev k JOIN vendor_group g ON g.vendor = k.vendor;
SELECT COUNT(*) AS cwe_rows, COUNT(DISTINCT cve_id) AS cves_with_cwe FROM kev_cwe;
