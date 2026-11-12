-- analysis queries, run 01_clean.sql first


-- 1. top 10 vendors and how much of the catalog they cover
WITH v AS (
    SELECT vendor, COUNT(*) AS kev_count
    FROM kev
    GROUP BY vendor
)
SELECT
    RANK() OVER (ORDER BY kev_count DESC) AS rnk,
    vendor,
    kev_count,
    ROUND(100.0 * kev_count / SUM(kev_count) OVER (), 1) AS pct_of_catalog,
    ROUND(100.0 * SUM(kev_count) OVER (ORDER BY kev_count DESC, vendor) / SUM(kev_count) OVER (), 1) AS running_pct
FROM v
ORDER BY kev_count DESC, vendor
LIMIT 10;


-- 2. ransomware share by vendor
-- min 10 entries, otherwise vendors with 1 or 2 rows show up at 100%
SELECT
    vendor,
    COUNT(*) AS kev_count,
    SUM(ransomware_flag) AS ransomware_count,
    ROUND(100.0 * SUM(ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev
GROUP BY vendor
HAVING COUNT(*) >= 10
ORDER BY ransomware_pct DESC, kev_count DESC;


-- 3. same thing by vendor group
SELECT
    COALESCE(g.vendor_group, 'Other (under 5 entries)') AS vendor_group,
    COUNT(DISTINCT k.vendor) AS vendors,
    COUNT(*) AS kev_count,
    SUM(k.ransomware_flag) AS ransomware_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev k
LEFT JOIN vendor_group g ON g.vendor = k.vendor
GROUP BY 1
ORDER BY ransomware_pct DESC;


-- 4. added per year
-- 2021/2022 are mostly backlog so compare from 2023. 2026 is through Nov 10
SELECT
    year_added,
    COUNT(*) AS added,
    SUM(launch_batch) AS from_launch_batch,
    COUNT(DISTINCT vendor) AS vendors_hit,
    COUNT(*) - LAG(COUNT(*)) OVER (ORDER BY year_added) AS change_vs_prior_year
FROM kev
GROUP BY year_added
ORDER BY year_added;


-- 5. how old is the CVE when it gets listed (launch batch left out)
SELECT
    CASE
        WHEN cve_age_years = 0 THEN '1. Same year'
        WHEN cve_age_years = 1 THEN '2. 1 year old'
        WHEN cve_age_years BETWEEN 2 AND 4 THEN '3. 2-4 years old'
        ELSE '4. 5+ years old'
    END AS age_bucket,
    COUNT(*) AS kev_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM kev
WHERE launch_batch = 0
GROUP BY 1
ORDER BY 1;

-- 5b. just 2023 onward
SELECT
    ROUND(100.0 * SUM(CASE WHEN cve_age_years >= 2 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_2yrs_or_older,
    ROUND(100.0 * SUM(CASE WHEN cve_age_years >= 5 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_5yrs_or_older,
    COUNT(*) AS total
FROM kev
WHERE year_added >= 2023;


-- 6. days given to fix, by year
SELECT
    year_added,
    COUNT(*) AS added,
    SUM(CASE WHEN fix_window_days <= 7 THEN 1 ELSE 0 END) AS due_within_7_days,
    SUM(CASE WHEN fix_window_days BETWEEN 8 AND 21 THEN 1 ELSE 0 END) AS due_8_to_21_days,
    SUM(CASE WHEN fix_window_days > 21 THEN 1 ELSE 0 END) AS due_over_21_days,
    ROUND(100.0 * SUM(CASE WHEN fix_window_days <= 7 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_within_7_days
FROM kev
GROUP BY year_added
ORDER BY year_added;


-- 7. top weakness types (a cve with 2 cwes counts under both)
SELECT
    c.cwe,
    COUNT(*) AS kev_count,
    SUM(k.ransomware_flag) AS ransomware_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev_cwe c
JOIN kev k ON k.cve_id = c.cve_id
GROUP BY c.cwe
ORDER BY kev_count DESC
LIMIT 10;


-- 8. products that keep coming back (entries in 4+ different years)
-- dropping the "Multiple Products" rows
SELECT
    vendor,
    product,
    COUNT(*) AS kev_count,
    COUNT(DISTINCT year_added) AS years_with_additions,
    SUM(ransomware_flag) AS ransomware_count,
    MAX(date_added) AS most_recent
FROM kev
WHERE product NOT LIKE 'Multiple%'
GROUP BY vendor, product
HAVING COUNT(DISTINCT year_added) >= 4
ORDER BY kev_count DESC
LIMIT 15;


-- 9. watchlist: 10+ entries, 25%+ ransomware, and something new in the last 12 months
SELECT
    k.vendor,
    COALESCE(g.vendor_group, 'Other') AS vendor_group,
    COUNT(*) AS kev_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct,
    SUM(CASE WHEN k.date_added >= '2025-11-10' THEN 1 ELSE 0 END) AS added_last_12_months
FROM kev k
LEFT JOIN vendor_group g ON g.vendor = k.vendor
GROUP BY k.vendor
HAVING COUNT(*) >= 10
    AND 100.0 * SUM(k.ransomware_flag) / COUNT(*) >= 25
    AND SUM(CASE WHEN k.date_added >= '2025-11-10' THEN 1 ELSE 0 END) >= 1
ORDER BY ransomware_pct DESC;
