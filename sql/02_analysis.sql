-- 02_analysis.sql
-- Run 01_clean.sql first.


-- Q1. How concentrated is the catalog? Top 10 vendors and running share.
WITH v AS (
    SELECT vendor, COUNT(*) AS kev_count
    FROM kev
    GROUP BY vendor
)
SELECT
    RANK() OVER (ORDER BY kev_count DESC)                         AS rnk,
    vendor,
    kev_count,
    ROUND(100.0 * kev_count / SUM(kev_count) OVER (), 1)          AS pct_of_catalog,
    ROUND(100.0 * SUM(kev_count) OVER (ORDER BY kev_count DESC, vendor)
          / SUM(kev_count) OVER (), 1)                            AS running_pct
FROM v
ORDER BY kev_count DESC, vendor
LIMIT 10;


-- Q2. Volume vs ransomware. Count alone makes Microsoft look like the whole
-- problem, so this ranks by the share of each vendor's entries that have
-- known ransomware use. Minimum 10 entries so tiny vendors don't hit 100%.
SELECT
    vendor,
    COUNT(*)                                        AS kev_count,
    SUM(ransomware_flag)                            AS ransomware_count,
    ROUND(100.0 * SUM(ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev
GROUP BY vendor
HAVING COUNT(*) >= 10
ORDER BY ransomware_pct DESC, kev_count DESC;


-- Q3. Same question by vendor group.
SELECT
    COALESCE(g.vendor_group, 'Other (under 5 entries)') AS vendor_group,
    COUNT(DISTINCT k.vendor)                        AS vendors,
    COUNT(*)                                        AS kev_count,
    SUM(k.ransomware_flag)                          AS ransomware_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev k
LEFT JOIN vendor_group g ON g.vendor = k.vendor
GROUP BY 1
ORDER BY ransomware_pct DESC;


-- Q4. Additions per year. 2021 and 2022 are inflated by the backlog CISA
-- loaded when the catalog started, so 2023 onward is the fair comparison.
-- 2026 is year to date (through Nov 10).
SELECT
    year_added,
    COUNT(*)                                        AS added,
    SUM(launch_batch)                               AS from_launch_batch,
    COUNT(DISTINCT vendor)                          AS vendors_hit,
    COUNT(*) - LAG(COUNT(*)) OVER (ORDER BY year_added) AS change_vs_prior_year
FROM kev
GROUP BY year_added
ORDER BY year_added;


-- Q5. How old are these vulnerabilities when they get listed?
-- Leaves out the launch batch because that was a catch-up load.
SELECT
    CASE
        WHEN cve_age_years = 0 THEN '1. Same year'
        WHEN cve_age_years = 1 THEN '2. 1 year old'
        WHEN cve_age_years BETWEEN 2 AND 4 THEN '3. 2-4 years old'
        ELSE '4. 5+ years old'
    END                                             AS age_bucket,
    COUNT(*)                                        AS kev_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM kev
WHERE launch_batch = 0
GROUP BY 1
ORDER BY 1;

-- Q5b. Same thing but only what was added 2023 onward
SELECT
    ROUND(100.0 * SUM(CASE WHEN cve_age_years >= 2 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_2yrs_or_older,
    ROUND(100.0 * SUM(CASE WHEN cve_age_years >= 5 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_5yrs_or_older,
    COUNT(*) AS total
FROM kev
WHERE year_added >= 2023;


-- Q6. Fix window by year. How many days agencies get between listing and due date.
SELECT
    year_added,
    COUNT(*)                                                            AS added,
    SUM(CASE WHEN fix_window_days <= 7 THEN 1 ELSE 0 END)               AS due_within_7_days,
    SUM(CASE WHEN fix_window_days BETWEEN 8 AND 21 THEN 1 ELSE 0 END)   AS due_8_to_21_days,
    SUM(CASE WHEN fix_window_days > 21 THEN 1 ELSE 0 END)               AS due_over_21_days,
    ROUND(100.0 * SUM(CASE WHEN fix_window_days <= 7 THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_within_7_days
FROM kev
GROUP BY year_added
ORDER BY year_added;


-- Q7. Most common weakness types. A CVE with two CWEs counts under both.
SELECT
    c.cwe,
    COUNT(*)                                        AS kev_count,
    SUM(k.ransomware_flag)                          AS ransomware_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct
FROM kev_cwe c
JOIN kev k ON k.cve_id = c.cve_id
GROUP BY c.cwe
ORDER BY kev_count DESC
LIMIT 10;


-- Q8. Repeat offenders: products with entries in 4 or more different years.
-- "Multiple Products" style rows are dropped since they aren't one product.
SELECT
    vendor,
    product,
    COUNT(*)                                        AS kev_count,
    COUNT(DISTINCT year_added)                      AS years_with_additions,
    SUM(ransomware_flag)                            AS ransomware_count,
    MAX(date_added)                                 AS most_recent
FROM kev
WHERE product NOT LIKE 'Multiple%'
GROUP BY vendor, product
HAVING COUNT(DISTINCT year_added) >= 4
ORDER BY kev_count DESC
LIMIT 15;


-- Q9. Watchlist. Vendors where a meaningful share of entries is ransomware
-- linked AND they are still getting new entries. This is the list I would
-- want in front of me before a vendor review.
SELECT
    k.vendor,
    COALESCE(g.vendor_group, 'Other')               AS vendor_group,
    COUNT(*)                                        AS kev_count,
    ROUND(100.0 * SUM(k.ransomware_flag) / COUNT(*), 1) AS ransomware_pct,
    SUM(CASE WHEN k.date_added >= '2025-11-10' THEN 1 ELSE 0 END) AS added_last_12_months
FROM kev k
LEFT JOIN vendor_group g ON g.vendor = k.vendor
GROUP BY k.vendor
HAVING COUNT(*) >= 10
   AND 100.0 * SUM(k.ransomware_flag) / COUNT(*) >= 25
   AND SUM(CASE WHEN k.date_added >= '2025-11-10' THEN 1 ELSE 0 END) >= 1
ORDER BY ransomware_pct DESC;
