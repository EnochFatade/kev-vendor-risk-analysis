# Which vendors keep showing up in CISA's exploited vulnerabilities list?

When I assess a vendor, most of what I look at is what the vendor tells me: SOC reports, pen test summaries, questionnaires. I wanted something from outside that process. CISA publishes a catalog of vulnerabilities that are confirmed to be exploited in real attacks (the KEV catalog), and every entry names the vendor and product. So I pulled it into SQL to see what it says about vendors.

**Dashboard:** [add Tableau Public link]

## Data

- Source: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), CSV from [cisagov/kev-data](https://github.com/cisagov/kev-data)
- Pulled November 10, 2026
- 1,779 vulnerabilities, 294 vendors, entries added from November 2021 to November 2026

## Tools

SQLite (DB Browser for SQLite) for cleaning and analysis, Tableau Public for the dashboard.

## What I found

**1. Ten vendors make up over half the catalog.** 294 vendors are listed, but the top 10 account for 52.8% of entries. Microsoft alone is 22% (391 entries).

**2. The vendors with the most entries are not the ones with the worst ransomware numbers.** CISA marks whether each vulnerability is known to be used in ransomware campaigns. Across the catalog that is 20.3%. For vendors with at least 10 entries:

| Vendor | Entries | Known ransomware use |
|---|---|---|
| QNAP | 11 | 81.8% |
| SonicWall | 20 | 65.0% |
| Atlassian | 14 | 57.1% |
| Fortinet | 32 | 43.8% |
| Palo Alto Networks | 16 | 37.5% |
| Microsoft | 391 | 29.9% |
| Cisco | 103 | 6.8% |
| Apple + Google | 173 | 0% |

Cisco is second by count and near the bottom on this measure. Apple and Google have 173 entries between them and none flagged for ransomware. If you ranked vendors by count alone you would get a very different list.

**3. My vendor grouping idea only half worked.** I expected network and security appliance vendors to stand out as a group. They came in at 24.6%, about the same as enterprise apps (25.5%), with OS/browser/endpoint vendors at 17.8%. The group average hides a big spread: SonicWall and Fortinet are high, Cisco and D-Link are low. The vendor matters more than the category.

**4. Fix deadlines got a lot shorter in 2026.** Each entry has a due date for federal agencies. From 2023 through 2025 nearly everything was due in 21 days, and under 8% of entries each year were due within a week. In 2026 so far, 54.2% are due within 7 days (157 of 295 are due in 3).

**5. Old vulnerabilities keep getting added.** Of the 913 entries added since 2023, 20.9% were for CVEs at least 2 years old and 10.4% were at least 5 years old.

**6. The weakness type matters.** Memory bugs (out-of-bounds write, use after free, buffer overflow) are common but only 12.1% are ransomware linked. Deserialization flaws are 40.8% and path traversal is 32.9%.

**7. 2026 is already the busiest year since the backlog was loaded.** 295 additions through November 10, compared to 245 in all of 2025 and 186 in 2024.

## How I'd use this in vendor risk work

- Check a vendor's products against the catalog during due diligence, and look at the ransomware share, not just the count.
- For any vendor running products from the watchlist (query 9), ask for their patch SLA for KEV-listed vulnerabilities specifically. With 3 day deadlines becoming common, a 30 day critical patch SLA is out of step.
- Ask about end-of-life software. A fifth of recent additions are for CVEs two or more years old.

## Limitations

- The catalog only covers vulnerabilities CISA has confirmed as exploited. It is not a measure of how secure a vendor is overall, and big vendors have more entries partly because they have more products and more users.
- "Unknown" ransomware use means not known, not no.
- 287 entries were loaded on the day the catalog launched and 2022 includes a lot of backlog too, so I don't treat 2021 and 2022 as real yearly counts.
- The vendor groups are my own, assigned at vendor level for the 53 vendors with 5 or more entries. 175 entries have no CWE listed.
- The data has no patch dates, so this says nothing about how fast vendors actually patch.

## Files

```
data/known_exploited_vulnerabilities.csv   raw file from CISA
sql/01_clean.sql                           cleaning, vendor groups, CWE split
sql/02_analysis.sql                        the nine queries behind the findings
sql/03_tableau_views.sql                   flat views exported for Tableau
tableau/kev_clean.csv                      one row per vulnerability
tableau/kev_cwe.csv                        one row per vulnerability per CWE
```

To rerun: import the raw CSV into SQLite as `kev_raw` with columns renamed to `cve_id, vendor, product, vuln_name, date_added, short_description, required_action, due_date, ransomware_use, forensic_triage, notes, cwes`, then run the three SQL files in order.
