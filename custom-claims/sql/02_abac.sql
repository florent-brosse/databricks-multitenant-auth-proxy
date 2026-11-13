-- ABAC variant: one schema-level policy protects every table whose tenant column is tagged.
-- Needs two governed tags (tag policies): tenant_col, salary_col.
-- Policies target only the service principal, so data owners / Genie authors still see everything.

CREATE SCHEMA IF NOT EXISTS main.claims_abac;
CREATE OR REPLACE TABLE main.claims_abac.employees (tenant_id STRING, employee_id INT, full_name STRING, salary INT);
CREATE OR REPLACE TABLE main.claims_abac.absences  (tenant_id STRING, employee_id INT, days INT);
ALTER TABLE main.claims_abac.employees ALTER COLUMN tenant_id SET TAGS ('tenant_col');
ALTER TABLE main.claims_abac.employees ALTER COLUMN salary    SET TAGS ('salary_col');
ALTER TABLE main.claims_abac.absences  ALTER COLUMN tenant_id SET TAGS ('tenant_col');

CREATE OR REPLACE FUNCTION main.claims_abac.tenant_filter(t STRING) RETURNS BOOLEAN
RETURN EXISTS (SELECT 1 FROM main.claims_demo.user_access u
               WHERE u.user_id = current_oauth_custom_identity_claim() AND u.tenant_id = t);

CREATE OR REPLACE FUNCTION main.claims_abac.salary_mask(s INT) RETURNS INT
RETURN CASE WHEN EXISTS (SELECT 1 FROM main.claims_demo.user_access u
                         WHERE u.user_id = current_oauth_custom_identity_claim() AND u.can_see_salary)
            THEN s ELSE NULL END;

CREATE POLICY tenant_rls ON SCHEMA main.claims_abac
ROW FILTER main.claims_abac.tenant_filter TO `<sp-application-id>`
FOR TABLES MATCH COLUMNS has_tag('tenant_col') AS t USING COLUMNS (t);

CREATE POLICY salary_mask ON SCHEMA main.claims_abac
COLUMN MASK main.claims_abac.salary_mask TO `<sp-application-id>`
FOR TABLES MATCH COLUMNS has_tag('salary_col') AS s ON COLUMN s;

-- WARNING: a table WITHOUT the tag is fully visible to the service principal (every tenant).
-- The tag is the security boundary: tag every tenant column, or grant SELECT table by table.
