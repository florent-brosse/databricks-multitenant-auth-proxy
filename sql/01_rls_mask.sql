-- Row filter + column mask driven by the OAuth custom identity claim.
-- Replace main.claims_demo with your catalog.schema.

CREATE SCHEMA IF NOT EXISTS main.claims_demo;

CREATE OR REPLACE TABLE main.claims_demo.hr_employees (
  tenant_id STRING, employee_id INT, full_name STRING, department STRING, salary INT);
INSERT INTO main.claims_demo.hr_employees VALUES
  ('acme', 1, 'Emma Martin', 'Sales', 52000),
  ('acme', 2, 'Lucas Bernard', 'Sales', 48000),
  ('acme', 3, 'Chloe Petit', 'Finance', 61000),
  ('acme', 4, 'Hugo Durand', 'Finance', 58000),
  ('globex', 5, 'Lea Moreau', 'Sales', 50000),
  ('globex', 6, 'Nathan Laurent', 'IT', 65000);

-- Mapping table: end user id (the claim) -> tenant, scope, rights.
-- The service principal gets NO grant on it: filters run with the definer's rights.
CREATE OR REPLACE TABLE main.claims_demo.user_access (
  user_id STRING, tenant_id STRING, department STRING, can_see_salary BOOLEAN);
INSERT INTO main.claims_demo.user_access VALUES
  ('alice@acme.test', 'acme', '*', true),        -- HR admin at acme
  ('bob@acme.test', 'acme', 'Sales', false),     -- Sales manager at acme
  ('carol@globex.test', 'globex', '*', true);    -- HR admin at globex

-- Plain equality only: a NULL claim (token without claim) matches no row.
CREATE OR REPLACE FUNCTION main.claims_demo.rls_claim(t STRING, d STRING)
RETURNS BOOLEAN
RETURN EXISTS (
  SELECT 1 FROM main.claims_demo.user_access u
  WHERE u.user_id = current_oauth_custom_identity_claim()
    AND u.tenant_id = t AND (u.department = '*' OR u.department = d));

CREATE OR REPLACE FUNCTION main.claims_demo.mask_salary(s INT, t STRING)
RETURNS INT
RETURN CASE WHEN EXISTS (
  SELECT 1 FROM main.claims_demo.user_access u
  WHERE u.user_id = current_oauth_custom_identity_claim() AND u.tenant_id = t AND u.can_see_salary)
  THEN s ELSE NULL END;

ALTER TABLE main.claims_demo.hr_employees
  SET ROW FILTER main.claims_demo.rls_claim ON (tenant_id, department);
ALTER TABLE main.claims_demo.hr_employees
  ALTER COLUMN salary SET MASK main.claims_demo.mask_salary USING COLUMNS (tenant_id);

-- Grants for the shared service principal (application id). Nothing on user_access.
-- GRANT USE CATALOG ON CATALOG main TO `<sp-application-id>`;
-- GRANT USE SCHEMA ON SCHEMA main.claims_demo TO `<sp-application-id>`;
-- GRANT SELECT ON TABLE main.claims_demo.hr_employees TO `<sp-application-id>`;
-- + CAN USE on the SQL warehouse, + entitlement databricks-sql-access on the SP.
