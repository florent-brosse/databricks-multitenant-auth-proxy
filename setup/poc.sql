-- ============================================================================
-- PoC SQL fixtures — multi-tenant data + per-user row filter + column mask
-- ============================================================================
--
-- Run this against your Databricks workspace via the SQL editor or the
-- Statement Execution API. The setup script (setup/setup.py) does this
-- for you automatically.
--
-- Placeholders to replace:
--   ${CATALOG}    your workspace default catalog (or any catalog you can
--                  CREATE SCHEMA IN). Example: workspace_default
--
-- ============================================================================

-- ============================================================================
-- TENANT 1: ACME
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ${CATALOG}.acme;

CREATE OR REPLACE TABLE ${CATALOG}.acme.employees (
  employee_id INT, name STRING, email STRING,
  department  STRING, salary DECIMAL(10,2), ssn STRING
);

INSERT INTO ${CATALOG}.acme.employees VALUES
  (1, 'Alice Martin', 'alice.martin@acme.com', 'hr',          90000.00, '123-45-6789'),
  (2, 'Bob Durand',   'bob.durand@acme.com',   'engineering', 85000.00, '234-56-7890'),
  (3, 'Carol Henry',  'carol.henry@acme.com',  'engineering', 92000.00, '345-67-8901'),
  (4, 'Eve Jones',    'eve.jones@acme.com',    'design',      72000.00, '567-89-0123');

CREATE OR REPLACE TABLE ${CATALOG}.acme.user_dept_mapping (
  user_email STRING, allowed_dept STRING
);

INSERT INTO ${CATALOG}.acme.user_dept_mapping VALUES
  ('alice@acme.test', NULL),         -- HR admin, full visibility
  ('bob@acme.test',   'engineering'),
  ('bob@acme.test',   'design');

CREATE OR REPLACE FUNCTION ${CATALOG}.acme.filter_by_user_dept(dept STRING)
RETURNS BOOLEAN
RETURN
  EXISTS (
    SELECT 1 FROM ${CATALOG}.acme.user_dept_mapping
    WHERE user_email = current_user() AND allowed_dept IS NULL
  )
  OR dept IN (
    SELECT allowed_dept FROM ${CATALOG}.acme.user_dept_mapping
    WHERE user_email = current_user()
  );

CREATE OR REPLACE FUNCTION ${CATALOG}.acme.mask_ssn(ssn STRING)
RETURNS STRING
RETURN CASE
  WHEN EXISTS (
    SELECT 1 FROM ${CATALOG}.acme.user_dept_mapping
    WHERE user_email = current_user() AND allowed_dept IS NULL
  ) THEN ssn
  ELSE CONCAT('XXX-XX-', RIGHT(ssn, 4))
END;

ALTER TABLE ${CATALOG}.acme.employees
  SET ROW FILTER ${CATALOG}.acme.filter_by_user_dept ON (department);

ALTER TABLE ${CATALOG}.acme.employees
  ALTER COLUMN ssn SET MASK ${CATALOG}.acme.mask_ssn;

-- GRANTs to Acme users only — this is what enforces cross-tenant isolation.
GRANT USE CATALOG ON CATALOG ${CATALOG} TO `alice@acme.test`;
GRANT USE SCHEMA  ON SCHEMA  ${CATALOG}.acme TO `alice@acme.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.acme.employees TO `alice@acme.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.acme.user_dept_mapping TO `alice@acme.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.acme.filter_by_user_dept TO `alice@acme.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.acme.mask_ssn TO `alice@acme.test`;

GRANT USE CATALOG ON CATALOG ${CATALOG} TO `bob@acme.test`;
GRANT USE SCHEMA  ON SCHEMA  ${CATALOG}.acme TO `bob@acme.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.acme.employees TO `bob@acme.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.acme.user_dept_mapping TO `bob@acme.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.acme.filter_by_user_dept TO `bob@acme.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.acme.mask_ssn TO `bob@acme.test`;

-- ============================================================================
-- TENANT 2: CONTOSO
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ${CATALOG}.contoso;

CREATE OR REPLACE TABLE ${CATALOG}.contoso.employees (
  employee_id INT, name STRING, email STRING,
  department  STRING, salary DECIMAL(10,2), ssn STRING
);

INSERT INTO ${CATALOG}.contoso.employees VALUES
  (101, 'Carol Park', 'carol.park@contoso.com', 'hr',    95000.00, '111-22-3333'),
  (102, 'Dave King',  'dave.king@contoso.com',  'sales', 82000.00, '222-33-4444'),
  (103, 'Edith Liu',  'edith.liu@contoso.com',  'sales', 78000.00, '333-44-5555');

CREATE OR REPLACE TABLE ${CATALOG}.contoso.user_dept_mapping (
  user_email STRING, allowed_dept STRING
);

INSERT INTO ${CATALOG}.contoso.user_dept_mapping VALUES
  ('carol@contoso.test', NULL),
  ('dave@contoso.test',  'sales');

CREATE OR REPLACE FUNCTION ${CATALOG}.contoso.filter_by_user_dept(dept STRING)
RETURNS BOOLEAN
RETURN
  EXISTS (
    SELECT 1 FROM ${CATALOG}.contoso.user_dept_mapping
    WHERE user_email = current_user() AND allowed_dept IS NULL
  )
  OR dept IN (
    SELECT allowed_dept FROM ${CATALOG}.contoso.user_dept_mapping
    WHERE user_email = current_user()
  );

CREATE OR REPLACE FUNCTION ${CATALOG}.contoso.mask_ssn(ssn STRING)
RETURNS STRING
RETURN CASE
  WHEN EXISTS (
    SELECT 1 FROM ${CATALOG}.contoso.user_dept_mapping
    WHERE user_email = current_user() AND allowed_dept IS NULL
  ) THEN ssn
  ELSE CONCAT('XXX-XX-', RIGHT(ssn, 4))
END;

ALTER TABLE ${CATALOG}.contoso.employees
  SET ROW FILTER ${CATALOG}.contoso.filter_by_user_dept ON (department);

ALTER TABLE ${CATALOG}.contoso.employees
  ALTER COLUMN ssn SET MASK ${CATALOG}.contoso.mask_ssn;

GRANT USE CATALOG ON CATALOG ${CATALOG} TO `carol@contoso.test`;
GRANT USE SCHEMA  ON SCHEMA  ${CATALOG}.contoso TO `carol@contoso.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.contoso.employees TO `carol@contoso.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.contoso.user_dept_mapping TO `carol@contoso.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.contoso.filter_by_user_dept TO `carol@contoso.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.contoso.mask_ssn TO `carol@contoso.test`;

GRANT USE CATALOG ON CATALOG ${CATALOG} TO `dave@contoso.test`;
GRANT USE SCHEMA  ON SCHEMA  ${CATALOG}.contoso TO `dave@contoso.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.contoso.employees TO `dave@contoso.test`;
GRANT SELECT      ON TABLE   ${CATALOG}.contoso.user_dept_mapping TO `dave@contoso.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.contoso.filter_by_user_dept TO `dave@contoso.test`;
GRANT EXECUTE     ON FUNCTION ${CATALOG}.contoso.mask_ssn TO `dave@contoso.test`;
