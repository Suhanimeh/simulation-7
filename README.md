Simulation 7: Dynamic SQL Execution and Security (DSL)
1. Overview

This simulation demonstrates dynamic SQL execution in SQL Server, showing both secure and vulnerable approaches.  

Objectives:

- Construct dynamic SQL queries using optional parameters  
- Implement secure dynamic SQL with `sp_executesql`  
- Demonstrate SQL injection vulnerabilities safely  
- Apply basic input validation  
- Log all procedure executions  
- Provide execution summary for analysis  

2. Description of Procedures

Secure Procedure
Name: `Reporting.usp_SecureSalesReport`  

- Uses parameterized dynamic SQL via `sp_executesql`.  
- Optional filters: `@TerritoryName`, `@SalesPersonName`, `@ProductCategory`, `@StartDate`, `@EndDate`.  
- Implements **input validation** to reject unsafe patterns like `--`, `DROP`, and `EXEC`.  
- Logs all executions in `Reporting.ExecutionLog` with status and parameter values.  

Example:
EXEC Reporting.usp_SecureSalesReport 
    @TerritoryName='Northwest', 
    @StartDate='2023-01-01', 
    @EndDate='2023-12-31';
    
Vulnerable Procedure

Name: Reporting.usp_VulnerableSalesReport

-Builds dynamic SQL using string concatenation, inserting parameter values directly.
-Supports the same optional filters.
-Demonstrates SQL injection vulnerability for educational purposes.
-Logs all executions in Reporting.ExecutionLog.

Example:

EXEC Reporting.usp_VulnerableSalesReport @TerritoryName='Northwest';


3. Testing Steps
-Run the full SQL script: SQL/Simulation7_SQLScript.sql in SSMS.
-Execute the secure procedure with different parameter combinations, including nulls.
-Execute the vulnerable procedure with normal input and then with unsafe input to demonstrate SQL injection:
  EXEC Reporting.usp_VulnerableSalesReport @TerritoryName='Northwest';
  EXEC Reporting.usp_VulnerableSalesReport @TerritoryName='Northwest''; DROP TABLE Sales.SalesOrderHeader; --';

Check the execution log table for all procedure runs:
SELECT * FROM Reporting.ExecutionLog;

Check the execution summary view for aggregated counts:
SELECT * FROM Reporting.vw_ExecutionSummary;



5. Expected Results
Secure procedure: Executes correctly for valid inputs, rejects unsafe input, and logs status as Success or Rejected.
Vulnerable procedure: Executes normally for valid input but is susceptible to SQL injection. Unsafe input may alter query results.
Execution log: Captures all runs with procedure name, parameters, status, and timestamp.
Execution summary: Provides totals for successful, failed, and rejected executions.

