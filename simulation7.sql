USE AdventureWorks2025;
GO

IF OBJECT_ID('Reporting.usp_SecureSalesReport', 'P') IS NOT NULL
    DROP PROCEDURE Reporting.usp_SecureSalesReport;
GO

IF OBJECT_ID('Reporting.usp_VulnerableSalesReport', 'P') IS NOT NULL
    DROP PROCEDURE Reporting.usp_VulnerableSalesReport;
GO

IF OBJECT_ID('Reporting.vw_ExecutionSummary', 'V') IS NOT NULL
    DROP VIEW Reporting.vw_ExecutionSummary;
GO

IF OBJECT_ID('Reporting.ExecutionLog', 'U') IS NOT NULL
    DROP TABLE Reporting.ExecutionLog;
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'Reporting')
BEGIN
    EXEC('CREATE SCHEMA Reporting');
END
GO

-- 1? Create ExecutionLog table
CREATE TABLE Reporting.ExecutionLog (
    LogID INT IDENTITY(1,1) PRIMARY KEY,
    ProcedureName NVARCHAR(128),
    ExecutionStatus NVARCHAR(50),
    ParameterValues NVARCHAR(MAX),
    ExecutionTime DATETIME DEFAULT GETDATE()
);
GO


-- 2? Secure Dynamic SQL Procedure
CREATE PROCEDURE Reporting.usp_SecureSalesReport
    @TerritoryName NVARCHAR(50) = NULL,
    @SalesPersonName NVARCHAR(50) = NULL,
    @ProductCategory NVARCHAR(50) = NULL,
    @StartDate DATE = NULL,
    @EndDate DATE = NULL
AS
BEGIN
    SET NOCOUNT ON;


    IF (@TerritoryName LIKE '%--%' OR @TerritoryName LIKE '%DROP%' OR @TerritoryName LIKE '%EXEC%')
       OR (@SalesPersonName LIKE '%--%' OR @SalesPersonName LIKE '%DROP%' OR @SalesPersonName LIKE '%EXEC%')
       OR (@ProductCategory LIKE '%--%' OR @ProductCategory LIKE '%DROP%' OR @ProductCategory LIKE '%EXEC%')
    BEGIN
        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_SecureSalesReport',
            'Rejected',
            CONCAT(
                'Territory: ', ISNULL(@TerritoryName,''), 
                ', SalesPerson: ', ISNULL(@SalesPersonName,''), 
                ', Category: ', ISNULL(@ProductCategory,'')
            )
        );
        RAISERROR('Unsafe input detected. Execution rejected.', 16, 1);
        RETURN;
    END


    IF (@StartDate IS NOT NULL AND @EndDate IS NOT NULL AND @StartDate > @EndDate)
    BEGIN
        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_SecureSalesReport',
            'Rejected',
            CONCAT('StartDate: ', CONVERT(NVARCHAR, @StartDate, 23), ', EndDate: ', CONVERT(NVARCHAR, @EndDate, 23))
        );
        RAISERROR('Invalid date range. Execution rejected.', 16, 1);
        RETURN;
    END

    DECLARE @SQL NVARCHAR(MAX) = N'
        SELECT 
            t.Name AS TerritoryName,
            CONCAT(p.FirstName, '' '', p.LastName) AS SalesPersonName,
            pc.Name AS ProductCategory,
            soh.OrderDate,
            sod.LineTotal AS TotalSalesAmount,
            sod.OrderQty AS OrderQuantity
        FROM Sales.SalesOrderHeader soh
        JOIN Sales.SalesOrderDetail sod ON soh.SalesOrderID = sod.SalesOrderID
        JOIN Sales.SalesPerson sp ON soh.SalesPersonID = sp.BusinessEntityID
        JOIN HumanResources.Employee e ON sp.BusinessEntityID = e.BusinessEntityID
        JOIN Person.Person p ON e.BusinessEntityID = p.BusinessEntityID
        JOIN Sales.SalesTerritory t ON soh.TerritoryID = t.TerritoryID
        JOIN Production.Product prod ON sod.ProductID = prod.ProductID
        JOIN Production.ProductSubcategory ps ON prod.ProductSubcategoryID = ps.ProductSubcategoryID
        JOIN Production.ProductCategory pc ON ps.ProductCategoryID = pc.ProductCategoryID
        WHERE 1=1
    ';

    DECLARE @Params NVARCHAR(MAX) = N'
        @TerritoryName NVARCHAR(50),
        @SalesPersonName NVARCHAR(50),
        @ProductCategory NVARCHAR(50),
        @StartDate DATE,
        @EndDate DATE
    ';

    IF @TerritoryName IS NOT NULL SET @SQL += ' AND t.Name = @TerritoryName';
    IF @SalesPersonName IS NOT NULL SET @SQL += ' AND CONCAT(p.FirstName, '' '', p.LastName) = @SalesPersonName';
    IF @ProductCategory IS NOT NULL SET @SQL += ' AND pc.Name = @ProductCategory';
    IF @StartDate IS NOT NULL SET @SQL += ' AND soh.OrderDate >= @StartDate';
    IF @EndDate IS NOT NULL SET @SQL += ' AND soh.OrderDate <= @EndDate';

    BEGIN TRY
        EXEC sp_executesql @SQL, @Params,
            @TerritoryName = @TerritoryName,
            @SalesPersonName = @SalesPersonName,
            @ProductCategory = @ProductCategory,
            @StartDate = @StartDate,
            @EndDate = @EndDate;

        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_SecureSalesReport',
            'Success',
            CONCAT(
                'Territory: ', ISNULL(@TerritoryName,''), 
                ', SalesPerson: ', ISNULL(@SalesPersonName,''), 
                ', Category: ', ISNULL(@ProductCategory,'')
            )
        );
    END TRY
    BEGIN CATCH
        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_SecureSalesReport',
            'Failed',
            CONCAT(
                'Territory: ', ISNULL(@TerritoryName,''), 
                ', SalesPerson: ', ISNULL(@SalesPersonName,''), 
                ', Category: ', ISNULL(@ProductCategory,'')
            )
        );
        THROW;
    END CATCH
END
GO


-- 3? Vulnerable Dynamic SQL Procedure

CREATE PROCEDURE Reporting.usp_VulnerableSalesReport
    @TerritoryName NVARCHAR(50) = NULL,
    @SalesPersonName NVARCHAR(50) = NULL,
    @ProductCategory NVARCHAR(50) = NULL,
    @StartDate DATE = NULL,
    @EndDate DATE = NULL
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @SQL NVARCHAR(MAX) = N'
        SELECT 
            t.Name AS TerritoryName,
            CONCAT(p.FirstName, '' '', p.LastName) AS SalesPersonName,
            pc.Name AS ProductCategory,
            soh.OrderDate,
            sod.LineTotal AS TotalSalesAmount,
            sod.OrderQty AS OrderQuantity
        FROM Sales.SalesOrderHeader soh
        JOIN Sales.SalesOrderDetail sod ON soh.SalesOrderID = sod.SalesOrderID
        JOIN Sales.SalesPerson sp ON soh.SalesPersonID = sp.BusinessEntityID
        JOIN HumanResources.Employee e ON sp.BusinessEntityID = e.BusinessEntityID
        JOIN Person.Person p ON e.BusinessEntityID = p.BusinessEntityID
        JOIN Sales.SalesTerritory t ON soh.TerritoryID = t.TerritoryID
        JOIN Production.Product prod ON sod.ProductID = prod.ProductID
        JOIN Production.ProductSubcategory ps ON prod.ProductSubcategoryID = ps.ProductSubcategoryID
        JOIN Production.ProductCategory pc ON ps.ProductCategoryID = pc.ProductCategoryID
        WHERE 1=1
    ';

    IF @TerritoryName IS NOT NULL SET @SQL += ' AND t.Name = ''' + @TerritoryName + '''';
    IF @SalesPersonName IS NOT NULL SET @SQL += ' AND CONCAT(p.FirstName, '' '', p.LastName) = ''' + @SalesPersonName + '''';
    IF @ProductCategory IS NOT NULL SET @SQL += ' AND pc.Name = ''' + @ProductCategory + '''';
    IF @StartDate IS NOT NULL SET @SQL += ' AND soh.OrderDate >= ''' + CONVERT(NVARCHAR, @StartDate, 23) + '''';
    IF @EndDate IS NOT NULL SET @SQL += ' AND soh.OrderDate <= ''' + CONVERT(NVARCHAR, @EndDate, 23) + '''';

    BEGIN TRY
        EXEC(@SQL);

        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_VulnerableSalesReport',
            'Success',
            CONCAT('Territory: ', ISNULL(@TerritoryName,''), ', SalesPerson: ', ISNULL(@SalesPersonName,''), ', Category: ', ISNULL(@ProductCategory,''))
        );
    END TRY
    BEGIN CATCH
        INSERT INTO Reporting.ExecutionLog (ProcedureName, ExecutionStatus, ParameterValues)
        VALUES (
            'usp_VulnerableSalesReport',
            'Failed',
            CONCAT('Territory: ', ISNULL(@TerritoryName,''), ', SalesPerson: ', ISNULL(@SalesPersonName,''), ', Category: ', ISNULL(@ProductCategory,''))
        );
        THROW;
    END CATCH
END
GO

-- 4? Execution Summary View
CREATE VIEW Reporting.vw_ExecutionSummary
AS
SELECT 
    COUNT(*) AS TotalExecutions,
    SUM(CASE WHEN ExecutionStatus='Success' THEN 1 ELSE 0 END) AS SuccessfulExecutions,
    SUM(CASE WHEN ExecutionStatus='Failed' THEN 1 ELSE 0 END) AS FailedExecutions,
    SUM(CASE WHEN ExecutionStatus='Rejected' THEN 1 ELSE 0 END) AS RejectedExecutions
FROM Reporting.ExecutionLog;
GO


-- 5? Test Examples
-- Secure procedure example
EXEC Reporting.usp_SecureSalesReport @TerritoryName='Northwest', @StartDate='2023-01-01', 
@EndDate='2023-12-31';

-- Vulnerable procedure example
EXEC Reporting.usp_VulnerableSalesReport @TerritoryName='Northwest';

SELECT * FROM Reporting.ExecutionLog;
SELECT * FROM Reporting.vw_ExecutionSummary;