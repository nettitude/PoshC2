<#
.Synopsis
   Invoke-SqlQuery
.DESCRIPTION
   Invoke-SqlQuery
.EXAMPLE
   Invoke-SqlQuery -Sqlserver 10.150.10.150 -Username sa -Password sa
#>
function Invoke-SqlQuery {

  param (
    [String]$ConnectionString,
    [String]$Sqlserver,
    [String]$Username,
    [String]$Password,
    [String]$Catalog,
    [String]$Database,
    [String]$Query
  )
  if (!$Database){
    $Database = ";"
  } else {
    $Database = "$Database;"
  }

  if (!$Catalog){
    $Catalog = "Initial Catalog=Master;"
  } else {
    $Catalog = "Initial Catalog=$Catalog;"
  }

  if ($Username -and $Password){
    $Authentication = "User Id=$Username;Password=$Password;"
  } else {
    $Authentication = "Integrated Security=True;"
  }

  if (!$query){
    $Query = 'SELECT @@version';
  }

  $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
  $SqlConnection.ConnectionString = "Data Source=$Sqlserver;$Catalog$Authentication$Database"
  $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
  $SqlCmd.CommandText = $Query
  $SqlCmd.Connection = $SqlConnection
  $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
  $SqlAdapter.SelectCommand = $SqlCmd
  $DataSet = New-Object System.Data.DataSet
  $SqlAdapter.Fill($DataSet)
  $DataSet.Tables[0]            

}
