<#
.Synopsis
    Searches recursively through the provided path searching for valid credit card numbers
.DESCRIPTION
	 Large files are read in chunks so as to not exhaust system resources
.EXAMPLE
    PS C:\> Get-CreditCardData -Path C:\Backup\
#>

Function Get-CreditCardData {

    param (
      [string]$path = $(throw "-path is required";)
    )

    #$Excel = New-Object -ComObject Excel.Application

    $REGEX = [regex]"(?im)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})"
    $REGEX2 = [regex]"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$"
    $REGEX3 = [regex]"[456][0-9]{15}","[456][0-9]{3}[-| ][0-9]{4} [-| ][0-9]{4}[-| ][0-9]{4}"

    Get-ChildItem -Rec -Exclude *.exe,*.dll $path -File | % {

        #if (($_.FullName -like "*xls") -or ($_.FullName -like "*.xlsx")){
            #$Workbook = $Excel.Workbooks.Open($_.FullName)
            #If(($Workbook.Sheets.Item(1).Range("A:Z")) | Select-String -pattern $REGEX){
            #    $Workbook.Close($false)
            #    Write-Output "[+] Potential Card data found:" $_.FullName -ForegroundColor green
            #}
        #}

        if ((Select-String -pattern $REGEX -Path $_.FullName -AllMatches).Matches.Count -gt 5 ) {
            Write-Output "[+] Potential Card data found:" $_.FullName -ForegroundColor green
            return
        }

    }
    
}

# Sample credit card data for testing
#3782 8224 6310 0054
#371449635398431
#371449635398432
#371449635398434
#371449635398432
#371449635398430
#371449635398432
