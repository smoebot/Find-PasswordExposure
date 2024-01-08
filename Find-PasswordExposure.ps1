function Find-PasswordExposure {
    <#
    .SYNOPSIS
        Connects to the Recorded Future Identity API, and checks for Passwords that have been leaked
    .DESCRIPTION
        Connects to the Recorded Future Identity API, and checks for Passwords that have been leaked
        Hashes cleartext passwords that are provided, before sending them to the API
    .PARAMETER Hash
        A SHA256 hash of the password that you are looking up
    .PARAMETER Password
        The cleartext value of the password that you are searching for
        This is hashed before being sent to the API
    .NOTES
        Author: Joel Ashman
        v0.1 - (2023-12-29) Initial version
    .EXAMPLE
        Find-Password -Hash 5649332AC4766C482F458AE0E276D7A5330A1F76816732E7A8C0BE9CCDFA2D1A
        Find-Password -Password Password123
    #>

    #requires -version 5
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Password,
        [Parameter()]
        [string]$Hash
    )

    # Function within a function?  Not sure if this is the best way. Ideally, a Powershell module containing all of our tools would be built
    function Get-HashOfString{
        <#
        .SYNOPSIS
            Computes the hash of a given input string
        .DESCRIPTION
            Computes the hash of a given input string
            Uses default hashing algorithm (SHA256) without parameter.
            Can be specified to use SHA1, SHA256, SHA384, SHA512, or MD5
        .PARAMETER String
            [Mandatory] String Parameter
            The string that you want to hash
            Enclose this in quotes if it has a space
        .PARAMETER Algorithm
            String Parameter
            Hashing algorithm to use. Options are: SHA1, SHA256, SHA384, SHA512, or MD5
            If no value is specified, or if the parameter is omitted, the default value is SHA256
        .NOTES
            Author: Joel Ashman (Shamelessly taken from below url) 
            https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.3
            v0.1 - (2023-12-29) Initial version
        .EXAMPLE
            Get-HashOfString -String "Boxing Day Test"
        #>

        #requires -version 5
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$String,
            [Parameter()]
            [string]$Algo
        )
        
        if ($Algo){$Algo = $Algo} # Ensure that the Algorithm is set
        else{$Algo = "SHA256"}
        Write-Warning "Hashing algorithm selected: $($Algo)"
        # Set up the input stream so that we can hash the string
        $StringAsStream = [System.IO.MemoryStream]::new()
        $Writer = [System.IO.StreamWriter]::new($StringAsStream)
        $Writer.write($String)
        $Writer.Flush()
        $StringAsStream.Position = 0
        try{
            (Get-FileHash -InputStream $stringAsStream -Algorithm $Algo| Select-Object Hash).hash # Calculate the hash of the string
        }
        catch{Write-Warning "Error: $($Error.Errors.Message)"}
    }

    # Main function starts here
    # Work out which way the user input the Password data
    if ((-not $Hash) -and ($Password)){ # No hash provided, just cleartext password data - hash the password before we send it to the API
        Write-Warning "Cleartext password provided, hashing before sending to API"
        $Hash = Get-HashOfString -String $Password
    }
    elseif (($Hash) -and (-not $Password)){ # Password hash provided - send the hash to the API, and ignore the cleartext password (if it was provided)
        Write-Warning "Hash provided, no need for further calculation before sending to API"
    }
    elseif ((-not $Hash) -and (-not $Password)){ # Value not provided for Password or Hash
        Write-Warning "No Password or Hash data provided, exiting"
        Return
    } 
    $ApiToken = "<API TOKEN GOES HERE>" # Not a secure way to store this - should investigate another option
    $RecordedFuturePasswordsUrl = "https://api.recordedfuture.com/identity/password/lookup"
    $Header = @{"X-RFToken" = $ApiToken} # Authorisation header for RF API
    ## Build the table to hold the request body data.  
    # Important - case sensitive.  The difference between Algorithm and algorithm took me far longer to troubleshoot than I'm willing to admit
    $Params = @{
        'passwords' = @(
            @{'algorithm' = 'SHA256' 
            'hash' = $Hash}
        )
    }
    $Body = $Params | ConvertTo-Json # Convert the table to JSON for the API to accept it

    # POST request to the API
    try{
        (Invoke-restmethod -Method Post -Headers $Header -Uri $RecordedFuturePasswordsUrl -Body $Body -ContentType application/json).results
    }
    catch{
        if($Error.Errors -eq $null){Write-Warning "Error: $($Error[0].ErrorDetails.message)"}
        else{Write-Warning "Error: $($Error.Errors.Message)"}
    }
}
