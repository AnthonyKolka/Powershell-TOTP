function Get-TOTP
{
    <#
        .SYNOPSIS
            Outputs a TOTP code based on provided HMAC key
    #>
    [CmdletBinding()]
    Param(
        #A string containing a RFC 4648 Base32 alphabet representation of a cryptographic key (most secret keys are in this format)
        [Parameter(Mandatory=$true)]
            [string]
            $key,
        # Duration TOTP is valid for (Both side must use same value) default 30
        [Parameter(Mandatory=$false)]
            [int32]
            $duration = 30,
        # TOTP character length (Both side must use same value) default 6
        [Parameter(Mandatory=$false)]
            [int32]
            $length = 6
    )
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    #Base32 decode secret into byte array
    $bint = [Numerics.BigInteger]::Zero
    foreach ($char in ($key.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
        $bint = ($bint -shl 5) -bor ('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.IndexOf($char))
    }
    $secretBytes = $bint.ToByteArray()
    if ($secretBytes[-1] -eq 0) {
        $secretBytes = $secretBytes[0..($secretBytes.Count - 2)]
    }
    [array]::Reverse($secretBytes)
    $hmac.key = $secretBytes

    #create hash
    $span = New-TimeSpan -Start (Get-Date -Date "1970-01-01 00:00") -End (Get-Date).ToUniversalTime()
    $seconds = [math]::floor($span.TotalSeconds)
    $counter = [Convert]::ToInt32($seconds / $duration)
    $bytes = New-Object Byte[] 8
    $current = 7
    while (($counter -gt 0) -and ($current -ge 0)) {
	   $bytes[$current] = ($counter -band 0xff)
	   $counter = [math]::floor($counter / 256)
	   $current -= 1
    }
    $randHash = $hmac.ComputeHash($bytes)

    # create an OTP compatable with http://tools.ietf.org/html/rfc4226#section-5.3
    $offset = $randhash[19] -band 0xf
    $Result = ($randhash[$offset] -band 0x7f) * 16777216
    $Result += ($randHash[$offset + 1] -band 0xff) * 65536
    $Result += ($randHash[$offset + 2] -band 0xff) * 256
    $Result += ($randHash[$offset + 3] -band 0xff)
    return ($Result % [math]::pow(10, $length)).ToString("0" * $length)
}