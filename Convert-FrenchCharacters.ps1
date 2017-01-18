<#
	.SYNOPSIS
		Remove French special characters.
	
	.DESCRIPTION
		Convert a string/name to basic Latin characters.
	
	.PARAMETER String
		String or Name to be converted.
	
	.EXAMPLE
		PS C:\> Convert-FrenchCharacters -String 'François Gérard'

		Francois Gerard

#>
function Convert-FrenchCharacters
{
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 0)]
		[ValidateNotNullOrEmpty()]
		[Alias('Name')]
		[string]
		$String
	)
	
	$Output = New-Object System.Text.StringBuilder
	
	$NoSpecial = $String.Normalize("FormD")
	
	$NoSpecial.ToCharArray() | ForEach-Object -Process {
		if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($psitem) -ne [Globalization.UnicodeCategory]::NonSpacingMark)
		{
			[void]$Output.Append($psitem)
		}
	}
	
	Return $Output.ToString()
}