param (
	[Parameter(Mandatory=$true)][string] $Method,
	$User,
	$Password,
	$MFACode
)

$base_uri = "https://api.evosecurity.com/api/v1/desktop"

function EvoAuthenticate([parameter(Mandatory = $true)] $user, [parameter(Mandatory = $true)] $password, $environment_url = "https://evo.evosecurity.io")
{
	$uri = "$($base_uri)/authenticate"
	$payload = ( @{ "user" = $user ; "password" = $password ; "environment_url" = $environment_url  } | ConvertTo-JSON )
	if ($Debug) { Write-Host -fore green $payload  }
	$WebResponse = Invoke-WebRequest -uri  $uri -Method POST -body $payload -ContentType "application/json"
	Write-Host $WebResponse.StatusCode
	if ($WebResponse.StatusCode -eq 200)
	{
		Write-Host "request_id: $(($WebResponse.Content | ConvertFrom-JSON).request_id)"
	}
	$WebResponse
}

function EvoValidateMFA([parameter(Mandatory = $true)] $user, [parameter(Mandatory = $true)] $mfa_code, $environment_url = "https://evo.evosecurity.io")
{
	$uri = "$base_uri/validate_mfa"
	$payload = ( @{ "mfa_code" = $mfa_code ; "environment_url" = $environment_url ; "user" = $user ; "password" = "Testing123!" } | ConvertTo-JSON)
	Write-Host -fore Green $payload
	$WebResponse = Invoke-WebRequest -uri $uri -Method POST -body $payload -ContentType "application/json"
	$WebResponse
}

function EvoCheckLoginRequest([parameter(Mandatory = $true)] $request_id)
{
	$uri = "$base_uri/check_login_request?request_id=$request_id"
	$WebResponse = Invoke-WebRequest -uri $uri -Method GET
	$WebResponse
}


if ($Method -eq "Authenticate") {
	$response = EvoAuthenticate $User $Password
	$response 
}
elseif ($Method -eq "Validate") {
	$what = EvoValidateMFA $User
	$what.Content
}
elseif ($Method -eq "CheckLogin") {
	EvoCheckLoginRequest
}
else {
	echo "Acceptable methods are: Authenticate, Validate, or CheckLogin"
	return
}


# $response = EvoAuthenticate "evo.testing@evosecurity.com" "Testing123!"

# $response_dict = ($response.content | ConvertFrom-JSON)
# $request_id = $response_dict.request_id

# "mfa_enabled: $($response_dict.mfa_enabled)"
# "request_id: $request_id"


# EvoValidate_MFA  "evo.testing@evosecurity.com" $request_id

# EvoCheckLoginRequest $request_id

