using namespace System.Net.Http
using namespace System.Net.Http.Headers
using namespace System.Net.Http.Json
using namespace System.Net.Security
using namespace System.Net
using namespace System.Text
using namespace System.Collections.Generic
using namespace Diagnostics.CodeAnalysis
using namespace System.Management.Automation
using namespace System.Security.Authentication
using namespace System.Security.Cryptography.X509Certificates

. '\Write-ColoredInfo.ps1'
$script:token = (Get-Content -Path .\bogus_token.txt -Raw).Trim()
$script:realToken = (Get-Content -Path 'c:\blahblah\blah\token.txt' -Raw).Trim()
$PSDefaultParameterValues['Write-ColoredInfo:InformationAction'] = 'Continue'

function New-HttpClientHandler {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [switch]$AllowAutoRedirect = $true,
    [DecompressionMethods]$AutomaticDecompression,
    [switch]$CheckCertificateRevocationList,
    [ClientCertificateOption]$ClientCertificateOptions,
    [X509CertificateCollection]$ClientCertificates,
    [CookieContainer]$CookieContainer,
    [ICredentials]$Credentials,
    [ICredentials]$DefaultProxyCredentials,
    [int]$MaxAutomaticRedirections = 15,
    [int]$MaxConnectionsPerServer,
    [long]$MaxRequestContentBufferSize,
    [int]$MaxResponseHeadersLength,
    [switch]$PreAuthenticate,
    [IDictionary[string, object]]$Properties,
    [IWebProxy]$Proxy,
    [Func[HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool]]
    $ServerCertificateCustomValidationCallback,
    #[SslProtocols]$SslProtocols = $([enum]::Parse([SslProtocols],'Tls12,Tls13')),
    [SslProtocols]$SslProtocols = 'Tls12,Tls13',
    [switch]$UseCookies,
    [switch]$UseDefaultCredentials,
    [switch]$UseProxy
  )
  $clientHandlerParam = $PSBoundParameters
  if ($clientHandlerParam.ContainsKey('SslProtocols')) {
    $clientHandlerParam['SslProtocols'] = [SslProtocols]$SslProtocols
  }
  if ($clientHandlerParam.ContainsKey('ClientCertificateOptions')) {
    $clientHandlerParam['ClientCertificateOptions'] = [ClientCertificateOption]::Parse($clientHandlerParam['ClientCertificateOptions'])
  }
  if ($clientHandlerParam.ContainsKey('ServerCertificateCustomValidationCallback')) {
    $clientHandlerParam['ServerCertificateCustomValidationCallback'] = $clientHandlerParam['ServerCertificateCustomValidationCallback'].GetScriptBlock()
  }
  try {
    $clientHandler = [Net.Http.HttpClientHandler]::new()
    foreach ($kv in $clientHandlerParam.GetEnumerator()) {
      if ($kv.Value -is [switch]) {
        $clientHandler.$($kv.Key) = $kv.Value.IsPresent
      } else {
        $clientHandler.$($kv.Key) = $kv.Value
      }
    }
  } catch {
    Write-ColoredInfo -InputString $_.Exception.Message -ForegroundColor Red
    Write-ColoredInfo -InputString $_.Exception.StackTrace -ForegroundColor Red
    throw $_.Exception
  }  
}
function New-HttpClient {
  [CmdletBinding()]
  param (
    [version]$DefaultRequestVersion,
    [hashtable]$RequestHeaders,
    [HttpVersionPolicy]$VersionPolicy,
    [uri]$BaseAddress,
    [TimeSpan]$Timeout = [TimeSpan]::FromMinutes(3),
    [int]$MaxResponseContentBufferSize = 2147483647
    
  )
  $clientParam = $PSBoundParameters
  if ($clientParam.ContainsKey('Timeout')) {
    $clientParam['Timeout'] = [TimeSpan]$clientParam['Timeout']
  } else {
    $clientParam['Timeout'] = [TimeSpan]::FromMinutes(3)
  }
  if ($clientParam.ContainsKey('MaxResponseContentBufferSize')) {
    $clientParam['MaxResponseContentBufferSize'] = [int]$clientParam['MaxResponseContentBufferSize']
  } else {
    $clientParam['MaxResponseContentBufferSize'] = 2147483647
  }
  if ($clientParam.ContainsKey('BaseAddress')) {
    $clientParam['BaseAddress'] = [Uri]$clientParam['BaseAddress']
  }
  if ($clientParam.ContainsKey('DefaultRequestVersion')) {
    $clientParam['DefaultRequestVersion'] = [Version]$clientParam['DefaultRequestVersion']
  }
  # if ($clientParam.ContainsKey('UseDefaultHandler')) {
  #   $clientParam['UseDefaultHandler'] = $clientParam['UseDefaultHandler'].IsPresent
  # } else {
  #   $clientParam['UseDefaultHandler'] = $false
  # }

  [HttpClient]$clientParam
}
function New-HttpRequestMessage {
  [CmdletBinding()]
  param (
    [ValidateSet('Get', 'Post', 'Put', 'Delete', 'Head', 'Options', 'Trace', 'Connect')]
    [HttpMethod]$Method,
    [Alias('Uri')]
    [Uri]$RequestUri,
    [hashtable]$Headers,
    $Content
  )
  if ($PSBoundParameters.ContainsKey('UseDefaultMethod')) {
    $requestParam = [HttpRequestMessage]::new()
  } else {
    $requestParam = [HttpRequestMessage]::new($PSBoundParameters['Method'], $PSBoundParameters['RequestUri'])
  }
  if ($PSBoundParameters.ContainsKey('Content')) {
    $requestParam.Content = $PSBoundParameters['Content']
  }
  if ($Headers) {
    foreach ($header in $Headers.GetEnumerator()) {
      $null = $requestParam.Headers.Add($header.Name, $header.Value)
    }
  }
  [HttpRequestMessage]$requestParam
}
function Add-HttpRequestMessageHeader {
  [Alias('Set-HttpRequestMessageHeader')]
  [CmdletBinding()]
  param (
    [Parameter(ValueFromPipeline = $true)]
    [HttpRequestMessage]$Request,
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    [ValidateNotNullOrEmpty()]
    [string]$Value
  )
  $requestParam = $PSBoundParameters
  $null = $requestParam.Remove('Name')
  $null = $requestParam.Remove('Value')
  $null = $requestParam['Request'].Headers.Add($Name, $Value)
  [HttpRequestMessage]$requestParam['Request']

}
function New-HttpContent {
  [CmdletBinding(DefaultParameterSetName = 'JsonContent')]
  param (
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'StringContent')]
    [string]$StringContent,
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'JsonContent')]
    [string]$JsonContent,
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'ByteArrayContent')]
    [byte[]]$ByteArrayContent,
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'StreamContent')]
    [IO.Stream]$StreamContent,
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'MultipartContent')]
    [hashtable]$MultipartContent,
    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      ParameterSetName = 'MultipartFormDataContent')]
    [hashtable]$MultipartFormDataContent,
    [Encoding]$Encoding = [Encoding]::UTF8
  )
  begin {}
  end {
    if ($PSCmdlet.ParameterSetName -eq 'JsonContent') {
      [Json.JsonContent]::Create(
        $PSBoundParameters['JsonContent'], [MediaTypeHeaderValue]'application/json', $null
      )
    } else {
      switch ($PSCmdlet.ParameterSetName) {
        'StringContent' {
          $params = [StringContent]$PSBoundParameters['StringContent']
        }
        'JsonContent' {
          $params = [Json.JsonContent]::Create(
            $PSBoundParameters['JsonContent'], [MediaTypeHeaderValue]'application/json', $null
          )
        }
        'ByteArrayContent' {
          $params = [ByteArrayContent]$PSBoundParameters['ByteArrayContent']
        }
        'StreamContent' {
          $params = [StreamContent]$PSBoundParameters['StreamContent']
        }
        'MultipartContent' {
          $params = [MultipartContent]$PSBoundParameters['MultipartContent']['Boundary']
          foreach ($item in $PSBoundParameters['MultipartContent']['Content']) {
            $params.Add($item)
          }
        }
        'MultipartFormDataContent' {
          $params = [MultipartFormDataContent]$PSBoundParameters['MultipartFormDataContent']['Boundary']
          foreach ($item in $PSBoundParameters['MultipartFormDataContent']['Content']) {
            $params.Add($item)
          }
        }
      }
      [HttpContent]$params
    }
  }
}
function Invoke-HttpRequest {
  [CmdletBinding(DefaultParameterSetName = '')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [HttpRequestMessage]$Request
  )
  if ($PSBoundParameters.ContainsKey('UseDefaultClient')) {
    if (-NOT $Global:PSHttpClient) {
      $Global:PSHttpClient = New-HttpClient
    }
    $Client = $Global:PSHttpClient
  } else {
    $Client = $PSBoundParameters['Client']
  }
  Write-Verbose -Message ('Sending request to: {0}' -f $Request.RequestUri) -Verbose
  $Client.SendAsync($Request).Result
}
function Get-ResponseContent {
  [CmdletBinding()]
  param (
    [Parameter(ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [HttpResponseMessage]$Response,
    [ValidateSet('String', 'Bytes', 'Stream', 'ReadAsStringAsync', 'ReadAsByteArrayAsync', 'ReadAsStreamAsync')]
    [string]$As = 'String'
  )
  if (-NOT $Response) {
    $PSCmdlet.ThrowTerminatingError([ErrorRecord]::new(
        [ArgumentNullException]::new('Response'),
        'Response',
        [ErrorCategory]::InvalidArgument,
        $Response
      ))
  }
  if (-NOT $Response.IsSuccessStatusCode) {
    Write-Verbose -Message 'Failure response received.' -Verbose
    $message = [string[]](
      'An error occurred:',
      ([string]::Format('Status Code: {0}', [int]$Response.StatusCode)), 
      ([string]::Format(' Reason: {0}', $Response.ReasonPhrase))
    ) -join "`n"
    #$PSCmdlet.WriteError($message)
    Write-Error -Message $message
  } else {
    switch ($As) {
      'String' {
        $Response.Content.ReadAsStringAsync().Result
      }
      'Bytes' {
        $Response.Content.ReadAsByteArrayAsync().Result
      }
      'Stream' {
        $Response.Content.ReadAsStreamAsync().Result
      }
      'ReadAsStringAsync' {
        $Response.Content.ReadAsStringAsync().Result
      }
      'ReadAsByteArrayAsync' {
        $Response.Content.ReadAsByteArrayAsync().Result
      }
      'ReadAsStreamAsync' {
        $Response.Content.ReadAsStreamAsync().Result
      }
    }
  }
}
function Test-HttpClientRequest {
  [CmdletBinding(DefaultParameterSetName = '')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [HttpRequestMessage]$Request
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request $Request -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Search-SplunkHead {
  [CmdletBinding()]
  param (
    [string]$ApiToken = $script:realToken,
    [string]$ComputerName = 'myriad.splunkcloud.com',
    [string]$Query,
    [int]$Count = 10,
    [int]$Offset = 0,
    [string]$Sort = 'desc'
  )
  if (-NOT (Get-Variable -Name PSHttpClient -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:PSHttpClient = @{
      HttpClient        = New-HttpClient -Timeout ([timespan]'00:00:30')
      DefaultHandler    = New-HttpClientHandler
      Timeout           = '00:00:30'
      UseDefaultHandler = $true
    }
  }
  if ($JobId) {
    $url = [uri]::new(('https://{0}:8089/services/search/jobs/{1}/results' -f $ComputerName, $JobId))
  } else {
    $url = [uri]::new(('https://{0}:8089/services/search/jobs/export' -f $ComputerName))
  }
  $req = New-HttpRequestMessage -RequestUri $url -Method Post -Content (
    New-HttpContent -StringContent $Query
  )
  $req = $req | Add-HttpRequestMessageHeader -Name 'Authorization' -Value ('Bearer {0}' -f $ApiToken)
  Invoke-HttpRequest -Client $Global:PSHttpClient -Request $req -UseDefaultClient | Get-ResponseContent -As ReadAsStringAsync
}
#region [Create Default Client Handler and then PSHttpClient if it doesn't exist]
$Script:DefaultClientHandler = New-HttpClientHandler -AllowAutoRedirect -AutomaticDecompression Deflate, GZip -SslProtocols Tls12, Tls13
if (-NOT (Get-Variable -Name PSHttpClient -ValueOnly -ErrorAction SilentlyContinue)) {
  $Global:PSHttpClient = New-HttpClient -Timeout ([timespan]'00:00:30')
}
#endregion
#region [User preferences]
function Set-PSHttpClientConfig {
  [CmdletBinding()]
  param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [HttpClientHandler]$Handler,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [timespan]$Timeout,
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [switch]$UseDefaultHandler
  )
}
#endregion
function Get-SwaggerDefinition {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpRequestMessage]$Request
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    } else {
      $Client = New-HttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request $Request -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Read-SwaggerJson {
  [CmdletBinding()]
  param (
    [Parameter(
      ValueFromPipeline = $true,
      Mandatory = $true,
      Position = 0)]
    [Alias('SwaggerJsonPath')]
    [string]$Path
  )
  if (-NOT (Test-Path -Path $Path)) {
    $PSCmdlet.ThrowTerminatingError([ErrorRecord]::new(
        [ArgumentNullException]::new('Path'),
        'Path',
        [ErrorCategory]::InvalidArgument,
        $Path
      ))
  } else {
    $Path = Resolve-Path -Path $Path
  } 
  $SwaggerJson = Get-Content -Path $Path -Raw
  $swaggerDef = ConvertFrom-Json -InputObject $SwaggerJson
  $swaggerDef
}

#region Test functions
function Test-HttpClientPost {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri,
    [ValidateNotNullOrEmpty()]
    [HttpContent]$Content
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Post -Content $Content -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientGet {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Get -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientPut {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri,
    [ValidateNotNullOrEmpty()]
    [HttpContent]$Content
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Put -Content $Content -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientDelete {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Delete -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientPatch {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri,
    [ValidateNotNullOrEmpty()]
    [HttpContent]$Content
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Patch -Content $Content -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientHead {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Head -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientOptions {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Options -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientTrace {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Trace -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientConnect {
  [CmdletBinding()]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(
      Mandatory = $true, 
      ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  }
  $response = Invoke-HttpRequest -Client $Client -Request (New-HttpRequestMessage -Method Connect -RequestUri $RequestUri) -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
function Test-HttpClientGetWithHeaders {
  [CmdletBinding(DefaultParameterSetName = 'NoClient')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidDefaultValueSwitchParameter', '')]
  param (
    [Parameter(ParameterSetName = 'SpecifiedClient')]
    [ValidateNotNullOrEmpty()]
    [HttpClient]$Client,
    [Parameter(ParameterSetName = 'NoClient')]
    [switch]$UseDefaultClient = $true,
    [ValidateNotNullOrEmpty()]
    [string]$RequestUri,
    [ValidateNotNullOrEmpty()]
    [string[]]$Headers
  )
  if ($PSCmdlet.ParameterSetName -eq 'SpecifiedClient') {
    $UseDefaultClient = [switch]$false
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    }
  } else {
    if ($Global:PSHttpClient) {
      $Client = $Global:PSHttpClient
    } else {
      $Client = New-HttpClient
    }
  }
  $request = New-HttpRequestMessage -Method Get -RequestUri $RequestUri
  foreach ($header in $Headers) {
    $name, $value = $header.Split(':').Trim()
    if ($value -match 'application/json') {
      $request.Headers.Add($name, [MediaTypeWithQualityHeaderValue]::Parse($value))
    } else {
      $request.Headers.Add($name, $value)
    }
    # if($name -match 'Content-Type|Accept') {
    #   $request.Headers.Add($name, [MediaTypeWithQualityHeaderValue]::Parse($value))
    # } else {
    #   $request.Headers.Add($name, $value)
    # }
  }
  $response = Invoke-HttpRequest -Client $Client -Request $request -UseDefaultClient:$UseDefaultClient
  ($response | Get-ResponseContent)
}
#Test-HttpClientGetWithHeaders -RequestUri 'https://httpbin.org/get' -Headers @('Accept: application/json', 'Content-Type: application/json')
#Test-HttpClientGet -RequestUri 'https://httpbin.org/get' -

#endregion

# $content = (New-HttpContent -StringContent '{
#   "host": "splunk.myriadgenetics.com",
#   "source": "James'' Powershell httpclient",
#   "sourcetype": "powershell",
#   "event": {
#     "message": "This is a test"
#     "severity": "info"
#   }
# }')
# $content = New-HttpContent -JsonContent '{
#   "id": 325,
#   "title": "Samsung Galaxy S23 Ultra",
#   "data": {
#     "generation": "5th",
#     "price": 2000
#   }
# }'
#$request = New-HttpRequestMessage -Method Get -Content $content -RequestUri 'https://splunk.myriadgenetics.com:8089/services/collector/event'
# $request = New-HttpRequestMessage -Method Post -Content $content -RequestUri 'https://httpbin.org/anything' -Headers @{
#   'Accept'     = [MediaTypeWithQualityHeaderValue]::new('application/json')
#   'User-Agent' = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome.ToString()
# }
# $request = New-HttpRequestMessage -Method Get -RequestUri 'https://httpbin.org/base64/dGhpcyBhIGNvb2wgYXdlc29tZSB0ZXN0' -Headers @{
#   'Accept' = [MediaTypeWithQualityHeaderValue]::new('application/json')
#   'User-Agent' = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome.ToString()
# }
#$request = $request | Add-HttpRequestMessageHeader -Name Authorization -Value $script:token

# $out = Invoke-HttpRequest -Request $request -UseDefaultClient | Get-ResponseContent -As ReadAsStringAsync
# $out
