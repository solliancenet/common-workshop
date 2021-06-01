<#
#
#  THIS CODE IS COPYRIGHT CHRIS GIVENS (@GIVENSCJ) WITH A LICENSE TO SOLLIANCE.NET ONLY!
#  ALL RIGHTS RESERVED
#>

$global:defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763";
$global:headers = new-object system.collections.hashtable;
$global:urlCookies = new-object System.Collections.Hashtable;

function ClearCookies()
{
    $global:urlCookies = new-object System.Collections.Hashtable;
}

function SetCookiesUnformatted($url, $cookies)
{
    $uri = new-object uri($url)
    SetCookies $url $(ParseCookies $cookies $uri.host $false);
}

function SetCookies($url, $incoming)
{
    $u = new-object Uri($url);

    if ($global:urlCookies.Contains($u.Host))
    {        
        $current = $global:urlCookies[$u.Host];

        foreach ($key in $incoming.Keys)
        {
            if ($current.ContainsKey($key))
            {
                $current[$key] = $incoming[$key];
            }
            else
            {
                $current.Add($key, $incoming[$key]);
            }
        }
    }
    else
    {
        $global:urlCookies.Add($u.Host, $incoming);
    }

    return;
}

function GetCookies($url)
{
    if ($global:nocookies)
    {
        return "";
    }

    $u = new-object Uri($url);

    if ($global:urlCookies.Contains($u.Host))
    {
        return $(FormatCookie $global:urlCookies[$u.Host]);
    }

    return "";
}

function FormatCookie($ht)
{
    $cookie = "";

    foreach ($key in $ht.Keys)
    {
        $cookie += $key.Trim() + "=" + $ht[$key] + "; ";
    }

    return $cookie;
}

function ParseCookies($cookieString, $inDomain, $isPreparsed)
{
    $ht = new-object System.Collections.Hashtable;

    if (!$cookieString)
    {
        return $ht;
    }

    $cookies = $cookieString.Split(';');

    $allCookies = new-object system.collections.hashtable;

    if ($isPreparsed)
    {
        $allCookies.Clear();

        $preCookies = $cookieString.Split(';');

        foreach ($s in $preCookies)
        {
            $allCookies.Add($s,$s);
        }
    }
    else
    {
        $cookies = [Regex]::Split($cookieString, "Secure,");

        foreach ($c in $cookies)
        {
            $cookies2 = [Regex]::Split($c, "HttpOnly,");

            foreach ($s in $cookies2)
            {
                if(!$allCookies.ContainsKey($s))
                {
                    $allCookies.Add($s,$s);
                }
            }

            $cookies2 = [Regex]::Split($c, "GMT,");

            foreach ($s in $cookies2)
            {
                if(!$allCookies.ContainsKey($s))
                {
                    $allCookies.Add($s,$s);
                }
            }
        }
    }

    foreach ($c in $allCookies.keys)
    {
        $domain = $inDomain;

        $vals = $c.split(";");

        if ($c.Contains("Domain"))
        {
            $tempDomain = ParseValue $c "Domain=" ";";

            if ($tempDomain)
            {
                $domain = $tempDomain;
            }
        }

        if ($c.Contains("domain"))
        {
            $tempDomain = ParseValue $c "domain=" ";";

            if ($tempDomain)
            {
                $domain = $tempDomain;
            }
        }

        if ($domain.Contains(","))
        {
            $domain = $domain.Substring(0, $domain.IndexOf(","));
        }

        if ($domain -eq "." + $inDomain)
        {
            $domain = $inDomain;
        }

        foreach($c1 in $vals)
        {
            try
            {
                $c1 = $c1.Replace("SameSite=Lax,", "");
                $c1 = $c1.Replace("SameSite=None,", "");
                $c1 = $c1.Replace("HttpOnly,", "");
                $c1 = $c1.Replace("Secure,", "");
                $c1 = $c1.Replace("version=1,", "");
                $c1 = $c1.Replace("Path=/,", "");            
                $c1 = $c1.Replace("path=/,", "");            

                if ($c1.Trim().Contains("HttpOnly"))
                {
                    continue;
                }

                if ($c1.Trim().tolower().Contains("httponly"))
                {
                    continue;
                }

                if ($c1.Trim().tolower().Contains("httponly"))
                {
                    continue;
                }

                if ($c1.tolower().Contains("expires="))
                {
                    $temp = ParseValue $c1 "=" "GMT,";

                    if($temp)
                    {
                        $c1 = $c1.replace("Expires=" + $temp + "GMT,", "");
                    }
                }

                if ($c1.tolower().Contains("expires="))
                {                
                    continue;
                }

                if ($c1.Contains("Max-Age="))
                {
                    continue;
                }

                if ($c1.Contains("domain="))
                {
                    continue;
                }

                if ($c1.Contains("secure="))
                {
                    continue;
                }

                if ($c1.Contains("path="))
                {
                    continue;
                }

                if ($c1.Trim() -eq "secure")
                {
                    continue;
                }

                if ($c1.Trim().StartsWith("secure,"))
                {
                    $c1 = $c1.substring(8);
                }

                if ($c1.Trim().StartsWith("httponly,"))
                {
                    $c1 = $c1.substring(10);
                }

                if ($c1.Contains("="))
                {
                    try
                    {                    
                        $value = $c1.Substring($c1.IndexOf("=") + 1);
                        $name = $c1.Substring(0, $c1.IndexOf("=")).trim();

                        if ($name.tolower().trim().contains("|max-age"))
                        {
                            continue;
                        }

                        if ($name.tolower().trim().contains("|version"))
                        {
                            continue;
                        }

                        if ($ht.ContainsKey($name))
                        {
                            $ht[$name] = $value;
                        }
                        else
                        {
                            $ht.Add($name, $value);
                        }
                    }
                    catch
                    {
                        write-host "Error parsing cookies";
                    }
                }
            }
            catch
            {
                write-host "Error parsing cookies";
            }
        }
    }

    return $ht;
}

function ParseValue($line, $startToken, $endToken, $useLastIndexOf)
{
    if ($startToken -eq $null)
    {
        return "";
    }

    if ($startToken -eq "")
    {
        if ($useLastIndexOf)
        {
            return $line.substring(0, $line.indexof($endtoken));
        }
        else
        {
            return $line.substring(0, $line.lastindexof($endtoken));
        }
    }
    else
    {
        try
        {
            $rtn = $line.substring($line.indexof($starttoken));
            
            if ($useLastIndexOf)
            {
                return $rtn.substring($startToken.length, $rtn.lastindexof($endToken) - $startToken.length).replace("`n","").replace("`t","");
                
            }
            else
            {
                return $rtn.substring($startToken.length, $rtn.indexof($endToken, $startToken.length) - $startToken.length).replace("`n","").replace("`t","");
            }
        }
        catch [System.Exception]
        {
            $message = "Could not find $starttoken"
            #write-host $message -ForegroundColor Yellow
        }
    }

}

$global:headers = new-object System.Collections.Hashtable
$global:videoBuffer = 2097152;
$global:currentMark = -1; 
$global:nextMark = -1;
$global:doChucks = $false;

function DoGet($url, $strCookies)
{    
    $cookies = new-object system.net.CookieContainer;
    
    try
    {
        $uri = new-object uri($url);
    }
    catch
    {
        write-host $($_.message + ":" + $url);
        return;
    }
    
    $httpReq = [system.net.HttpWebRequest]::Create($uri)
    
    if ($httpReq.GetType().Name -eq "FileWebRequest")
    {
        write-host $($_.message + ":" + $url);
        return;
    }    

    $httpReq.Accept = "text/html, application/xhtml+xml, */*"
    $httpReq.method = "GET"   
    
    if ($global:httptimeout)
    {        
        $httpReq.Timeout = $global:httptimeout;
    }

    if ($global:language)
    {
        $httpReq.Headers["Accept-Language"] = $global:language;
        $global:language = $Null;
    }

    if ($global:useragent)
    {
        $httpReq.useragent = $global:useragent;
        $global:useragent = $null;
    }
    else
    {
        $httpReq.useragent = $global:defaultUserAgent;
    }

    if ($global:referer)
    {
        $httpReq.Referer = $global:referer;
        $global:referer = $null;
    }

    if ($global:accept)
    {
        $httpReq.Accept = $global:accept;
        $global:accept = $null;
    }

    if ($global:connection)
    {
        $sp = $httpreq.ServicePoint;
        $prop = $sp.GetType().GetProperty("HttpBehaviour", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic);
        $prop.SetValue($sp, [byte]0, $null);

 
        $global:connection = $null;
    }

    $httpReq.AllowAutoRedirect = $global:allowautoredirect;    
    
    #allow us to override the cookies if we have done so...
    if ($strCookies.length -gt 0)
    {
        $httpReq.Headers.add("Cookie", $strCookies);
    }
    else
    {
        $cookie = GetCookies($url);

        if (![string]::IsNullOrEmpty($cookie))
        {
            $httpreq.Headers.Add("Cookie", $cookie);
        }    
    }

    foreach($key in $global:headers.keys)
    {
        $httpReq.Headers.add($key, $global:headers[$key]);
    }

    $global:headers.Clear();

    [string]$results = ProcessResponse $httpReq;    
    
    return $results
}

$global:fileName = ""
$global:fileBuffer = $null;
$global:location = "";
$global:contentRange = "";

function ProcessResponse($req)
{
    #use them all...
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Ssl3 -bor [System.Net.SecurityProtocolType]::Tls;

    if ($global:ignoreSSL)
    {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
    }

    $global:httpCode = -1;
    $global:fileName = ""
    #$global:fileBuffer = $null;    

    $urlFileName = $req.RequestUri.Segments[$req.RequestUri.Segments.Length - 1];            
    $response = "";            

    try
    {
        $res = $req.GetResponse();

        $mimeType = $res.ContentType;
        $statusCode = $res.StatusCode.ToString();
        $global:httpCode = [int]$res.StatusCode;
        $cookieC = $res.Cookies;
        $resHeaders = $res.Headers;  
        $global:rescontentLength = $res.ContentLength;
        $global:location = $null;
                                
        try
        {
            $global:location = $res.Headers["Location"].ToString();
        }
        catch
        {
        }

        try
        {
            $global:contentRange = $res.Headers["Content-Range"].ToString();

            $vals = $global:contentRange.replace("bytes","").split("-");
            $global:lastMark = $vals[0];        
            $vals = $vals[1].split("/");
            $global:currentMark = $vals[0];
            $global:maxMark = $vals[1];

            #set the content length...
            $global:rescontentLength = $global:maxMark;
        }
        catch
        {
        }

        try
        {
            $rawCookies = $res.Headers["set-cookie"].ToString();
            $global:httpcookies = $rawCookies;

            SetCookiesUnformatted $res.ResponseUri.ToString() $rawCookies;
        }
        catch 
        {
            write-host $_.Exception.message;
        }

        $global:fileName = "";
        $length = 0;

        try
        {
            $global:fileName = $res.Headers["Content-Disposition"].ToString();

            if ($global:fileName -ne "attachment")
            {
                $global:fileName = $global:fileName.Replace("attachment; filename=", "").Replace("""", "");

                if ($global:filename.contains("filename="))
                {
                    $global:filename = ParseValue $global:fileName "filename=" ";";
                }

                $length = $res.ContentLength;
            }
            else
            {
                $global:fileName = "";
            }
        }
        catch
        {

        }        

        if ($global:fileName.Length -gt 0 -or $res.ContentType -eq "application/vnd.openxmlformats-officedocument.presentationml.presentation" -or $res.ContentType -eq "application/x-protobuf")
        {
            $bufferSize = 10240;
            $buffer = new-object byte[] $buffersize;

            $strm = $res.GetResponseStream();  
            
            if ($global:fileBuffer -eq $Null)
            {          
                $global:bytesRead = 0;
                $global:fileBuffer = new-object byte[] $($res.ContentLength);
                $global:ms = new-object system.io.MemoryStream (,$global:fileBuffer);
            }
            
            while (($bytesRead = $strm.Read($buffer, 0, $bufferSize)) -ne 0)
            {
                $global:ms.Write($buffer, 0, $bytesRead);
            } 

            $global:ms.Close();
            $strm.Close();

            if ($res.contenttype -eq "application/x-protobuf")
            {
                $response = [System.Text.Encoding]::UTF8.GetString($global:filebuffer);
            }
        }
        else
        {
            $responseStream = $res.GetResponseStream();
            $contentType = $res.Headers["Content-Type"];

            if ($res.ContentEncoding.ToLower().Contains("gzip"))
            {
                $responseStream = new-object System.IO.Compression.GZipStream($responseStream, [System.IO.Compression.CompressionMode]::Decompress);
            }
            
            if ($res.ContentEncoding.ToLower().Contains("deflate"))
            {
                $responseStream = new-object System.IO.Compression.DeflateStream($responseStream, [System.IO.Compression.CompressionMode]::Decompress);
            }

            switch($contentType)
            {                
                {$_ -in "image/gif","image/png","image/jpeg","video/mp4"}
                {
                    $bufferSize = 409600;
                    $buffer = new-object byte[] $buffersize;                                        
                    $bytesRead = 0;

                    if ($global:fileBuffer -eq $Null)
                    {          
                        $global:bytesRead = 0;
                        $global:fileBuffer = new-object byte[] $($global:rescontentlength);
                        $global:ms = new-object system.io.MemoryStream (,$global:fileBuffer);
                    }
                                        
                    while (($bytesRead = $responseStream.Read($buffer, 0, $bufferSize)) -ne 0)
                    {
                        $global:ms.Write($buffer, 0, $bytesRead);
                        $global:bytesRead += $bytesRead;
                    } 
                    
                    <#
                    if ($global:bytesRead -eq $global:maxMark)
                    {
                        #$global:ms.Close();
                    }
                    #>

                    $responseStream.Close();

                    if ($global:fileName.Length -eq 0)
                    {                        
                        $global:fileName = $req.requesturi.segments[$req.requesturi.segments.length-1];

                        if ($contentType -eq "video/mp4")
                        {
                            $global:fileName += ".mp4";
                        }
                    }

                    }
                default{
                    $reader = new-object system.io.StreamReader($responseStream, [System.Text.Encoding]::UTF8);
                    $response = $reader.ReadToEnd();                            
                    }
            }

            $res.Close();
            $responseStream.Close();

            $req = $null;
            $proxy = $null;
        }
    }
    catch
    {
        $res2 = $_.Exception.InnerException.Response;
        $global:httpCode = $_.Exception.InnerException.HResult;
        $global:contentRange = $null;

        try
        {
            if ($res2)
            {
                $responseStream = $res2.GetResponseStream();
                $statusCode = $res2.StatusCode.ToString();
                $global:httpCode = [int]$res2.StatusCode;
                $reader = new-object system.io.StreamReader($responseStream, [System.Text.Encoding]::UTF8);                    
                $response = $reader.ReadToEnd();                            
                return $response;
            }
            else
            {
                write-host "Error getting response from $($req.RequestUri)";
            }
        }
        catch
        {
            $global:httperror = $_.exception.message;

            write-host "Error getting response from $($req.RequestUri)";

            return $null;
        }

        if ($res2 -and $res2.ContentEncoding.ToLower().Contains("gzip"))
        {
            $responseStream = new GZipStream($responseStream, [System.IO.Compression.CompressionMode]::Decompress);
        }
        
        if ($res2 -and $res2.ContentEncoding.ToLower().Contains("deflate"))
        {
            $responseStream = new DeflateStream($responseStream, [System.IO.Compression.CompressionMode]::Decompress);
        }

        if ($responseStream)
        {
            $reader = new-object System.IO.StreamReader($responseStream, [System.Text.Encoding]::UTF8);
            $response = $reader.ReadToEnd();                
        }
        else
        {
            $response = $null;
        }
    }    

    return $response;
}

$contentType = "application/x-www-form-urlencoded"
$overrideContentType = $null
$useXRequestWith = $false

function DoHttpSendAction($action, $url, $post, $strCookies )
{
    if ($post.GetType().Name -eq "Byte[]")
    {
        $buf = $post;
    }
    else
    {
        $encoding = new-object system.text.asciiencoding;
        $buf = $encoding.GetBytes($post);
    }
    
    $uri = new-object uri($url);
    $httpReq = [system.net.HttpWebRequest]::Create($uri)
    $httpReq.AllowAutoRedirect = $false
    $httpReq.method = $action;
    #$httpReq.Referer = ""
    $httpReq.contentlength = $buf.length

    $httpReq.ServicePoint.Expect100Continue = $false;

    $httpReq.Accept = "text/html, application/xhtml+xml, */*"
    #$httpReq.ContentType = "application/x-www-form-urlencoded"
    $httpReq.headers.Add("Accept-Language", "en-US")
    $httpReq.UserAgent = $global:defaultUserAgent;

    #allow us to override the cookies if we have done so...
    if ($strCookies)
    {
        $httpReq.Headers.add("Cookie", $strCookies);
    }
    else
    {
        $cookie = GetCookies($url);

        if (![string]::IsNullOrEmpty($cookie))
        {
            $httpreq.Headers.Add("Cookie", $cookie);
        }    
    }

    if ($global:referer)
    {
        $httpReq.Referer = $global:referer;
        $global:referer = $null;
    }

    if ($global:useragent)
    {
        $httpReq.useragent = $global:useragent;
        $global:useragent = $null;
    }
    
    if ($global:overrideContentType)
    {
        $httpReq.ContentType = $overrideContentType
        $global:overrideContentType = $null
    }
    else
    {
        $httpReq.ContentType = "application/x-www-form-urlencoded"
    }

    if ($global:accept)
    {
        $httpReq.Accept = $global:accept;
        $global:accept = $null;
    }

    if ($digest)
    {
        $httpReq.headers.Add("X-RequestDigest", $digest)
    }

    if ($useXRequestWith)
    {
        $httpReq.headers.Add("X-Requested-With", "XMLHttpRequest")
        $useXRequestWith = $false
    }

    foreach($key in $global:headers.keys)
    {
        $httpReq.Headers.add($key, $global:headers[$key]);
    }

    $global:headers.Clear();
    
    $stream = $httpReq.GetRequestStream()

    [void]$stream.write($buf, 0, $buf.length)
    $stream.close()

    [string]$results = ProcessResponse $httpReq;       

    return $results
}

function DoPost($url, $post, $strCookies )
{    
    $global:fileBuffer = $null;  
    DoHttpSendAction "POST" $url $post $strCookies
}

function DoDelete($url, $post, $strCookies )
{    
    $global:fileBuffer = $null;  
    DoHttpSendAction "DELETE" $url $post $strCookies
}

function DoPut($url, $post, $strCookies )
{    
    $global:fileBuffer = $null;  
    DoHttpSendAction "PUT" $url $post $strCookies
}

