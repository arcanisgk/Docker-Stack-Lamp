#=========================================#
# Method Designer

function Get-AddCyanLine {
    Write-Host "`n ============================================================================" -ForegroundColor "Cyan"
}

function Get-TittleScreen {
    Write-Host "`n Environment Installer and Setup."  -ForegroundColor "Red"
    Get-AddCyanLine
}

function Get-AddTask {
    Write-Host "`n [New-Task] " -ForegroundColor "DarkYellow" -NoNewline
}

function Get-EndTask {
    Write-Host "`n [Successfully] " -ForegroundColor "Green" -NoNewline
}

function Get-Pause {
    Read-Host "`n Press Enter to continue"
}

function Get-ErrorOutput {
    param (
        [string]$code,
        [string]$smg
    )
    Write-Host "`n ============================================================================" -ForegroundColor "Red"
    Write-Host " Error Code $code" -ForegroundColor "Red" -NoNewline
    Write-Host ":`n Cannot continue with the installation." -ForegroundColor "Red"
    Write-Host " $smg" -ForegroundColor "Red"
    Write-Host " ============================================================================" -ForegroundColor "Red"

    # add to log

    Get-Pause
    Exit 0
}

#=========================================#
# Method helpers

function Get-NewProcess {
    $scriptPath = $MyInvocation.MyCommand.ScriptBlock.File
    Start-Process -FilePath 'powershell' -ArgumentList ('-File', $scriptPath) -Verb RunAs -WindowStyle Maximized
    Exit 0
}

function Get-Administrator {
    $isAdministrator = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) {
        Get-NewProcess
    } else {
        Set-ExecutionPolicy Bypass -Scope Process -Force;
    }
}

function Install-Prerequisite{
    param (
        [boolean]$security
    )
    if($security){
        [Console]::Clear()
        Get-TittleScreen
        Write-Host "`n Validation and Installation of Prerequisites.`n"  -ForegroundColor "Red"
        $checkCoco = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { "$env:PROGRAMDATA\chocolatey" }
        if (-not (Test-Path $checkCoco)) {
            Get-AddTask; Write-Host "Downloading and installing Chocolatey...`n"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) > $null
            Get-EndTask; Write-Host "Chocolatey is Installed !!! But you need restart the Script Execution.`n"  -ForegroundColor "Red"
            Get-Pause
            Get-NewProcess # need restart the Script
        } else {
            Get-EndTask; Write-Host "Chocolatey is Installed !!!"
        }
        $checkMkcert = "$env:PROGRAMDATA\chocolatey\bin\mkcert.exe"
        if (-not (Test-Path $checkMkcert)) {
            Get-AddTask; Write-Host "Downloading and installing mkcert...`n"
            choco install mkcert >> run.log 2>&1
            mkcert -install >> run.log 2>&1
            Get-EndTask; Write-Host "mkcert is Installed !!!"
        } else {
            Get-EndTask; Write-Host "mkcert is Installed !!!"
        }
        Get-AddCyanLine
        Get-Pause
    }
}

#=========================================#
# Method Core

function Get-Security {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Would you like to enable HTTPS and WSS protocols via SSL (default: No)."  -ForegroundColor "Red"
    Write-Host " Note: if yes, this will open port: 443; otherwise only port 80 would work."
    Write-Host "`n => 1. No. (press any Key)."
    Write-Host " => 2. Yes (press Y or 2)."
    Get-AddCyanLine; $choice = Read-Host " Choose option 1 or 2 (Press any key for default: 1/No)"
    if ($choice -eq "2" -or $choice -eq "Y" -or $choice -eq "y") {
        return $true
    } else {
        return $false
    }
}

function Get-DefaultOrCustom {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Configure custom URL to use locally."  -ForegroundColor "Red"
    Write-Host " Note: At this point you will decide if you want to use custom URL or the ones that Stack uses by default."
    Write-Host "`n => 1. Use the default URL [ lh-stack.dock ]"
    Write-Host " => 2. Indicate the URL you want to Implement."
    Get-AddCyanLine
    $choice = Read-Host " Choose option 1 or 2 (Press any key for default: 1)"
    if ($choice -eq "2") {
        return $false
    } else {
        return $true
    }
}

function Get-Url {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Indicate here a URL to use."
    Write-Host " Example: [myapp]`n result: myapp.dock"
    Get-AddCyanLine
    Write-Host " ==> : " -NoNewline -ForegroundColor "Red"
    return Read-Host
}

function Get-UrlConfirm {
    param (
        [PSCustomObject]$Urls
    )
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Confirmation URL."  -ForegroundColor "Red"
    Write-Host " You have requested the configuration of custom URL:"
    Write-Host "`n Main Url: $($Urls.main_url)" -ForegroundColor "Yellow"
    Write-Host " PhpMyAdmin: $($Urls.pma_url)" -ForegroundColor "Yellow"
    Write-Host " crontab-ui: $($Urls.cron_url)" -ForegroundColor "Yellow"
    Write-Host " Note: keep in mind that pma and cron are static url on stack."
    Write-Host "`n => press [Y]es or any key to confirm and continue."
    Write-Host " => press [N]o to set it again."
    Get-AddCyanLine
    Write-Host " ==>" -NoNewline -ForegroundColor "Red"
    $choice = Read-Host
    if ($choice -eq "N") {
        return $true
    } else {
        return $false
    }
}

function Set-DirectoryForSSL {
    param(
        [string]$certPath
    )
    if (-not (Test-Path -Path $certPath -PathType Container)) {
        $null = New-Item -Path $certPath -ItemType Directory -Force | Out-Null
    }
}

function Get-SslCerts {
    param (
        [PSCustomObject]$Urls
    )
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n SSL certificates are required for this instance."  -ForegroundColor "Red"
    Get-AddTask; Write-Host "Generating Certificates with mkcert..."
    if($Urls.main_url -eq $Urls.stack_url) {
        $site = $Urls.main_url
        $certPath = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/ssl/$site/"
        Set-DirectoryForSSL -certPath $certPath
        mkcert -cert-file "$certPath$site.crt" -key-file "$certPath$site.key" "$site" "*.$site" >> run.log 2>&1
    } else {
        $site1 = $Urls.main_url
        $certPath1 = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/ssl/$site1/"
        Set-DirectoryForSSL -certPath $certPath1
        mkcert -cert-file "$certPath1$site1.crt" -key-file "$certPath1$site1.key" "$site1" "*.$site1" >> run.log 2>&1
        $site2 = $Urls.stack_url
        $certPath2 = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/ssl/$site2/"
        if (-not (Test-Path -Path $certPath2 -PathType Container)) {
            Set-DirectoryForSSL -certPath $certPath2
            mkcert -cert-file "$certPath2$site2.crt" -key-file "$certPath2$site2.key" "$site2" "*.$site2" >> run.log 2>&1
        }
    }
    Get-EndTask; Write-Host "SSL Certificates Generated!!!!!!"
    Get-AddCyanLine
    Get-Pause
}

function Set-Destination {
    param (
        [string]$dockroot
    )
    $sourceFile = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/public/index.php"
    $destinationPath = Join-Path -Path $scriptDirectory -ChildPath "/project/$dockroot"
    if (-not (Test-Path -Path $destinationPath -PathType Container)) {
        $null = New-Item -Path $destinationPath -ItemType Directory | Out-Null
    }
    Copy-Item -Path $sourceFile -Destination $destinationPath -Recurse
}

function Get-DirectoryRoot {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Set your DocumentRoot directory."  -ForegroundColor "Red"
    Write-Host " You have requested the configuration of custom URLs:"
    Write-Host "`n => 1. Base to (/)        Like: Apache, CodeIgniter"
    Write-Host " => 2. Base to (/public)  Like: Laravel, Symfony"
    Write-Host " => 3. Set your Custom    Like: Yii (web), CakePHP (webroot)"
    Get-AddCyanLine
    $choice = Read-Host " Choose option 1, 2, 3 (Press any key for default: 1)"
    if ($choice -eq "2") {
        $sourcePath = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/public"
        $destinationPath = Join-Path -Path $scriptDirectory -ChildPath "/project"
        Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse
        Get-Pause
        return "/public"
    } elseif($choice -eq "3") {
        Get-AddCyanLine
        Write-Host "`n Set your Custom Name Folder."  -ForegroundColor "Red"
        Write-Host " Note: if it not exists, it would be created."
        Write-Host " ==>" -NoNewline -ForegroundColor "Red"
        $dockroot = Read-Host
        Set-Destination -dockroot $dockroot
        Get-Pause
        return "/$dockroot"
    } else {
        $sourceFile = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/public/index.php"
        $destinationPath = Join-Path -Path $scriptDirectory -ChildPath "/project"
        if (-not (Test-Path -Path $destinationPath -PathType Container)) {
            $null = New-Item -Path $destinationPath -ItemType Directory | Out-Null
        }
        Copy-Item -Path $sourceFile -Destination $destinationPath -Recurse
        Get-Pause
        return "/"
    }
}

function Get-PhpVersion {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n PHP Version.`n"  -ForegroundColor "Red"
    Write-Host " Choose one of these PHP versions to be installed:"
    Write-Host "`n => 1. v7.2"
    Write-Host " => 2. v7.4"
    Write-Host " => 3. v8.0"
    Write-Host " => 4. v8.1"
    Write-Host " => 5. v8.2`n"
    $choice = Read-Host " Choose option 1, 2, 3, 4 or 5 (Press any key for default: 5)"
    if ($choice -eq "1") {
        return "7.2"
    } elseif($choice -eq "2") {
        return "7.4"
    } elseif($choice -eq "3") {
        return "8.0"
    } elseif($choice -eq "4") {
        return "8.1"
    } else {
        return "8.2"
    }
}

function Get-DataBase {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Configure Database Credentials.`n"  -ForegroundColor "Red"
    $confirm = $true
    while ($confirm) {
        $username = Read-Host " Set username"
        if($username -ne "" -and $username.Length -ge 5){
            $confirm = $false
        } else {
            Get-AddCyanLine
            Write-Host "`n Username must have a minimum of 5 characters"
        }
    }
    $confirm = $true
    while ($confirm) {
        $pass1 = Read-Host " Set password" -AsSecureString
        $pass2 = Read-Host " Confirm password" -AsSecureString
        $passPl1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1))
        $passPl2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2))
        if($passPl1 -eq $passPl2 -and $passPl1.Length -ge 8){
            $confirm = $false
        }else{
            Get-AddCyanLine
            Write-Host "`n Passwords must be the same and must have a minimum of 8 characters"
            Write-Host " Wrong: $passPl1 != $passPl2"
        }
    }
    Get-EndTask; Write-Host " Captured Database Credentials!!!"
    Get-AddCyanLine
    Get-Pause
    return New-Object PSObject -Property @{
        Username = $username
        Password = $passPl1
    }
}

function Get-DevEmail {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Indicate here your Development e-mail."
    Write-Host " ==> " -NoNewline -ForegroundColor "Red"
    $email = Read-Host
    Get-EndTask; Write-Host " Captured development e-mail!!!"
    Get-AddCyanLine
    Get-Pause
    return $email
}

function Set-EnvironmentVariables {
    param (
        [PSCustomObject]$Urls,
        [PSCustomObject]$dbConfig,
        [string]$email,
        [string]$dockroot,
        [string]$phpVersion
    )
    Get-AddTask; Write-Host "Search and Organization of Environment Variables..."
    $project_name = [System.IO.Path]::GetFileNameWithoutExtension($Urls.main_url)
    $project_name_Uppercase = $project_name.ToUpper()
    [System.Environment]::SetEnvironmentVariable("LH_SYSTEM_NAME", $project_name, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_PROJECT_NAME", $project_name_Uppercase, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_MAIN_WEB", $Urls.main_url, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_PMA_WEB", $Urls.pma_url, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_CRONTAB_DOMAIN", $Urls.cron_url, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_MYSQL_USER", $dbConfig.Username, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_MYSQL_PASSWORD", $dbConfig.Password, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_DEV_MAIL", $email, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_DOCUMENT_ROOT", $dockroot, [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable("LH_PHP_VERSION", $phpVersion, [System.EnvironmentVariableTarget]::Process)
    Get-EndTask; Write-Host " --> Project Name: " -ForegroundColor "Cyan" -NoNewline
    Write-Host "$project_name_Uppercase ($project_name)" -ForegroundColor "Yellow"
    $envFilePath = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/other/tpl.dev.env"
    Get-AddTask; Write-Host "Found the .env template file in the following location:"
    Write-Host " --> Location: " -ForegroundColor "Cyan" -NoNewline
    Write-Host "$((Get-Item -Path $envFilePath).FullName)" -ForegroundColor "Yellow"
    Get-AddTask; Write-Host "Processing template file to get environment variables..."
    Write-Host " Progress: " -NoNewline
    $envFileContent = Get-Content $envFilePath -Raw
    $envFileNewContent = ""
    $envFileContentLines = [Regex]::Split($envFileContent, "\r\n|\n")
    $character = [char]::ConvertFromUtf32(0x2588)
    $expressionRegular = '\$\{([^}]*)\}'
    $envFileContentLines| ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^([^#=]+)=(.*)$') {
            $Key = $Matches[1]
            $Value = $Matches[2]
            $coincidencias = [System.Text.RegularExpressions.Regex]::Matches($Value, $expressionRegular)
            foreach ($coincidencia in $coincidencias) {
                $textoEncontrado = $coincidencia.Groups[1].Value
                if ([System.Environment]::GetEnvironmentVariable($textoEncontrado)) {
                    $newValue = [System.Environment]::GetEnvironmentVariable($textoEncontrado)
                    $newValue = $newValue.Trim()
                    $line = $line.Replace($coincidencia, $newValue)
                }
            }
            $partes = $line.Split('=')
            $parte2 = $partes[1]
            [System.Environment]::SetEnvironmentVariable($Key, $parte2, [System.EnvironmentVariableTarget]::Process)
        }
        $envFileNewContent += $line+"`n"
        Write-Host "$character" -ForegroundColor "DarkCyan" -NoNewline
    } -End {
        Write-Host " 100%"
    }
    $outputFilePath = Join-Path -Path $scriptDirectory -ChildPath "/docker/.env"
    $envFileNewContent = $envFileNewContent -replace "(\r?\n)+\z", ""
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($outputFilePath, $envFileNewContent, $Utf8NoBomEncoding)
    Write-Host " --> File Create: " -ForegroundColor "Cyan" -NoNewline
    Write-Host ".env" -ForegroundColor "Red"
    Get-EndTask; Write-Host " --> File has been expanded environment variables."
}

function Get-DockerComposeYml {
    $directorio = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/yml"
    $archivos = Get-ChildItem -Path $directorio -Filter *.yml
    foreach ($archivo in $archivos) {
        $file = $archivo.Name
        $ymlFilePath = $archivo.FullName
        Get-AddTask; Write-Host "Found the YML template file in the following location:"
        Write-Host " --> " -NoNewline
        Write-Host "$((Get-Item -Path $ymlFilePath).FullName)" -ForegroundColor "Yellow"
        Get-AddTask; Write-Host "Processing template file to get the docker set up..."
        $ymlFileContent = Get-Content $ymlFilePath -Raw
        $ymlFileNewContent = ""
        $ymlFileContentLines = [Regex]::Split($ymlFileContent, "\r\n|\n")
        Write-Host " Progress: " -NoNewline
        $character = [char]::ConvertFromUtf32(0x2588)
        $expressionRegular = '\$\{([^}]*)\}'
        $i = 1
        $ymlFileContentLines| ForEach-Object {
            $line = $_
            $coincidencias = [System.Text.RegularExpressions.Regex]::Matches($line, $expressionRegular)
            if($coincidencias.Count -gt 0){
                Write-Host "$character" -ForegroundColor "DarkCyan" -NoNewline
            }
            foreach ($coincidencia in $coincidencias) {
                $textoEncontrado = $coincidencia.Groups[1].Value
                if ([System.Environment]::GetEnvironmentVariable($textoEncontrado)) {
                    $newValue = [System.Environment]::GetEnvironmentVariable($textoEncontrado)
                    $line = $line.Replace($coincidencia, $newValue)
                }
            }
            $ymlFileNewContent += $line+"`n"
            $i++
        } -End {
            Write-Host " 100%"
        }
        $outputFilePath = Join-Path -Path $scriptDirectory -ChildPath "/docker/$file"
        $ymlFileNewContent = $ymlFileNewContent -replace "(\r?\n)+\z", ""
        $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::WriteAllLines($outputFilePath, $ymlFileNewContent, $Utf8NoBomEncoding)
        Write-Host " --> File Create: " -NoNewline
        Write-Host "$file" -ForegroundColor "Red"
        Get-EndTask; Write-Host " --> File has been expanded environment variables."
    }
}

function Get-VhostFile {
    $file = "/docker/tpl/other/tpl.vhost.conf"
    $vhostFilePath = Join-Path -Path $scriptDirectory -ChildPath $file
    Get-AddTask; Write-Host "Found the VHost template file in the following location:"
    Write-Host " --> " -NoNewline
    Write-Host "$((Get-Item -Path $vhostFilePath).FullName)" -ForegroundColor "Yellow"
    Get-AddTask; Write-Host "Processing template file to get the VHost set up..."
    $vhostFileContent = Get-Content $vhostFilePath -Raw
    $vhostFileNewContent = ""
    $vhostFileContentLines = [Regex]::Split($vhostFileContent, "\r\n|\n")
    Write-Host " Progress: " -NoNewline
    $character = [char]::ConvertFromUtf32(0x2588)
    $expressionRegular = '\$\{([^}]*)\}'
    $i = 1
    $vhostFileContentLines| ForEach-Object {
        $line = $_
        $coincidencias = [System.Text.RegularExpressions.Regex]::Matches($line, $expressionRegular)
        Write-Host "$character" -ForegroundColor "DarkCyan" -NoNewline
        foreach ($coincidencia in $coincidencias) {
            $textoEncontrado = $coincidencia.Groups[1].Value
            if ([System.Environment]::GetEnvironmentVariable($textoEncontrado)) {
                $newValue = [System.Environment]::GetEnvironmentVariable($textoEncontrado)
                $line = $line.Replace($coincidencia, $newValue)
            }
        }
        $vhostFileNewContent += $line+"`n"
        $i++
    } -End {
        Write-Host " 100%"
    }
    $outputFilePath = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/vhost/vhost.conf"
    $vhostFileNewContent = $vhostFileNewContent -replace "(\r?\n)+\z", ""
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($outputFilePath, $vhostFileNewContent, $Utf8NoBomEncoding)
    Write-Host " --> File Create: " -NoNewline
    Write-Host "vhost.conf" -ForegroundColor "Red"
    Get-EndTask; Write-Host " --> File has been expanded environment variables."
}

function Set-NetWorkEnvironment {
    param (
        [PSCustomObject]$Urls
    )
    Get-AddTask;Write-Host "Applying network settings for Local URLs..."
    $hosts_file = "${env:SystemRoot}\System32\drivers\etc\hosts"
    $current_content = Get-Content $hosts_file -Raw
    $lines = $current_content -split "`r`n"
    $start_marker = "# Developer Area Docker"
    $end_marker = "# End of Area"
    $startIndex = [array]::IndexOf($lines, $start_marker)
    if ($startIndex -ge 0) {
        $endIndex = [array]::IndexOf($lines, $end_marker, $startIndex)
        if ($endIndex -lt 0) {
            $endIndex = $lines.Length - 1
        }
        $newEntries = @("127.0.0.1 $($Urls.main_url)", "127.0.0.1 $($Urls.pma_url)", "127.0.0.1 $($Urls.cron_url)")
        $existingEntries = $lines[($startIndex + 1)..$endIndex]
        $entriesToAdd = $newEntries | Where-Object { $_ -notin $existingEntries }
        $lines = $lines[0..$startIndex] + $entriesToAdd + $lines[($startIndex + 1)..($lines.Length - 1)]
    } else {
        $lines += $start_marker
        $lines += "127.0.0.1 $($Urls.main_url)"
        $lines += "127.0.0.1 $($Urls.pma_url)"
        $lines += "127.0.0.1 $($Urls.cron_url)"
        $lines += $end_marker
    }
    $updated_content = $lines -join "`r`n"
    Set-Content -Path $hosts_file -Value $updated_content
    Get-EndTask
    Write-Host " --> Updated operating system hosts file."
    Get-Pause
}

function Set-DockerNetwork{
    $networkName = "lamp-network"
    $redExistente = docker network ls --filter "name=$networkName" --format '{{.Name}}'
    if (-not ($redExistente -contains $networkName)) {
        docker network create --driver bridge $networkName
    }
}

function Get-DockerInstall {
    param (
        [boolean]$security,
        [PSCustomObject]$Urls,
        [PSCustomObject]$StaticContainers
    )
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n Automatic Docker Installation Interface" -ForegroundColor "Red"
    Get-AddTask; Write-Host "The docker service is being validated..."
    $dockerIsRunning = (docker ps 2>&1) -match '^(?!error)'
    if ($dockerIsRunning){
        Write-Host " --> The Docker Desktop and Service is running."
    } else {
        Get-ErrorOutput -code "0002" -smg "You must install and open Docker manually before using this program."
    }
    $env:DOCKER_HOST = "tcp://localhost:2375"
    $path = Join-Path -Path $scriptDirectory -ChildPath "/docker/"
    $stackName = [System.Environment]::GetEnvironmentVariable('LH_SYSTEM_NAME')
    Set-DockerNetwork
    Get-AddTask; Write-Host "List containers to be installed...`n`n"
    $files = ""
    $tobeInstalled = ""
    foreach ($container in $StaticContainers.PSObject.Properties) {
        $containerName = $container.Name
        $file = $container.Value
        $containerExist = docker ps --filter "name=$containerName" --format '{{.Names}}'
        if (-not ($containerExist -contains $containerName)) {
            $files +=" -f $path$file.yml"
            $tobeInstalled +="`n $containerName"
        }
    }
    $webserver = "webserver.yml"
    $files +=" -f $path$webserver"
    $tobeInstalled +="`n Web-Server"
    Write-Host " Container to be Installed:"
    Write-Host $tobeInstalled
    Get-EndTask; Write-Host " --> List Analyzed and Completed!!!"
    $files = $files.Trim()
    $command = "docker-compose -p $stackName $files up -d --build"
    $postInstall = $false
    if (-not ($command -like "*nginx*")) {
        $postInstall = $true
    }
    Get-AddTask; Write-Host "Starting the downloading of image and construction of containers...`n`n"
    Invoke-Expression -Command $command
    Get-EndTask; Write-Host " --> Installation completed successfully!!!"
    if($postInstall){
        Get-AddTask; Write-Host "Starting the Post-Installation...`n`n"
        $sslLocalPath = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/ssl/$($Urls.main_url)/*"
        $command2 = "docker cp $sslLocalPath Proxy-Server:/etc/nginx/certs/"
        Invoke-Expression -Command $command2
        Get-EndTask; Write-Host " --> Post-Installation completed successfully!!!"
    }
    Get-Pause
}

function Set-Shortcut {
    param (
        [string]$protocol,
        [PSCustomObject]$urls
    )
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    foreach ($urlTemp in $urls.PSObject.Properties) {
        $site = $urlTemp.Name
        $url = $urlTemp.Value
        $websiteName = [System.IO.Path]::GetFileNameWithoutExtension($url)
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut("$desktopPath\$websiteName.lnk")
        $shortcut.TargetPath = "$protocol$url"
        $iconPath = Join-Path -Path $scriptDirectory -ChildPath "/docker/tpl/icon/$site.ico"
        $shortcut.IconLocation = $iconPath
        $shortcut.Save()
    }
}


function Get-SuccessfulInstall {
    param (
        [string]$protocol,
        [PSCustomObject]$urls,
        [PSCustomObject]$dbConfig,
        [string]$email,
        [string]$dockroot
    )
    [Console]::Clear()
    Get-TittleScreen
    Set-Shortcut -urls $urls -protocol $protocol
    Write-Host "`n Docker LAMP Stack Installation Summary" -ForegroundColor "Red"
    Write-Host "`n Main Web Server URL: " -NoNewline
    Write-Host $protocol$($Urls.main_url) -ForegroundColor "Yellow"
    Write-Host " phpMyAdmin URL:      " -NoNewline
    Write-Host $protocol$($Urls.pma_url) -ForegroundColor "Yellow"
    Write-Host " phpMyAdmin URL:      " -NoNewline
    Write-Host $protocol$($Urls.cron_url) -ForegroundColor "Yellow"
    Write-Host " DB user:             " -NoNewline
    $user = $dbConfig.Username
    Write-Host $user -ForegroundColor "Yellow"
    Write-Host " DB password:         " -NoNewline
    Write-Host "********" -ForegroundColor "Yellow"
    Write-Host " Dev e-mail:         " -NoNewline
    Write-Host $email -ForegroundColor "Yellow"
    Get-AddCyanLine
    Write-Host "`n There are new desktop shortcuts to development urls." -ForegroundColor "Red"
    Get-AddCyanLine
    Write-Host "`n To develop code, the Windows path has been set to:" -ForegroundColor "Red"
    Write-Host "`n Project Root (all code):"
    Write-Host " "$([char]::ConvertFromUtf32(0x21B3))$(Join-Path -Path $scriptDirectory -ChildPath "/project") -ForegroundColor "Yellow"
    Write-Host " Document Root (entry point)"
    if($dockroot -eq " /") {
        $dockroot="";
    }
    $dockroot = $dockroot.Trim()
    Write-Host " "$([char]::ConvertFromUtf32(0x21B3))$(Join-Path -Path $scriptDirectory -ChildPath "/project$dockroot")  -ForegroundColor "Yellow"
    Get-AddCyanLine
}

function Get-Welcome {
    [Console]::Clear()
    Get-TittleScreen
    Write-Host "`n You must Read and Accept this before Continuing."  -ForegroundColor "Red"
    Get-AddCyanLine
    Write-Host "`n Welcome to Docker-Stack-Lamp, the purpose of this application"
    Write-Host " is to guide you in the installation of the Docker-based"
    Write-Host " Stack Lamp, keep the following in mind:"
    Write-Host "`n   1. Let's configure some necessary parameters." -ForegroundColor "Yellow"
    Write-Host "   2. We will modify your System Host file." -ForegroundColor "Yellow"
    Write-Host "   3. Local Urls." -ForegroundColor "Yellow"
    Write-Host "   4. We will create a Proxy, MySql and phpMyAdmin container." -ForegroundColor "Yellow"
    Write-Host "   5. You could also run this process several times to create " -ForegroundColor "Yellow"
    Write-Host "      new containers to host web projects based on a LAMP stack." -ForegroundColor "Yellow"
    Write-Host "`n For more information you can visit the site on github:"
    Write-Host " https://github.com/arcanisgk/Docker-Stack-Lamp"
    Get-AddCyanLine
    Write-Host "`n If you do not agree with what is indicated here,"
    Write-Host " you should close this terminal."  -ForegroundColor "Red"
    Get-AddCyanLine
    Get-Pause
}

#=========================================#
# Environment Preparation

[Console]::Clear()
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "|| Environment Installer and Setup ||"
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -Path $scriptDirectory
$Urls = New-Object PSObject -Property @{
    "main_url" = ""
    "stack_url" = "lh-stack.dock"
    "pma_url" = "pma.lh-stack.dock"
    "cron_url" = ""
}
$StaticContainers = New-Object PSObject -Property @{
    "MySql-Server" = "db"
    "Proxy-Server" = ""
}

#=========================================#
# Execution

Get-Administrator
$summaryPath = Join-Path -Path $scriptDirectory -ChildPath "/summary.txt"
Start-Transcript -Path $summaryPath  >> run.log 2>&1
Get-Welcome
$security = Get-Security
Install-Prerequisite -security $security
if (Get-DefaultOrCustom -eq $true) {
    $Urls.main_url = $Urls.stack_url
    $Urls.cron_url = "cron.$($Urls.main_url)"
} else {
    $confirm = $true
    while ($confirm) {
        $main_url = Get-Url
        $Urls.main_url = "$main_url.dock"
        $Urls.cron_url = "cron.$main_url.dock"
        $confirm = Get-UrlConfirm -Urls $Urls
    }
}

if($security) {
    $protocol="https://"
    $StaticContainers."Proxy-Server" = "nginx.ssl"
    Get-SslCerts -Urls $Urls
} else {
    $StaticContainers."Proxy-Server" = "nginx"
    $protocol="http://"
}

$dockroot = Get-DirectoryRoot
$dockroot = $dockroot.Trim()
$phpVersion = Get-PhpVersion
$dbConfig = Get-DataBase
$email = Get-DevEmail
[Console]::Clear()
[System.Console]::CursorVisible = $false
Get-TittleScreen
Write-Host "`n Starting the Installation of the Docker Development Environment" -ForegroundColor "Red"
Set-EnvironmentVariables -Urls $Urls -dbConfig $dbConfig -email $email -dockroot $dockroot -phpVersion $phpVersion
$file = Join-Path -Path $scriptDirectory -ChildPath "/docker/.env"

if (Test-Path $file) {
    Get-DockerComposeYml -security $security
    $file1 = Join-Path -Path $scriptDirectory -ChildPath "/docker/db.yml"
    $file2 = Join-Path -Path $scriptDirectory -ChildPath "/docker/nginx.yml"
    $file3 = Join-Path -Path $scriptDirectory -ChildPath "/docker/nginx.ssl.yml"
    $file4 = Join-Path -Path $scriptDirectory -ChildPath "/docker/webserver.yml"
    if ((Test-Path $file1) -and (Test-Path $file2) -and (Test-Path $file3) -and (Test-Path $file4)) {
        Get-VhostFile
        $file = Join-Path -Path $scriptDirectory -ChildPath "/docker/config/vhost/vhost.conf"
        if (Test-Path $file) {
            Set-NetWorkEnvironment -Urls $Urls
            Get-DockerInstall -security $security -Urls $Urls -StaticContainers $StaticContainers
            Get-SuccessfulInstall -protocol $protocol -Urls $Urls -dbConfig $dbConfig -email $email -dockroot $dockroot
        }else{
            Get-ErrorOutput -code "0001" -smg "Could not find virtual host configuration file."
        }
    } else {
        Get-ErrorOutput -code "0001" -smg "The Compose file for Docker was not found."
    }
} else {
    Get-ErrorOutput -code "0001" -smg "The environment variables file was not found."
}
[System.Console]::CursorVisible = $true
Stop-Transcript  >> run.log 2>&1
Get-Pause