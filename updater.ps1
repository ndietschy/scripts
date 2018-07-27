<# Ce script s'occupe de mettre à jour les logiciels suivants : 
 - Wireshark
 - FileZilla client
 - Notepad++
 - Keepass
 - Java
 - ccleaner
 - firefox
#>
# Pour accéder aux sites https (utilisé pour ccleaner)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if($array){Clear-Variable array}


# Logiciels à mettre à jour :
[boolean]$wiresharkCheck = $true  ;  $wiresharkURL = "https://www.wireshark.org/download.html"      ;  $wiresharkParam = "/S"
[boolean]$fileZilaCheck  = $true  ;  $filezilaURL  = "https://filezilla-project.org/download.php"   ;  $fileZilaParam  = "/S"
[boolean]$notepadCheck   = $true  ;  $notepadURL   = "https://notepad-plus-plus.org/repository"     ;  $notepadParam   = "/S"
[boolean]$keepassCheck   = $true  ;  $keepassURL   = "https://keepass.info/download.html"           ;  $keepassParam   = "/VERYSILENT"
[boolean]$ccleanerCheck  = $true  ;  $ccleanerURL  = "https://filehippo.com/fr/download_ccleaner"   ;  $ccleanerParam  = "/S"
#[boolean]$coretempCheck  = $false  ;  $coretempURL  = "https://www.alcpu.com/CoreTemp"               ;  $coretempParam  = ""
#[boolean]$7zipCheck      = $false  ;  $7zipURL      = "https://www.alcpu.com/CoreTemp"               ;  $7zipParam      = ""
[boolean]$javaCheck      = $true  ;  $javaURL       = "https://www.java.com/fr/download/manual.jsp"  ;  $javaParam      = "/s"          ;   $javaKeepOldVersion = "no"

$chromePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
$downloadPath = "$env:USERPROFILE\Downloads"


# Si la récupération via Get-ItemProperty échoue, on passe par la commande reg 
Function Get-Programs(){
    Write-Host "Appel de la fonction Get-Programs"

    if(Test-Path "$PSScriptRoot\32.reg"){Remove-Item $PSScriptRoot\32.reg} ; if(Test-Path "$PSScriptRoot\64.reg"){Remove-Item $PSScriptRoot\64.reg}
    
    reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall $PSScriptRoot\32.reg ; reg export HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall $PSScriptRoot\64.reg

    Start-Sleep -Seconds 1

    $fichier = Get-Content $PSScriptRoot\32.reg,$PSScriptRoot\64.reg ; $i=0 ; $array=@()

    foreach($line in $fichier){
        if($line.StartsWith('[')){ $object = New-Object –TypeName psobject }
        elseif($line.StartsWith('"DisplayName')){ $object | Add-Member –MemberType NoteProperty -Name "DisplayName"  –Value "$($($line.Split('=')[-1]).replace('"',''))" -ErrorAction SilentlyContinue }
        elseif($line.StartsWith('"DisplayVersion')){ $object | Add-Member –MemberType NoteProperty -Name "DisplayVersion"  –Value "$($($line.Split('=')[-1]).replace('"',''))" -ErrorAction SilentlyContinue }
        elseif($line -eq ""){ if($object.DisplayName -match "[a-z]"){ $array += $object }}  
    }
    return $($array | Sort-Object)
}




# Récupération des programmes
try{ $array=Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" ; $array+=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Sort-Object -Descending }
catch{ $array=Get-Programs }



# Parcours de la liste des logiciels présents sur le PC
foreach($_ in $array){

    if($wiresharkCheck -and $_.displayName -and $_.displayName.contains("Wireshark")){
        Write-Host -NoNewline "$($_.displayName)        -->  " ;$PCversion=$_.DisplayVersion

        $geturl=Invoke-WebRequest "$wiresharkURL"
        $urls=$geturl.ParsedHtml.body.getElementsByTagName('a') | Where-Object {$_.getAttributeNode('class').Value -eq 'accordion-toggle'}
        $onlineVersion=$urls[0].textContent.Split(" ")[-1] ;$onlineVersion=$onlineVersion.Substring(1,$($onlineVersion.Length)-2)

        if($PCversion -ne $onlineVersion){
            Write-Host -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion Téléchargement en cours ..."
            Invoke-WebRequest -Uri https://1.eu.dl.wireshark.org/win64/Wireshark-win64-$onlineVersion.exe -OutFile $downloadPath\wireshark-win64-$onlineVersion.exe
            Start-Process $downloadPath\wireshark-win64-$onlineVersion.exe -ArgumentList "$wiresharkParam" -Wait -PassThru
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la derniène version" }
    }   
    
    elseif($fileZilaCheck -and $_.displayName -and $_.displayName.contains("FileZilla Client")){
        Write-Host -NoNewline "$($_.displayName)       -->  "
        $PCversion=$_.DisplayVersion

        $geturl=Invoke-WebRequest "$filezilaURL"               
        $onlineVersion=$($geturl.ParsedHtml.body.getElementsByTagName('p') | Where-Object {if($_.innerHTML){ $_.innerHTML.contains('stable')}}).innerHTML.split(" ")[-1]
        

        if($PCversion -ne $onlineVersion){
            Write-Host -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion Téléchargement en cours ..."
            $link=$geturl.ParsedHtml.getElementById("quickdownloadbuttonlink").href
            Invoke-WebRequest -Uri $link -OutFile $downloadPath\$($link.split("/")[-1])            
            Start-Process $downloadPath\$($link.split("/")[-1]) -ArgumentList "$fileZilaParam" -Wait -PassThru
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la dernière version"}

    }

    elseif($notepadCheck -and $_.displayName -and $_.displayName.contains("Notepad")){
        Write-Host -NoNewline "$($_.displayName)        -->  "
        $PCversion=$_.DisplayVersion
        $geturl=Invoke-WebRequest https://notepad-plus-plus.org/
        $urls=$geturl.ParsedHtml.body.getElementsByTagName('li') | Where-Object  {$_.getAttributeNode('class').Value -eq 'first'}
        $onlineVersion=$urls.innerText.Split(" ")[1]
        $major=$onlineVersion.split(".")[0]

        if($PCversion -ne $onlineVersion){
            Write-Host -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion Téléchargement en cours ..."
            Invoke-WebRequest  $notepadURL/$major.x/$onlineVersion/npp.$onlineVersion.Installer.exe -OutFile $downloadPath\npp.$onlineVersion.Installer.exe
            Start-Process $downloadPath\npp.$onlineVersion.Installer.exe -ArgumentList "$notepadParam" -Wait -PassThru
                 
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la dernière version"}

    }

    elseif($keepassCheck -and $_.displayName -and $_.displayName.contains("KeePass")){
        $i = 0
        Write-Host -NoNewline "$($_.displayName)  -->  "
        $PCversion=$_.DisplayVersion
        $geturl=Invoke-WebRequest $keepassURL
        $onlineVersion=$($geturl.ParsedHtml.body.getElementsByTagName('th') | Where-Object  {$_.getAttributeNode('colSpan').Value -eq '2'}).innerHTML[0].split(" ")[-1]

        if($PCversion -ne $onlineVersion){
            Write-Host -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion Téléchargement en cours ..."
            $result = Invoke-WebRequest $keepassURL
            $link = $result.AllElements | Where-Object Class -eq "dlbtn"  | Select-Object -First 1 -ExpandProperty href
            Start-Process "$chromePath" -ArgumentList "$link" 
            Write-Host -ForegroundColor Cyan "Téléchargement de keepass pause de 20 secondes"
            
            while($i -lt 30 -and !($(Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]).FullName.Contains("KeePass") ){
                Write-Host "KeePass installer absent : $i secondes"
                Start-Sleep -Seconds 1 ; $i++
            }
            if($i -ne 30){ Start-Process "$($($(Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]).FullName)" -ArgumentList "$keepassParam" }
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la dernière version" }

    }

    elseif($ccleanerCheck -and $_.displayName -and $_.displayName.contains("CCleaner")){
        $i = 0
        Write-Host -NoNewline "$($_.displayName)  -->  "
        $PCversion=$_.DisplayVersion

        $result = Invoke-WebRequest $ccleanerURL
        $onlineVersion = $($result.AllElements | Where-Object Class -eq "title-text").innerText.split(" ")[1]


        if(!$onlineVersion.Contains("$PCversion") ){
            Write-Host -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion Téléchargement en cours ..."
            $dlLink=$result.AllElements | Where-Object Class -eq "program-header-download-link green button-link active long download-button"  | Select-Object -First 1 -ExpandProperty href
            Start-Process "$chromePath" -ArgumentList "$dlLink" 
            Write-Host -ForegroundColor Cyan "Téléchargement de CCleaner pause de 20 secondes"            
            while($i -lt 30 -and !($(Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]).FullName.Contains("ccsetup") ){
                Write-Host -NoNewline "$i "
                Start-Sleep -Seconds 1 ; $i++
            }
            if($i -ne 30){Write-Host "ok" ; Start-Process "$($($(Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]).FullName)" -ArgumentList "$ccleanerParam" }
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la dernière version"}
    }

    elseif($javaCheck -and $_.displayName -and $_.displayName -match "Java \d Update" ){
        Write-Host -NoNewline "$($_.displayName)  -->  "
        $PCversion=$_.DisplayVersion

        $geturl=Invoke-WebRequest "$javaURL" 
        $onlineVersionRaw=$($geturl.ParsedHtml.body.getElementsByTagName('h4') | Where-Object {$_.innerHTML.contains("Recommandé Version") }).innerhtml
        $onlineVersion=$onlineVersionRaw.Split(" ")[-3]+".0."+$onlineVersionRaw.Split(" ")[-1]

        
        if(!$PCversion.Contains("$onlineVersion")){
            Write-Host -NoNewline -ForegroundColor Yellow "Version du PC obsolète $PCversion < $onlineVersion "
            
            if($javaKeepOldVersion -eq "no"){
                Write-Host -NoNewline -Foreground red "Désinstallation de la version précédente de Java "
                $productID=$_.UninstallString.split("{}")[1]    
                Start-Process msiexec.exe -ArgumentList "/uninstall {$productID}  /qn /norestart" -Wait
            }

            Write-Host -ForegroundColor Yellow "Téléchargement en cours ..."
            
            $link=$($geturl.Links | Where-Object {$_.innerHTML -eq "Windows Hors ligne (64 bits)"}).href
            Invoke-WebRequest -Uri $link -OutFile $downloadPath\java.exe
            Start-Process "$downloadPath\java.exe" -ArgumentList "$javaParam"
        }
        else{ Write-Host -ForegroundColor Green "Le PC dispose de la dernière version"}
    }
}

#pause