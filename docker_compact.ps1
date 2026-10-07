# 관리자 권한 확인
$admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "관리자 PowerShell에서 실행하세요."
    exit
}

$vhdx = "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx"
$docker = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
$before = [math]::Round((Get-Item $vhdx).Length / 1GB, 1)

# Docker 종료 후 WSL 완전 중지
& $docker -Shutdown
Start-Sleep -Seconds 20
wsl --shutdown
Start-Sleep -Seconds 5

# diskpart 명령 파일 작성 후 실행
$script = Join-Path $env:TEMP "compact.txt"
@"
select vdisk file="$vhdx"
attach vdisk readonly
compact vdisk
detach vdisk
exit
"@ | Set-Content $script -Encoding ascii
diskpart /s $script
Remove-Item $script

# 결과 출력 후 Docker 재시작
$after = [math]::Round((Get-Item $vhdx).Length / 1GB, 1)
Write-Host "압축 결과: $before GB -> $after GB"
Start-Process $docker
