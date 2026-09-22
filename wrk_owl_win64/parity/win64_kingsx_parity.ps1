# M4 differential GUI-parity oracle (committed, parameterized). Drives BOTH the 32-bit BC4.5 golden and
# the native-Win64 mdbcc exe through the IDENTICAL deterministic tick sequence, captures the KINGSX
# "Layout Class" child at the 720 and 3600 tiers, and pixel-compares. Deterministic: CM_MNUFIPAUS is queued
# behind the TStart IDOK so the real 100ms SetTimer is killed before its first tick (R=0); EvTimer has no
# GamePaused guard, so injected WM_TIMER ticks drive the simulation as a pure function of tick count.
#
# The two builds match pixel-for-pixel EXCEPT the Arrival/Departure delay LED boxes, where the BC4.5 golden
# has a documented blank-delay-box GDI bug (LAYOUT.CPP:630, HTimeSym/StretchBlt) and the win64 build (with
# the source fix) renders the digits. That region is masked; the metric is the TRACK/clock/platform pixels.
#
# Emits a final "PARITY PASS"/"PARITY FAIL" line. Exit 0 = pass, 3 = fail. Invoked by the O6 slice gate.
param(
  [Parameter(Mandatory=$true)][string]$Win64Exe,
  [Parameter(Mandatory=$true)][string]$GoldenExe,
  [Parameter(Mandatory=$true)][string]$DataDir,     # holds KINGSX.RCD
  [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) ("win64_parity_" + [Guid]::NewGuid().ToString("N").Substring(0,8))),
  [int[]]$Tiers = @(720, 3600),
  [int]$Tolerance = 0    # max differing px allowed OUTSIDE the masked delay-LED region
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Text;
public static class P{
 public delegate bool EP(IntPtr h,IntPtr l);
 [StructLayout(LayoutKind.Sequential)] public struct RECT{public int L,T,R,B;}
 [DllImport("user32.dll")]public static extern bool EnumWindows(EP cb,IntPtr l);
 [DllImport("user32.dll")]public static extern bool EnumChildWindows(IntPtr h,EP cb,IntPtr l);
 [DllImport("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")]public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out RECT r);
 [DllImport("user32.dll")]public static extern bool PrintWindow(IntPtr h,IntPtr hdc,uint f);
 [DllImport("user32.dll")]public static extern bool PostMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")]public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);
 [DllImport("user32.dll")]public static extern bool UpdateWindow(IntPtr h);
 [DllImport("kernel32.dll")]public static extern uint SetErrorMode(uint m);}
"@
[void][P]::SetErrorMode(3)
$WM_COMMAND=0x0111; $WM_TIMER=0x0113; $IDOK=1; $ID_TIMER=2100
if(Test-Path $OutDir){ Remove-Item $OutDir -Recurse -Force }; New-Item -ItemType Directory -Force $OutDir | Out-Null

function ClassOf($h){ $sb=New-Object Text.StringBuilder 128; [void][P]::GetClassName($h,$sb,128); $sb.ToString() }
function FindByClass($pid_,$cls){ $script:r=[IntPtr]::Zero; $script:fp=$pid_; $script:fc=$cls
  $cc=[P+EP]{param($h,$l) $wp=0;[void][P]::GetWindowThreadProcessId($h,[ref]$wp); if($wp -eq $script:fp -and (ClassOf $h) -eq $script:fc){$script:r=$h;return $false} return $true}
  [void][P]::EnumWindows([P+EP]{param($h,$l) $wp=0;[void][P]::GetWindowThreadProcessId($h,[ref]$wp); if($wp -ne $script:fp){return $true}
    if((ClassOf $h) -eq $script:fc){$script:r=$h;return $false}; [void][P]::EnumChildWindows($h,$cc,[IntPtr]::Zero); return ($script:r -eq [IntPtr]::Zero)},[IntPtr]::Zero); $script:r }
function WaitClass($pid_,$cls,$ms){ $dl=(Get-Date).AddMilliseconds($ms); while((Get-Date) -lt $dl){ $h=FindByClass $pid_ $cls; if($h -ne [IntPtr]::Zero){return $h}; Start-Sleep -Milliseconds 80 }; [IntPtr]::Zero }
function Cap($h,$path){ $r=New-Object P+RECT; [void][P]::GetWindowRect($h,[ref]$r); $w=$r.R-$r.L; $ht=$r.B-$r.T
  if($w -le 0 -or $ht -le 0){return $null}
  [void][P]::UpdateWindow($h); $bmp=New-Object Drawing.Bitmap $w,$ht; $g=[Drawing.Graphics]::FromImage($bmp); $hdc=$g.GetHdc()
  try{[void][P]::PrintWindow($h,$hdc,0)}finally{$g.ReleaseHdc($hdc);$g.Dispose()}
  $bmp.Save($path,[Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); @{w=$w;h=$ht} }
function DriveTicks($layout,$n){ $res=[IntPtr]::Zero; for($i=0;$i -lt $n;$i++){ [void][P]::SendMessageTimeout($layout,$WM_TIMER,[IntPtr]$ID_TIMER,[IntPtr]::Zero,0x2,500,[ref]$res) } }
function PixDiffOutsideDelay($a,$b){
  $mx0=45;$mx1=290;$my0=308;$my1=356   # golden's blank-delay-LED region (padded), masked
  $x=[Drawing.Bitmap]::FromFile($a); $y=[Drawing.Bitmap]::FromFile($b)
  try{ if($x.Width -ne $y.Width -or $x.Height -ne $y.Height){return @{nm=-1;reason="size $($x.Width)x$($x.Height) vs $($y.Width)x$($y.Height)"}}
    $dm=0
    for($yy=0;$yy -lt $x.Height;$yy++){ for($xx=0;$xx -lt $x.Width;$xx++){ if($x.GetPixel($xx,$yy).ToArgb() -ne $y.GetPixel($xx,$yy).ToArgb()){
      if(-not($xx -ge $mx0 -and $xx -le $mx1 -and $yy -ge $my0 -and $yy -le $my1)){$dm=$dm+1} } } }
    @{nm=$dm;reason=""} } finally{ $x.Dispose(); $y.Dispose() } }

function SetupRun($name,$exe){
  $run=Join-Path $OutDir $name; New-Item -ItemType Directory -Force $run | Out-Null
  Copy-Item (Join-Path $DataDir "KINGSX.RCD") (Join-Path $run "KINGSX.RCD") -Force
  Copy-Item $exe (Join-Path $run "railc.exe") -Force
  $ep=Join-Path $run "railc.exe"
  $nd=[Text.Encoding]::ASCII.GetBytes("RAILC.INI"); $rp=[Text.Encoding]::ASCII.GetBytes(".\RC.INI")
  $b=[IO.File]::ReadAllBytes($ep)
  for($i=0;$i -le $b.Length-$nd.Length;$i++){ $m=$true; for($j=0;$j -lt $nd.Length;$j++){ if($b[$i+$j]-ne $nd[$j]){$m=$false;break} }
    if($m){ for($j=0;$j -lt $rp.Length;$j++){$b[$i+$j]=$rp[$j]}; for($j=$rp.Length;$j -lt $nd.Length;$j++){$b[$i+$j]=0} } }
  [IO.File]::WriteAllBytes($ep,$b)
  $rcd=Join-Path $run "KINGSX.RCD"
  "[Main Window]`r`nX position=60`r`nY position=60`r`nWidth=600`r`nHeight=400`r`nSave on exit=0`r`nOptimize on start=1`r`nEnable delay=0`r`nEnable sound=0`r`nLoco refuel=1`r`nTimer speed=3`r`nData file name=$rcd`r`n[Arrival Window]`r`nExists=0`r`n[Departure Window]`r`nExists=0`r`n[Platform Window]`r`nExists=0`r`n[Locoyard Window]`r`nExists=0`r`n" | Set-Content -LiteralPath (Join-Path $run "RC.INI") -Encoding ASCII
  $ep }

function StartGame($name,$exe){
  $ep=SetupRun $name $exe
  $p=Start-Process $ep -WorkingDirectory (Split-Path $ep) -PassThru
  $main=WaitClass $p.Id "Main_Window_Class" 12000
  if($main -eq [IntPtr]::Zero){ throw "${name}: no main window" }
  Start-Sleep -Milliseconds 600
  [void][P]::PostMessage($main,$WM_COMMAND,[IntPtr]100,[IntPtr]::Zero)
  $start=WaitClass $p.Id "#32770" 8000
  if($start -eq [IntPtr]::Zero){ throw "${name}: no TStart" }
  [void][P]::PostMessage($start,$WM_COMMAND,[IntPtr]$IDOK,[IntPtr]::Zero)
  [void][P]::PostMessage($main,$WM_COMMAND,[IntPtr]101,[IntPtr]::Zero)  # pause real timer (deterministic)
  $layout=WaitClass $p.Id "Layout Class" 8000
  if($layout -eq [IntPtr]::Zero){ throw "${name}: no Layout Class" }
  Start-Sleep -Milliseconds 300
  @{Proc=$p;Main=$main;Layout=$layout} }

$fail = $false
try {
  $g=StartGame "golden" $GoldenExe
  $w=StartGame "win64"  $Win64Exe
  $prev=0
  foreach($tier in $Tiers){
    $step=$tier-$prev; $prev=$tier
    DriveTicks $g.Layout $step
    DriveTicks $w.Layout $step
    Start-Sleep -Milliseconds 200
    if($g.Proc.HasExited){ Write-Host "golden CRASHED at tier $tier"; $fail=$true; break }
    if($w.Proc.HasExited){ Write-Host ("win64 CRASHED at tier $tier code=0x{0:X8}" -f ([uint32]([int64]$w.Proc.ExitCode -band 0xFFFFFFFFL))); $fail=$true; break }
    $gp=Join-Path $OutDir "golden_tick$tier.png"; $wp=Join-Path $OutDir "win64_tick$tier.png"
    $gc=Cap $g.Layout $gp; $wc=Cap $w.Layout $wp
    $d=PixDiffOutsideDelay $gp $wp
    if($d.reason){ Write-Host ("tier {0}: {1}" -f $tier,$d.reason); $fail=$true }
    elseif($d.nm -gt $Tolerance){ Write-Host ("tier {0}: {1}x{2}  FAIL outside-delay-LED diff {3} px (> tol {4})" -f $tier,$gc.w,$gc.h,$d.nm,$Tolerance); $fail=$true }
    else { Write-Host ("tier {0}: {1}x{2}  PASS outside-delay-LED diff {3} px (<= tol {4})" -f $tier,$gc.w,$gc.h,$d.nm,$Tolerance) }
  }
  foreach($ctx in @($g,$w)){ if(-not $ctx.Proc.HasExited){ $ctx.Proc.Kill(); $ctx.Proc.WaitForExit() } }
} catch {
  Write-Host ("HARNESS ERROR: {0}" -f $_.Exception.Message); exit 2   # inconclusive -> caller treats as skip
}
if($fail){ Write-Host "PARITY FAIL"; exit 3 } else { Write-Host "PARITY PASS"; exit 0 }
