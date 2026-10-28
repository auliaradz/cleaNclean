param(
    [string]$SvgPath = "$PSScriptRoot\..\assets\logo.svg",
    [string]$IcoPath = "$PSScriptRoot\..\assets\app.ico"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$SvgFullPath = [System.IO.Path]::GetFullPath($SvgPath)
$IcoFullPath = [System.IO.Path]::GetFullPath($IcoPath)

if (-not (Test-Path -LiteralPath $SvgFullPath)) {
    throw "File SVG tidak ditemukan: $SvgFullPath"
}

# 1. Buat wrapper HTML transparan 512x512 agar seluruh filter, clipPath, dan gradient SVG 2.0 dirender sempurna
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "cleaNclean_ico_build"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

$svgRaw = Get-Content -LiteralPath $SvgFullPath -Raw
$htmlPath = Join-Path $tempDir "render_svg.html"
$masterPngPath = Join-Path $tempDir "master_512.png"

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body {
    width: 512px;
    height: 512px;
    background: transparent !important;
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  svg {
    width: 512px !important;
    height: 512px !important;
    display: block;
  }
</style>
</head>
<body>
$svgRaw
</body>
</html>
"@

Set-Content -LiteralPath $htmlPath -Value $htmlContent -Encoding UTF8

# 2. Render SVG ke PNG 512x512 transparan menggunakan Chromium (Chrome / Edge Headless)
$browserExe = @(
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $browserExe) {
    throw "Tidak ditemukan Chrome atau Microsoft Edge untuk merender SVG."
}

$htmlUri = ([System.Uri]$htmlPath).AbsoluteUri
$procArgs = @(
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--default-background-color=00000000",
    "--window-size=512,512",
    "--screenshot=$masterPngPath",
    $htmlUri
)

Start-Process -FilePath $browserExe -ArgumentList $procArgs -Wait -NoNewWindow

if (-not (Test-Path -LiteralPath $masterPngPath)) {
    throw "Gagal merender PNG master dari SVG."
}

# 3. Buat 6 frame multi-resolusi (16, 32, 48, 64, 128, 256) dan kemas ke dalam format biner Windows .ICO
$sizes = @(16, 32, 48, 64, 128, 256)
$pngPayloads = New-Object System.Collections.Generic.List[byte[]]

$masterBmp = [System.Drawing.Bitmap]::new($masterPngPath)
try {
    foreach ($sz in $sizes) {
        $resized = [System.Drawing.Bitmap]::new($sz, $sz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $g = [System.Drawing.Graphics]::FromImage($resized)
            try {
                $g.Clear([System.Drawing.Color]::Transparent)
                $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $g.DrawImage($masterBmp, 0, 0, $sz, $sz)
            } finally {
                $g.Dispose()
            }

            $ms = New-Object System.IO.MemoryStream
            $resized.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $pngPayloads.Add($ms.ToArray())
            $ms.Dispose()
        } finally {
            $resized.Dispose()
        }
    }
} finally {
    $masterBmp.Dispose()
}

# 4. Tulis struktur ICONDIR & ICONDIRENTRY ke assets/app.ico
$outDir = [System.IO.Path]::GetDirectoryName($IcoFullPath)
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$fs = [System.IO.File]::Create($IcoFullPath)
$bw = New-Object System.IO.BinaryWriter($fs)
try {
    # ICONDIR Header (6 bytes): Reserved=0, Type=1 (ICO), Count=6
    $bw.Write([uint16]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]$sizes.Count)

    # Offset data pertama dimulai setelah header (6 bytes) + N * ICONDIRENTRY (16 bytes)
    $currentOffset = 6 + ($sizes.Count * 16)

    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $sz = $sizes[$i]
        $payload = $pngPayloads[$i]
        $dimByte = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }

        $bw.Write($dimByte)                     # bWidth (0 berarti 256)
        $bw.Write($dimByte)                     # bHeight (0 berarti 256)
        $bw.Write([byte]0)                      # bColorCount
        $bw.Write([byte]0)                      # bReserved
        $bw.Write([uint16]1)                    # wPlanes
        $bw.Write([uint16]32)                   # wBitCount (32-bit ARGB)
        $bw.Write([uint32]$payload.Length)      # dwBytesInRes
        $bw.Write([uint32]$currentOffset)       # dwImageOffset

        $currentOffset += $payload.Length
    }

    # Tulis seluruh blok PNG payload
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $bw.Write($pngPayloads[$i])
    }
} finally {
    $bw.Dispose()
    $fs.Dispose()
}

Copy-Item -LiteralPath $masterPngPath -Destination (Join-Path $outDir "logo_preview.png") -Force
Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Berhasil membuat multi-resolution ICO ($($sizes -join 'x, ')x) di: $IcoFullPath ($((Get-Item $IcoFullPath).Length) bytes)"
