# We will consider UEFITool's guids.csv as the ultimate source of truth
$Uri = "https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/guids.csv"
$OutFile = "$PSScriptRoot\..\guids.csv"
Invoke-WebRequest -Uri $Uri -OutFile $OutFile
