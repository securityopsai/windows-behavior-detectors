# Windows Behavior Detectors

Advanced behavioral malware detection mechanisms for Windows environments using PowerShell.

## Features

- **Memory Analysis**: Implements Shannon entropy calculation for process memory regions to detect packed or encrypted code segments
- **Process Monitoring**: Tracks process creation chains and parent-child relationships to identify injection attempts
- **Registry Monitoring**: Watches critical registry locations for persistence mechanisms

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrative privileges

## Usage

```powershell
# Import modules
Import-Module .\src\Detectors\MemoryAnalysis.psm1
Import-Module .\src\Detectors\ProcessMonitor.psm1
Import-Module .\src\Detectors\RegistryMonitor.psm1

# Initialize memory analysis
Initialize-MemoryAnalysis

# Start monitoring
Watch-ProcessBehavior -MonitorDuration 600 -EntropyThreshold 7.2
```

## Security Considerations

This tool requires administrative privileges to access process memory and monitor system events. Use in controlled environments only.

## License

MIT License