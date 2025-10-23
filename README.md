# Windows Privacy Guard

Takes back your privacy from Windows 11. Disables all the creepy tracking, telemetry, and data collection while keeping your system working properly.

## What it does

- **Kills telemetry**: Stops Windows from sending your data to Microsoft
- **Disables tracking**: Turns off location, usage tracking, and advertising ID
- **Blocks data collection**: Stops Cortana, Edge tracking, and other data harvesters
- **Removes bloatware**: Gets rid of Microsoft's pre-installed spyware
- **Smart detection**: Automatically detects what's already disabled
- **Visual interface**: Beautiful GUI with real-time privacy scoring
- **Privacy scoring**: Live privacy protection rating (0-100)
- **Quick actions**: One-click privacy protection setup
- **Advanced features**: Reports, backups, and detailed analysis
- **Actually works**: No more "we're just helping you" nonsense

*It's got some fancy stuff like automated registry tweaks, smart detection, a beautiful GUI with privacy scoring, and advanced reporting features, but the basic privacy protection works great without any configuration*

## Just run it

### GUI Version (Recommended)
```powershell
# Download and run the visual version
python privacy-guard-gui.py

# Or use the launcher
python run-gui.py
```

**New GUI Features:**
- **Privacy Score**: Real-time privacy protection rating (0-100)
- **Quick Actions**: Select All, Clear All, and Recommended buttons
- **Advanced Options**: Generate HTML reports, backup/restore settings
- **Smart Detection**: Automatically scans and shows current privacy status
- **Visual Status**: Color-coded privacy health indicators
- **Professional Reports**: Detailed HTML privacy analysis reports

### PowerShell Version
```powershell
# Download and run (easiest way)
iwr -useb https://raw.githubusercontent.com/your-username/windows-privacy-guard/main/privacy-guard.ps1 | iex

# Or download first, then run
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-username/windows-privacy-guard/main/privacy-guard.ps1" -OutFile "privacy-guard.ps1"
.\privacy-guard.ps1
```

## What it disables

### Telemetry & Data Collection
- **Windows Telemetry**: All data collection and reporting
- **Cortana**: Voice assistant and data harvesting
- **Edge tracking**: Browser tracking and data collection
- **Location services**: GPS and location tracking
- **Usage statistics**: App usage and behavior tracking

### Advertising & Personalization
- **Advertising ID**: Unique identifier for targeted ads
- **Personalized ads**: Targeted advertising based on your data
- **Start menu suggestions**: AI-powered suggestions that spy on you
- **Search suggestions**: Web search suggestions that track you
- **Activity timeline**: Your activity history and tracking

### Microsoft Services
- **OneDrive sync**: Automatic file syncing and cloud storage
- **Microsoft account**: Forced account linking and data sharing
- **Windows Hello**: Biometric data collection
- **Windows Update**: Automatic driver and app installations
- **Feedback Hub**: User feedback and data collection

*There's also some advanced stuff like DNS filtering and network-level blocking, but honestly, the basic privacy protection works great*

## Works with your setup

- **Windows 11**: Works on all versions (though newer versions have more tracking)
- **Admin rights**: Needs admin to disable system-level tracking
- **Existing apps**: Won't break your installed software
- **Essential features**: Keeps Windows working, just stops the spying

## How to use it

### GUI Version (Easiest)
1. **Run the GUI**: `python privacy-guard-gui.py`
2. **Quick Setup**: Click "Recommended" for optimal privacy settings
3. **Custom Setup**: Check/uncheck specific privacy options
4. **Apply Protection**: Click "Apply Privacy Protection"
5. **View Status**: See your privacy score and detailed status

**GUI Features:**
- **Privacy Score**: See your protection level (0-100)
- **Quick Actions**: One-click setup with Select All/Clear All/Recommended
- **Smart Detection**: Automatically shows what's already protected
- **Advanced Options**: Generate reports, backup/restore settings
- **Visual Feedback**: Color-coded status indicators

### PowerShell Version
```powershell
# Disable telemetry only
.\privacy-guard.ps1 --telemetry

# Disable tracking only
.\privacy-guard.ps1 --tracking

# Disable advertising
.\privacy-guard.ps1 --advertising

# Full privacy protection
.\privacy-guard.ps1 --all
```

*There's also a bunch of other options like `--aggressive`, `--conservative`, and `--custom` if you want to get fancy*

## What it protects

### Data Collection
- **Telemetry**: Windows usage data and error reporting
- **Diagnostics**: System diagnostics and performance data
- **Usage statistics**: App usage and behavior patterns
- **Error reporting**: Crash reports and system errors
- **Feedback**: User feedback and suggestions

### Tracking & Monitoring
- **Location tracking**: GPS and location services
- **Activity monitoring**: What you do and when you do it
- **Search tracking**: Web searches and browsing history
- **Voice data**: Cortana voice commands and recordings
- **Biometric data**: Windows Hello face and fingerprint data

### Advertising & Personalization
- **Advertising ID**: Unique identifier for targeted ads
- **Personalized content**: AI-powered suggestions and recommendations
- **Start menu tracking**: What you click and when
- **Search suggestions**: Web search suggestions and tracking
- **Activity timeline**: Your activity history and patterns

*It's got some smart detection to avoid breaking essential Windows features, and it'll restore functionality if something goes wrong*

## Configuration

### GUI Configuration (Recommended)
The GUI makes configuration super easy:

1. **Quick Setup**: Use the "Recommended" button for optimal settings
2. **Custom Setup**: Check/uncheck specific privacy options
3. **Privacy Levels**: Choose from Conservative, Aggressive, or Custom
4. **Smart Detection**: Automatically detects current privacy status
5. **Visual Feedback**: See your privacy score and protection level

**GUI Quick Actions:**
- **Select All**: Enable all privacy protections
- **Clear All**: Disable all privacy protections
- **Recommended**: Set optimal privacy settings for most users
- **Generate Report**: Create detailed HTML privacy report
- **Backup Settings**: Save current configuration
- **Restore Settings**: Load saved configuration

### PowerShell Configuration
```powershell
# Conservative (keeps some features)
.\privacy-guard.ps1 --conservative

# Aggressive (disables everything)
.\privacy-guard.ps1 --aggressive

# Custom (pick what to disable)
.\privacy-guard.ps1 --custom
```

### Whitelist essential features
Some features you might want to keep:
- **Windows Update**: Security updates (but not telemetry)
- **Defender**: Antivirus protection
- **Essential services**: Core Windows functionality

*There's also some cool stuff like automated backups, rollback functionality, and detailed HTML reports if you want to get fancy*

## Troubleshooting

### Common issues

1. **Permission Denied**: Some features need admin rights
   ```powershell
   # Run PowerShell as Administrator
   .\privacy-guard.ps1
   ```

2. **Features not working**: Some apps might need certain services
   - Check the whitelist in config
   - Or run with `--conservative` mode

3. **Windows Update issues**: Telemetry might be needed for some updates
   - Use `--conservative` mode
   - Or manually enable telemetry when updating

### Debug mode
Enable debug mode for detailed logging:
```powershell
.\privacy-guard.ps1 --debug
```

*The script logs everything to `%TEMP%\privacy-guard.log` so you can see what's happening*

## Examples

### GUI Examples (Recommended)
```powershell
# Run the GUI
python privacy-guard-gui.py

# Quick setup with recommended settings
# 1. Click "Recommended" button
# 2. Click "Apply Privacy Protection"
# 3. View your privacy score

# Generate a detailed report
# 1. Click "Generate Report" button
# 2. Choose location to save HTML report
# 3. Open report in browser for detailed analysis

# Backup and restore settings
# 1. Click "Backup Settings" to save current config
# 2. Later, click "Restore Settings" to load saved config
```

### PowerShell Examples
```powershell
# Basic privacy protection
.\privacy-guard.ps1 --all

# Conservative approach
.\privacy-guard.ps1 --conservative

# Custom privacy settings
.\privacy-guard.ps1 --custom --telemetry --tracking

# Restore Windows defaults
.\privacy-guard.ps1 --restore
```

*There's also some cool stuff like automated monitoring, alerts if privacy settings get reverted, and detailed HTML reports with privacy scoring*

## What it doesn't break

### Essential Windows Features
- **Windows Update**: Security updates still work
- **Defender**: Antivirus protection remains active
- **Core services**: Essential Windows functionality
- **Your apps**: Installed software continues to work
- **Network**: Internet and network connectivity

### What you might lose
- **Cortana**: Voice assistant (but you probably don't use it)
- **Start menu suggestions**: AI-powered suggestions
- **Personalized ads**: Targeted advertising
- **Activity timeline**: Your activity history
- **Some Microsoft services**: That you probably don't need anyway

*The script is designed to be safe and won't break your system, but some Microsoft services might not work as expected*

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test on multiple Windows 11 versions
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- Create an issue for bug reports
- Start a discussion for feature requests
- Check the wiki for additional documentation
