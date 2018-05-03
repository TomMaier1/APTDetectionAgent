namespace ClientDetectionAgent
{
    /// <summary>
    /// General configuration file of ATP Detection Agent
    /// </summary>
    internal class Configuration
    {
        public const string directoryPath = @"C:\Program Files\ATP Detection Agent";
        public const string logFile = directoryPath + @"\logfile.log";
        public const string sysmonLogName = "Microsoft-Windows-Sysmon/Operational";
        public const string configFilePath = @"C:\temp\myXml.xml";
    }
}