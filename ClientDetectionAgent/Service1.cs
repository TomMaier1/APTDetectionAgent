using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;
using System.Xml.Linq;

namespace ClientDetectionAgent
{
    /// <summary>
    /// Class that implements ATP Detection Agent logic
    /// created by Tom Maier
    /// </summary>
    public partial class Service1 : ServiceBase
    {
        private List<EventHistory> EventHistory = new List<EventHistory>();

        //thread safe boolean used for signalling stop of worker thread
        private volatile bool StopThread = false;

        private Thread t;

        public Service1(string[] args)
        {
            InitializeComponent();

            t = new Thread(DoWork) { Name = "Worker Thread" };
            t.Start();

            /*
             * 
             * 
             * 
             * 
             * 
            guter link
            https://codewala.net/2013/10/04/reading-event-logs-efficiently-using-c/
            https://phejndorf.wordpress.com/2011/03/31/using-c-and-linq-to-read-a-windows-eventlog-file-evtx/
            https://www.youtube.com/watch?v=tGCuYwVzPFM

            XPath Querys
            https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.2.8/com.ibm.wincollect.doc/c_ug_wincollect_xpathqueryexamples.html

            Sysmon EventLogWatcher
            https://github.com/fightincanary/SysMonster/blob/master/Sysmonster.cs

            TO DO:

            History Log mit gescheiter Abfrage

            ">*[EventData/Data/ProcessGuid ='{1a41a554-310f-5a73-0000-0010b1050200}']</

            query = "*[EventData[Data[@Name='ProcessGuid'] = '{1a41a554-3fab-5a74-0000-0010dd48d400}']] ";
            */

        }

        /// <summary>
        /// DoWork function that continously parses sysmon event log and cross checks them for matching events
        /// in configuration file for our worker thread
        /// </summary>
        private void DoWork()
        {
            var yesterday = DateTime.UtcNow.AddMinutes(-2);

            var yesterdayDtFormatStr = yesterday.ToString(
               "yyyy-MM-ddTHH:mm:ss.fffffff00K",
               CultureInfo.InvariantCulture
            );

            var query = string.Format(
               "*[System/TimeCreated/@SystemTime >='{0}']",
               yesterdayDtFormatStr
            );

            while (!StopThread)
            {
                var output = ReadEventLog(query);
                var newList = ConvertToList(output);

                var liste = ReadConfigFile(new FileInfo(Configuration.configFilePath));

                if (liste?.Count > 0)
                {
                    liste.ForEach(x =>
                    {
                        var Analysis = newList.AsQueryable().Where<JObject>(x.Predicate);

                        if (Analysis?.Count() > 0)
                        {
                            Analysis.ToList().ForEach(y =>
                            {
                                TriggerAlarm(x.Event, y);
                            });
                        }
                    });
                }

                Thread.Sleep(10000);
            }
        }

        /// <summary>
        /// general function that gets triggered when an alarm hits!
        /// </summary>
        /// <param name="eventId"></param>
        /// <param name="y"></param>
        private void TriggerAlarm(string eventId, JObject y)
        {
            if (String.IsNullOrEmpty(eventId))
            {
                throw new ArgumentException("message", nameof(eventId));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            var traceProcessHistory = new List<JObject>();

            //check whether the event has already been analyzed (matching EventId and ProcessGuid)
            if (EventHistory.Where(x => x.EventId == eventId && x.JObjectGuid == y["ProcessGuid"]?.ToString()).Count() == 0)
            {
                Log("----------------- Alarm was triggered! -----------------");
                Log($"The following event defined in {Configuration.configFilePath} file triggerd the alarm:");
                Log(eventId);

                //add first element that triggered alarm to eventHistory
                traceProcessHistory.Add(y);

                EventHistory.Add(new ClientDetectionAgent.EventHistory { EventId = eventId, JObjectGuid = y["ProcessGuid"].ToString() });

                //forget me function!
                if (y["ParentProcessGuid"] != null)
                {
                    var hasParentProcess = true;

                    while (hasParentProcess)
                    {
                        var history = ReadEventLog($"*[EventData[Data[@Name = 'ProcessGuid'] = '{y["ParentProcessGuid"].ToString()}']]");
                        var newList = ConvertToList(history);

                        traceProcessHistory.AddRange(newList);

                        if (newList?.Count > 0)
                        {
                            y = newList.Last();
                        }
                        else
                        {
                            //no more parents anymore. So end recursive search
                            hasParentProcess = false;
                        }
                    }
                }
            }

            if (traceProcessHistory?.Count > 0)
            {
                Log(Environment.NewLine);
                Log("Activity History:");
                traceProcessHistory?.ForEach(x => Log(x.ToString()));
            }

            //send alert by mail
        }

        /// <summary>
        /// This function reads the atp detection agent xml config file.
        /// </summary>
        /// <param name="configFilePath">path to config file</param>
        /// <returns>A list of AuditCriterias that is used to check sysmon eventlog</returns>
        public List<AuditCriteria> ReadConfigFile(FileInfo configFilePath)
        {
            if (!File.Exists(configFilePath.FullName))
            {
                Log($"ERROR: Config file does not seem to exist! Path: {Configuration.configFilePath}");
            }
            if (configFilePath.Extension != ".xml")
            {
                Log($"ERROR: Config file must be of data extension *.xml");
            }

            var liste = new List<AuditCriteria>();
            try
            {
                var xml = XDocument.Parse(File.ReadAllText(configFilePath.FullName));

                foreach (XElement item in xml.Descendants("Event"))
                {
                    if (item != null)
                    {
                        var predicate = PredicateBuilder.True<JObject>();
                        var eventId = item.FirstAttribute?.Value;

                        if (!String.IsNullOrEmpty(eventId))
                        {
                            predicate = x => x["EventId"].ToString() == eventId;

                            foreach (XElement image in item.Nodes())
                            {
                                if (image != null)
                                {
                                    var operation = image.FirstAttribute?.Value;

                                    if (!String.IsNullOrEmpty(operation))
                                    {
                                        switch (operation)
                                        {
                                            case "is":
                                                predicate = predicate.And(x => x[image.Name.LocalName] != null && x[image.Name.LocalName].ToString().ToLower() == image.Value.ToLower());
                                                break;

                                            case "begin with":
                                                predicate = predicate.And(x => x[image.Name.LocalName] != null && x[image.Name.LocalName].ToString().ToLower().StartsWith(image.Value.ToLower()));
                                                break;

                                            case "end with":
                                                predicate = predicate.And(x => x[image.Name.LocalName] != null && x[image.Name.LocalName].ToString().ToLower().EndsWith(image.Value.ToLower()));
                                                break;

                                            case "contains":
                                                predicate = predicate.And(x => x[image.Name.LocalName] != null && x[image.Name.LocalName].ToString().ToLower().Contains(image.Value.ToLower()));
                                                break;

                                            case "not contains":
                                                predicate = predicate.And(x => x[image.Name.LocalName] != null && !x[image.Name.LocalName].ToString().ToLower().Contains(image.Value.ToLower()));
                                                break;

                                            default:
                                                Log($"unknown operation specified '{operation}' for event type '{image.ToString()}'");
                                                Log($"please see documentation for valid set of operations");
                                                predicate = null;
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        Log($"the following entry is missing condition and can therefore not be parsed.");
                                        Log(image.ToString());
                                    }
                                }
                            }
                        }
                        else
                        {
                            Log($"Unable to parse because of missing id in Event");
                            Log(item.ToString());
                        }
                        //add predicate to list
                        if (!String.IsNullOrEmpty(item.ToString()) && predicate != null)
                            liste.Add(new AuditCriteria { Event = item.ToString(), Predicate = predicate });
                    }
                    var b = item.Value;
                }
            }
            catch (System.Xml.XmlException xml)
            {
                Log($"Error while trying to parse xml file {configFilePath.FullName}");
                Log($"Please make sure config xml file has a correct syntax with known operators (see Documentation)");
                Log($"Exception Message: {xml.Message}");
                Log($"Exception InnerMessage: {xml.InnerException}");
                Log($"Exception StackTrace: {xml.StackTrace}");
            }
            catch (Exception ex)
            {
                Log($"Error while trying to parse xml file {configFilePath.FullName}");
                Log($"Please make sure config xml file has a correct syntax with known operators (see Documentation)");
                Log($"Exception Message: {ex.Message}");
                Log($"Exception InnerMessage: {ex.InnerException}");
                Log($"Exception StackTrace: {ex.StackTrace}");
            }
            return liste;
        }

        /// <summary>
        /// Function to log activity to a log file. Also prints to console in an interactive session.
        /// </summary>
        /// <param name="input"></param>
        private void Log(string input)
        {
            if (!String.IsNullOrEmpty(input))
            {
                if (!new DirectoryInfo(Configuration.directoryPath).Exists)
                    new DirectoryInfo(Configuration.directoryPath).Create();

                if (Environment.UserInteractive)
                    Console.WriteLine(input);

                //creates the file in case it doesn't exist!
                File.AppendAllText(Configuration.logFile, input + Environment.NewLine);
            }
        }

        /// <summary>
        /// Converts event log enumerable file to a list of jobjects with additional information (machine name and event id)
        /// </summary>
        /// <param name="output"></param>
        /// <returns>list of events from event log converted to jobjects</returns>
        private List<JObject> ConvertToList(IEnumerable<EventLogRecord> output)
        {
            var list = new List<JObject>();
            output.ToList().ForEach(x =>
            {
                var jsonObject = new JObject
                {
                    ["MachineName"] = x.MachineName,
                    ["EventId"] = x.Id
                };

                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var xml = XDocument.Parse(x.ToXml());

                //prüfung wenn element null ist

                foreach (XElement i in xml.Root.Element(ns + "EventData").Elements(ns + "Data"))
                {
                    if (i != null)
                    {
                        jsonObject[i.Attribute("Name").Value] = i.Value;
                    }
                }
                list.Add(jsonObject);
            });
            return list;
        }

        /// <summary>
        /// Function executed upon service launch
        /// </summary>
        /// <param name="args"></param>
        protected override void OnStart(string[] args)
        {
            Log("ATP Detection Agent by Tom Maier");
            Log("OnStart received");

            if (IsSysmonRunning())
            {
                Log("SUCCESS: Sysmon is running!");
            }
            else
            {
                Log("Sysmon service does not seem to be running. Please turn it on.");
                OnStop();
            }
        }

        /// <summary>
        /// Reading eventlog and also performs a XPath query
        /// </summary>
        /// <param name="xPathQuery"></param>
        /// <returns>An Enumerable data structure with query results</returns>
        private static IEnumerable<EventLogRecord> ReadEventLog(string xPathQuery = "*")
        {
            var eventLogQuery = new EventLogQuery(Configuration.sysmonLogName, PathType.LogName, xPathQuery);
            using (var eventLogReader = new EventLogReader(eventLogQuery))
            {
                EventLogRecord eventLogRecord;

                while ((eventLogRecord = (EventLogRecord)eventLogReader.ReadEvent()) != null)
                    yield return eventLogRecord;
            }
        }

        /// <summary>
        /// Function executed upon service stop
        /// </summary>
        protected override void OnStop()
        {
            Log("Stop of service received");

            //signal stop thread and wait for thread to finish
            StopThread = true;

            if (t != null)
            {
                t.Join();
                Log("Worker thread has stopped successfully!");
            }
        }

        /// <summary>
        /// function used for debugging
        /// </summary>
        /// <param name="args">startup arguments if desired</param>
        ///
        internal void TestStartupAndStop()
        {
            this.OnStart(null);
            Console.ReadLine();
            this.OnStop();
        }

        /// <summary>
        /// function that checks whether Sysmon service is running or not
        /// </summary>
        /// <returns>bool that is true if sysmon service is running</returns>
        private bool IsSysmonRunning()
        {
            Log("Check if Sysmon is running");
            return new ServiceController("Sysmon64").Status == ServiceControllerStatus.Running || new ServiceController("Sysmon").Status == ServiceControllerStatus.Running;
        }
    }
}