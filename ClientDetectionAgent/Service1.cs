using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Linq;

namespace ClientDetectionAgent
{
    /// <summary>
    /// Class that implements APT Detection Agent logic
    /// created by Tom Maier
    /// </summary>
    public partial class Service1 : ServiceBase
    {
        [DllImport("advapi32.dll")]
        private static extern bool SetServiceStatus(IntPtr hServiceStatus, ref SERVICE_STATUS lpServiceStatus);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public int serviceType;
            public int currentState;
            public int controlsAccepted;
            public int win32ExitCode;
            public int serviceSpecificExitCode;
            public int checkPoint;
            public int waitHint;
        }

        internal enum SERVICE_STATE : int
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        private List<EventHistory> EventHistory = new List<EventHistory>();

        //thread safe boolean used for signalling stop of worker thread
        private volatile bool StopThread = false;

        private Thread t;

        public Service1(string[] args)
        {
            InitializeComponent();
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

                var liste = ReadConfigFile(new FileInfo(Application.StartupPath + @"\config.xml"));

                if (liste?.Count > 0)
                {
                    liste.ForEach(x =>
                    {
                        var Analysis = newList.AsQueryable().Where<JObject>(x.Predicate);

                        //do we have events that match our criteria list?
                        if (Analysis?.Count() > 0)
                        {
                            Analysis.ToList().ForEach(y =>
                            {
                                TriggerAlarm(x.Event, y);
                            });
                        }
                    });
                    Log($"------- HEARTBEAT --------");
                }

                Thread.Sleep(10000);
            }
        }

        /// <summary>
        /// Starts our long running worker thread that polls event log on a regular basis.
        /// On stop signal the worker thread joins with main thread and the application exits.
        /// </summary>
        private void StartWorkerThread()
        {
            Log("Starting Worker Thread");
            t = new Thread(DoWork) { Name = "Worker Thread" };
            t.Start();
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
                throw new ArgumentException(nameof(eventId));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            var traceProcessHistory = new JArray();

            //check whether the event has already been analyzed (matching EventId and ProcessGuid/SourceProcessGuid)
            if (EventHistory.Where(x => x.EventId == eventId && x.JObjectGuid == y["ProcessGuid"]?.ToString()).Count() == 0 &&
                EventHistory.Where(x => x.EventId == eventId && x.JObjectGuid == y["SourceProcessGuid"]?.ToString()).Count() == 0)
            {
                Log("----------------- Alarm was triggered! -----------------");
                Log($"The following event defined in {Application.StartupPath + @"\config.xml"} file triggerd the alarm:");
                Log(eventId);

                //add first element that triggered alarm to eventHistory
                traceProcessHistory.Add(y);

                EventHistory.Add(new ClientDetectionAgent.EventHistory { EventId = eventId, JObjectGuid = y["SourceProcessGuid"] != null ? y["SourceProcessGuid"].ToString() : y["ProcessGuid"] != null ? y["ProcessGuid"].ToString() : "" });

                var hasParentProcess = true;

                //recursively parse the history of event log
                while (hasParentProcess)
                {
                    var pick = y["SourceProcessGuid"] != null ? y["SourceProcessGuid"].ToString() : y["ParentProcessGuid"] != null ? y["ParentProcessGuid"].ToString() : y["ProcessGuid"]?.ToString() ?? "";

                    var history = ReadEventLog($"*[EventData[Data[@Name = 'ProcessGuid'] = '{pick}']]");
                    var newList = ConvertToList(history);

                    traceProcessHistory.Merge(newList);

                    if (newList?.Where(x => x["ParentProcessGuid"] != null).Count() > 0)
                    {
                        y = newList?.Where(x => x["ParentProcessGuid"] != null).LastOrDefault();
                    }
                    else
                    {
                        //no more parents anymore. So end recursive search
                        hasParentProcess = false;
                    }
                }
            }

            if (traceProcessHistory?.Count > 0)
            {
                Log(Environment.NewLine);
                Log("Activity History:");
                Log(traceProcessHistory.ToString());
            }

            //send alert
        }

        /// <summary>
        /// This function reads the atp detection agent xml config file.
        /// </summary>
        /// <param name="configFilePath">path to config file</param>
        /// <returns>A list of AuditCriterias that is used to check sysmon eventlog</returns>
        public List<Criteria> ReadConfigFile(FileInfo configFilePath)
        {
            //abfrage abändern und config lesen ohne unauthorizedaccess exception
            if (!File.Exists(configFilePath.FullName) || configFilePath.Extension != ".xml")
            {
                Log($"ERROR: Config file does not seem to exist or doesn't have file extension .xml! Path: {configFilePath}");
                return null;
            }

            var liste = new List<Criteria>();
            try
            {
                var xml = XDocument.Parse(ReadLogfileContent(configFilePath));

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

                                            case "image":
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
                                                Log($"valid set of operations are 'is', 'begin with', 'end with', 'image', 'contains', 'not contains'");
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
                            liste.Add(new Criteria { Event = item.ToString(), Predicate = predicate });
                    }
                    var b = item.Value;
                }
            }
            catch (System.Xml.XmlException xml)
            {
                Log($"Error while trying to parse xml file {configFilePath.FullName}");
                Log($"Please make sure config xml file has a correct syntax with known operators (see Documentation)");
                Log($"Exception Message: {xml.Message}");
            }
            catch (Exception ex)
            {
                Log($"Error while trying to parse xml file {configFilePath.FullName}");
                Log($"Please make sure config xml file has a correct syntax with known operators (see Documentation)");
                Log($"Exception Message: {ex.Message}");
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
                input = input.Insert(0, $"[{System.DateTime.UtcNow.ToString("dd/MM/yyyy HH:mm:ss")}] ");
                if (Environment.UserInteractive)
                    Console.WriteLine(input);
                try
                {
                    if (new FileInfo(Application.StartupPath + @"\activity.log").Exists && new FileInfo(Application.StartupPath + @"\activity.log").Length > 800000000)
                    {
                        File.Delete(Application.StartupPath + @"\activity.log");
                    }
                    //creates the file in case it doesn't exist!
                    File.AppendAllText(Application.StartupPath + @"\activity.log", input + Environment.NewLine);
                }
                catch (System.IO.IOException)
                {
                }
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
                    ["IP"] = Dns.GetHostEntry(Dns.GetHostName()).AddressList.LastOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToString() ?? "",
                    ["EventId"] = x.Id
                };

                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var xml = XDocument.Parse(x.ToXml());

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
            base.OnStart(args);

            IntPtr handle = this.ServiceHandle;

            var service = new SERVICE_STATUS
            {
                currentState = (int)SERVICE_STATE.SERVICE_START_PENDING,
                waitHint = 10000
            };

            SetServiceStatus(this.ServiceHandle, ref service);

            /*
             * https://msdn.microsoft.com/de-de/library/system.serviceprocess.servicebase.onstart(v=vs.90).aspx
            SetServiceStatus(handle, ref myServiceStatus);
            myServiceStatus.currentState = (int)State.SERVICE_START_PENDING;
            SetServiceStatus(handle, ref myServiceStatus);
            */

            Log("APT Detection Agent by Tom Maier");
            Log("OnStart received");

            if (IsSysmonRunning())
            {
                Log("SUCCESS: Sysmon is running!");
                t = new Thread(StartWorkerThread) { Name = "Worker Thread" };
                t.Start();

                service.currentState = (int)SERVICE_STATE.SERVICE_RUNNING;
                SetServiceStatus(this.ServiceHandle, ref service);
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
            base.OnStop();

            var service = new SERVICE_STATUS
            {
                currentState = (int)SERVICE_STATE.SERVICE_STOP_PENDING,
                waitHint = 10000
            };
            SetServiceStatus(this.ServiceHandle, ref service);

            Log("Stop of service received");

            //signal stop thread and wait for thread to finish
            StopThread = true;

            if (t != null)
            {
                t.Join();
                Log("Worker thread has stopped successfully!");
            }

            service.currentState = (int)SERVICE_STATE.SERVICE_STOPPED;
            SetServiceStatus(this.ServiceHandle, ref service);
        }

        /// <summary>
        /// function used for debugging when launching in an interactive visual studio session
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
        /// Read the content of a file even if file is in use by other processes
        /// </summary>
        /// <param name="latestFile"></param>
        /// <returns>content of the file as string</returns>
        private string ReadLogfileContent(FileInfo latestFile)
        {
            var StreamOutput = "";
            if (File.Exists(latestFile.FullName))
            {
                try
                {
                    using (var reader = new FileStream(latestFile.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        using (var stream = new StreamReader(reader))
                        {
                            StreamOutput = stream.ReadToEnd();
                        }
                    };
                }
                catch (Exception)
                {
                }
            }
            return StreamOutput;
        }

        /// <summary>
        /// function that checks whether Sysmon service is running or not
        /// </summary>
        /// <returns>bool that is true if sysmon service is running</returns>
        private bool IsSysmonRunning()
        {
            Log("Check if Sysmon is running");
            return ServiceController.GetServices().Any(s => (s.ServiceName == "Sysmon64" || s.ServiceName == "Sysmon"));
        }
    }
}