using System;
using System.ServiceProcess;

namespace ClientDetectionAgent
{
    internal static class Program
    {

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        public static void Main(string[] args)
        {
            if (Environment.UserInteractive)
            {
                Console.WriteLine("Starting ATP Detection Agent in an interactive session!");
                Console.WriteLine("Hi good sir!");


                new ProjectInstaller().DebugInstallation();

                var service = new Service1(args);
                service.TestStartupAndStop();
                Console.ReadKey();
            }
            else
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[]
                {
                new Service1(args)
                };
                ServiceBase.Run(ServicesToRun);
            }
        }
    }
}