using System.Collections;
using System.ComponentModel;
using System.IO;

namespace ClientDetectionAgent
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();
        }

        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);

            File.WriteAllText(@"C:\temp\installation_log.log", "installed something");

            //starts the service
            Program.Main(null);
            
        }

        public override void Uninstall(IDictionary savedState)
        {
            base.Uninstall(savedState);

            //remove as a service
            //delete all files
        }
    }
}