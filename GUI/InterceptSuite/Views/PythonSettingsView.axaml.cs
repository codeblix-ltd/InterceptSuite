using Avalonia.Controls;
using InterceptSuite.ViewModels;

namespace InterceptSuite.Views
{
    public partial class PythonSettingsView : UserControl
    {
        public PythonSettingsView()
        {
            InitializeComponent();
            DataContext = new PythonSettingsViewModel();
        }
    }
}
