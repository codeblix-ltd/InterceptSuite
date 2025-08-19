using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace InterceptSuite.ViewModels;

public partial class ProjectStartupViewModel : ViewModelBase
{
    private bool _isProVersion = false;

    [ObservableProperty]
    private string _selectedProjectPath = string.Empty;

    [ObservableProperty]
    private bool _dialogResult = false;

    public bool IsProVersion => _isProVersion;
    public bool IsProjectSelectionEnabled => _isProVersion;

    [RelayCommand]
    private async Task OpenProject()
    {
        if (!IsProVersion)
        {
            await ShowProVersionDialog();
            return;
        }

        SelectedProjectPath = "Pro feature - Open existing project";
        DialogResult = true;
    }

    [RelayCommand]
    private async Task NewProject()
    {
        if (!IsProVersion)
        {
            await ShowProVersionDialog();
            return;
        }

        SelectedProjectPath = "Pro feature - Create new project";
        DialogResult = true;
    }

    [RelayCommand]
    private void ContinueWithoutProject()
    {
        SelectedProjectPath = string.Empty;
        DialogResult = true;
    }

    [RelayCommand]
    private async Task OpenProUpgradeUrl()
    {
        try
        {
            var url = "https://interceptsuite.com/pro";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                };
                Process.Start(psi);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
        }
        catch (Exception)
        {
        }

        await Task.CompletedTask;
    }

    private async Task ShowProVersionDialog()
    {
        await Task.CompletedTask;
    }
}
