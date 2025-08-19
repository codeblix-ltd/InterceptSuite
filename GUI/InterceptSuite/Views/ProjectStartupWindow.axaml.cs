using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using InterceptSuite.ViewModels;

namespace InterceptSuite.Views;

public partial class ProjectStartupWindow : Window
{
    public ProjectStartupWindow()
    {
        InitializeComponent();
        DataContext = new ProjectStartupViewModel();

        if (DataContext is ProjectStartupViewModel viewModel)
        {
            viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(ProjectStartupViewModel.DialogResult) && viewModel.DialogResult)
                {
                    Close();
                }
            };
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
    }
}
