//! TLS Intercept Suite - Rust GUI
//!
//! A modern, cross-platform GUI for TLS traffic interception and analysis.
//! This application provides a complete replacement for the .NET C# WPF version
//! with improved performance, cross-platform compatibility, and a unified dark theme.
//!
//! Architecture:
//! - Modular design with separation of concerns
//! - Message-driven architecture using Iced framework
//! - Centralized state management
//! - Reusable styling system following DRY principles

// Hide console window on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod library;
mod ui;

use iced::{Application, Settings, Size};
use app::InterceptApp;

fn main() -> iced::Result {
    // Initialize the application with modern window settings
    InterceptApp::run(Settings {
        window: iced::window::Settings {
            size: Size::new(1200.0, 800.0),
            min_size: Some(Size::new(800.0, 600.0)),
            resizable: true,
            decorations: true,
            icon: None, // TODO: Add application icon
            ..Default::default()
        },
        antialiasing: true,
        default_font: iced::Font::default(),
        default_text_size: iced::Pixels(14.0),
        ..Default::default()
    })
}


