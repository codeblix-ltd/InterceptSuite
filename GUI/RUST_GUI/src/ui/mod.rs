/// UI module for the Rust GUI application
///
/// This module provides a complete separation of concerns for the user interface,
/// organizing all UI-related functionality into logical submodules following
/// the DRY principle and modern software architecture patterns.

pub mod messages;
pub mod state;
pub mod styles;
pub mod tabs;
pub mod views;

// Re-export commonly used types for convenience
pub use messages::Message;
pub use state::AppState;
// pub use styles::*;
//pub use views::view as main_view;
