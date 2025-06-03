/// Styling module for the TLS Intercept Suite GUI
///
/// This module provides styling functions compatible with iced 0.12
/// using the new theme system with a custom very dark theme.

use iced::{Color, Theme};

// Color constants for very dark theme (Discord/GitHub Dark inspired)
pub const DARK_BACKGROUND: Color = Color::from_rgb(0.08, 0.08, 0.08); // #141414 - Very dark background
pub const DARK_PANEL: Color = Color::from_rgb(0.11, 0.11, 0.11); // #1C1C1C - Slightly lighter panels
pub const MENU_BACKGROUND: Color = Color::from_rgb(0.13, 0.13, 0.13); // #212121 - Menu background
pub const BORDER_COLOR: Color = Color::from_rgb(0.18, 0.18, 0.18); // #2E2E2E - Borders
pub const TEXT_PRIMARY: Color = Color::from_rgb(0.95, 0.95, 0.95); // #F2F2F2 - Bright white text
pub const TEXT_SECONDARY: Color = Color::from_rgb(0.7, 0.7, 0.7); // #B3B3B3 - Dimmed text
pub const ACCENT_COLOR: Color = Color::from_rgb(0.0, 0.6, 1.0); // #0099FF - Bright blue
pub const SUCCESS_COLOR: Color = Color::from_rgb(0.0, 0.9, 0.0); // #00E600 - Bright green
pub const ERROR_COLOR: Color = Color::from_rgb(1.0, 0.2, 0.2); // #FF3333 - Bright red
pub const WARNING_COLOR: Color = Color::from_rgb(1.0, 0.9, 0.0); // #FFE600 - Bright yellow
pub const INFO_COLOR: Color = Color::from_rgb(0.0, 0.8, 1.0); // #00CCFF - Bright cyan

// Create a custom dark theme
pub fn create_dark_theme() -> Theme {
    Theme::custom("Very Dark".to_string(), iced::theme::Palette {
        background: DARK_BACKGROUND,
        text: TEXT_PRIMARY,
        primary: ACCENT_COLOR,
        success: SUCCESS_COLOR,
        danger: ERROR_COLOR,
    })
}

// Text Colors for iced 0.12 (use Color directly with .style() method)
pub fn text_primary() -> Color {
    TEXT_PRIMARY
}

pub fn text_secondary() -> Color {
    TEXT_SECONDARY
}

pub fn text_success() -> Color {
    SUCCESS_COLOR
}

pub fn text_error() -> Color {
    ERROR_COLOR
}

pub fn text_warning() -> Color {
    WARNING_COLOR
}

pub fn text_info() -> Color {
    INFO_COLOR
}

pub fn text_danger() -> Color {
    ERROR_COLOR
}

// Button themes for iced 0.12
pub fn button_primary() -> iced::theme::Button {
    iced::theme::Button::Primary
}

pub fn button_secondary() -> iced::theme::Button {
    iced::theme::Button::Secondary
}

pub fn button_danger() -> iced::theme::Button {
    iced::theme::Button::Destructive
}

pub fn button_success() -> iced::theme::Button {
    iced::theme::Button::Positive
}

pub struct TabButtonStyle;

impl iced::widget::button::StyleSheet for TabButtonStyle {
    type Style = iced::Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(MENU_BACKGROUND)),
            border: iced::Border {
                radius: 2.0.into(),
                width: 1.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_SECONDARY,
        }
    }
}

pub fn button_tab() -> iced::theme::Button {
    iced::theme::Button::Custom(Box::new(TabButtonStyle))
}

pub struct ActiveTabButtonStyle;

impl iced::widget::button::StyleSheet for ActiveTabButtonStyle {
    type Style = iced::Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(DARK_PANEL)),
            border: iced::Border {
                radius: 2.0.into(),
                width: 1.0,
                color: ACCENT_COLOR,
            },
            shadow: Default::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }
}

pub fn button_active_tab() -> iced::theme::Button {
    iced::theme::Button::Custom(Box::new(ActiveTabButtonStyle))
}

// Additional button styles
pub fn button_transparent() -> iced::theme::Button {
    iced::theme::Button::Custom(Box::new(TransparentButtonStyle))
}

struct TransparentButtonStyle;

impl iced::widget::button::StyleSheet for TransparentButtonStyle {
    type Style = iced::Theme;

    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::TRANSPARENT)),
            border: iced::Border {
                radius: 4.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            shadow: iced::Shadow::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }

    fn hovered(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::from_rgba(0.2, 0.2, 0.2, 0.3))),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: BORDER_COLOR,
            },
            shadow: iced::Shadow::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }

    fn pressed(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::from_rgba(0.3, 0.3, 0.3, 0.4))),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: ACCENT_COLOR,
            },
            shadow: iced::Shadow::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }

    fn disabled(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::TRANSPARENT)),
            border: iced::Border {
                radius: 4.0.into(),
                width: 0.0,
                color: Color::TRANSPARENT,
            },
            shadow: iced::Shadow::default(),
            shadow_offset: iced::Vector::default(),
            text_color: Color::from_rgb(0.4, 0.4, 0.4),
        }
    }
}

// Container themes for iced 0.12 with custom dark backgrounds
pub fn container_primary() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(DARK_PANEL)),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn container_secondary() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(DARK_BACKGROUND)),
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn container_main() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(DARK_BACKGROUND)),
        border: iced::Border::default(),
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn container_dark() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(Color::from_rgb(0.05, 0.05, 0.05))), // Even darker
        border: iced::Border {
            radius: 8.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn container_item() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(MENU_BACKGROUND)),
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn menu_bar() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(MENU_BACKGROUND)),
        border: iced::Border {
            radius: 0.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

pub fn status_bar() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(MENU_BACKGROUND)),
        border: iced::Border {
            radius: 0.0.into(),
            width: 1.0,
            color: BORDER_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

// Text Input themes for iced 0.12
pub fn text_input_primary() -> iced::theme::TextInput {
    iced::theme::TextInput::Default
}

// Checkbox themes for iced 0.12
pub fn checkbox_primary() -> iced::theme::Checkbox {
    iced::theme::Checkbox::Primary
}

// PickList themes for iced 0.12
pub fn pick_list_primary() -> iced::theme::PickList {
    iced::theme::PickList::Default
}

// Legacy compatibility - these were used in the old code
pub fn primary_text_color() -> Color {
    TEXT_PRIMARY
}

pub fn secondary_text_color() -> Color {
    TEXT_SECONDARY
}

pub fn error_text_color() -> Color {
    ERROR_COLOR
}

pub fn success_text_color() -> Color {
    SUCCESS_COLOR
}

pub fn container_highlight() -> iced::theme::Container {
    iced::theme::Container::Custom(Box::new(|_theme: &_| iced::widget::container::Appearance {
        background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.25, 0.4))), // Dark blue highlight
        border: iced::Border {
            radius: 6.0.into(),
            width: 2.0,
            color: ACCENT_COLOR,
        },
        shadow: Default::default(),
        text_color: Some(TEXT_PRIMARY),
    }))
}

// Custom styles for the new pane grid split view

pub struct PaneStyle;

impl iced::widget::container::StyleSheet for PaneStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(DARK_PANEL)),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            text_color: Some(TEXT_PRIMARY),
        }
    }
}

pub struct HeaderContainerStyle;

impl iced::widget::container::StyleSheet for HeaderContainerStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.13, 0.13, 0.13))),
            border: iced::Border {
                radius: 0.0.into(),
                width: 0.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            text_color: Some(TEXT_SECONDARY),
        }
    }
}

pub struct TableBodyStyle;

impl iced::widget::container::StyleSheet for TableBodyStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(DARK_BACKGROUND)),
            border: iced::Border {
                radius: 0.0.into(),
                width: 0.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            text_color: Some(TEXT_PRIMARY),
        }
    }
}

pub struct SelectedRowStyle;

impl iced::widget::container::StyleSheet for SelectedRowStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.18, 0.22, 0.28))),
            border: iced::Border {
                radius: 2.0.into(),
                width: 1.0,
                color: ACCENT_COLOR,
            },
            shadow: Default::default(),
            text_color: Some(TEXT_PRIMARY),
        }
    }
}

pub struct TableRowButtonStyle;

impl iced::widget::button::StyleSheet for TableRowButtonStyle {
    type Style = iced::Theme;    fn active(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::TRANSPARENT)),
            border: iced::Border::default(),
            shadow: Default::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }    fn hovered(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.18, 0.18, 0.18))),
            border: iced::Border::default(),
            shadow: Default::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }    fn pressed(&self, _style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.08, 0.18, 0.28))),
            border: iced::Border::default(),
            shadow: Default::default(),
            shadow_offset: iced::Vector::default(),
            text_color: TEXT_PRIMARY,
        }
    }
}

pub struct DataTextStyle;

impl iced::widget::container::StyleSheet for DataTextStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(Color::from_rgb(0.05, 0.05, 0.05))),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: Color::from_rgb(0.25, 0.25, 0.25),
            },
            shadow: Default::default(),
            text_color: Some(Color::from_rgb(0.9, 0.9, 0.9)),
        }
    }
}

pub struct TabHeaderStyle;

impl iced::widget::container::StyleSheet for TabHeaderStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(DARK_PANEL)),
            border: iced::Border {
                radius: 0.0.into(),  // No radius at the top for tab bar
                width: 0.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            text_color: Some(TEXT_PRIMARY),
        }
    }
}

pub struct TabHeaderUnderlineStyle;

impl iced::widget::container::StyleSheet for TabHeaderUnderlineStyle {
    type Style = iced::Theme;
    fn appearance(&self, _style: &Self::Style) -> iced::widget::container::Appearance {
        iced::widget::container::Appearance {
            background: Some(iced::Background::Color(BORDER_COLOR)),
            border: iced::Border {
                radius: 0.0.into(),
                width: 0.0,
                color: BORDER_COLOR,
            },
            shadow: Default::default(),
            text_color: None,
        }
    }
}