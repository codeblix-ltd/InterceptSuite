use iced::{Element, Length};
use iced::widget::{container, column, row, text, button, Space};

use crate::ui::messages::Message;
use crate::ui::state::AppState;
use crate::ui::messages::Tab;
use crate::ui::styles;
use crate::ui::tabs;

/// Main view function that renders the entire GUI
///
/// This function provides a unified interface for rendering all application views,
/// following the DRY principle by centralizing view logic and tab management.
pub fn view(state: &AppState) -> Element<'_, Message> {
    let content = column![
        create_tab_navigation(state),
        create_current_tab_content(state),
        create_status_bar(state),
    ]
    .spacing(0);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(styles::container_dark())
        .into()
}

/// Creates the tab navigation bar
fn create_tab_navigation(state: &AppState) -> Element<'_, Message> {    let tabs = row![
        create_tab_button("Intercept", Tab::Intercept, state.current_tab),
        create_tab_button("Proxy History", Tab::ProxyHistory, state.current_tab),
        create_tab_button("Settings", Tab::Settings, state.current_tab),
        create_tab_button("Connections", Tab::Connections, state.current_tab),
    ]
    .spacing(1);

    container(tabs)
        .width(Length::Fill)
        .style(styles::menu_bar())
        .padding([10, 20])
        .into()
}

/// Creates a tab button with active/inactive styling
fn create_tab_button(label: &str, tab: Tab, current_tab: Tab) -> Element<'static, Message> {
    let is_active = current_tab == tab;

    button(text(label).size(14))
        .style(if is_active {
            styles::button_active_tab()
        } else {
            styles::button_tab()
        })
        .padding([8, 16])
        .on_press(Message::TabSelected(tab))
        .into()
}

/// Creates the content for the currently selected tab
fn create_current_tab_content(state: &AppState) -> Element<'_, Message> {    let content = match state.current_tab {
        Tab::Intercept => tabs::intercept::view(state),
        Tab::ProxyHistory => tabs::proxy_history::view(state),
        Tab::Settings => tabs::settings::view(state),
        Tab::Connections => tabs::connections::view(state),
    };

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(20)
        .style(styles::container_main())
        .into()
}

/// Creates the status bar with proxy status and library status
fn create_status_bar(state: &AppState) -> Element<'_, Message> {
    let left_section = row![
        text(&state.get_status_text()).size(14).style(styles::text_primary()),
    ]
    .align_items(iced::Alignment::Center);let right_section = if !state.library_status.is_empty() {
        row![
            text(&state.library_status)
                .size(12)
                .style(iced::theme::Text::Color(styles::ERROR_COLOR)),
        ]
        .align_items(iced::Alignment::Center)
    } else {
        row![].align_items(iced::Alignment::Center)
    };

    let status_content = row![
        left_section,
        Space::with_width(Length::Fill),
        right_section,
    ]
    .align_items(iced::Alignment::Center);

    container(status_content)
        .width(Length::Fill)
        .style(styles::status_bar())
        .padding([5, 20])
        .into()
}
