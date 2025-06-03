use iced::{Element, Length};
use iced::widget::{column, row, text, button, text_input, checkbox, container, Space, scrollable, pick_list};
use std::sync::Arc;

use crate::library::InterceptLibrary;
use crate::ui::messages::{Message, InterceptDirection};
use crate::ui::state::AppState;
use crate::ui::styles;

// Standalone view function for settings tab
pub fn view(state: &AppState) -> Element<'_, Message> {
    let proxy_config = proxy_configuration(state);
    let intercept_config = intercept_configuration(state);
    let proxy_control = proxy_control(state, &state.library);

    let content = column![
        proxy_config,
        Space::with_height(Length::Fixed(20.0)),
        intercept_config,
        Space::with_height(Length::Fixed(20.0)),
        proxy_control,
    ]
    .spacing(0);

    scrollable(content).into()
}

#[derive(Debug)]
pub struct SettingsTab;

fn proxy_configuration(state: &AppState) -> Element<'_, Message> {
        let bind_address_input = row![
            text("Bind Address:")
                .size(14)
                .style(styles::text_primary())
                .width(Length::Fixed(120.0)),            pick_list(
                state.config_inputs.available_ips.as_slice(),
                state.config_inputs.selected_bind_address.as_ref(),
                Message::BindAddressSelected
            )
                .style(styles::pick_list_primary())
                .width(Length::Fixed(200.0)),
            Space::with_width(Length::Fixed(20.0)),
            button(text("Refresh IPs"))
                .style(styles::button_secondary())
                .on_press(Message::LoadSystemIps),
        ]
        .align_items(iced::Alignment::Center);

        let port_input = row![
            text("Port:")
                .size(14)
                .style(styles::text_primary())
                .width(Length::Fixed(120.0)),
            text_input("4444", &state.config_inputs.port)
                .style(styles::text_input_primary())
                .on_input(Message::PortChanged)
                .width(Length::Fixed(200.0)),
        ]
        .align_items(iced::Alignment::Center);

        let log_file_input = row![
            text("Log File:")
                .size(14)
                .style(styles::text_primary())
                .width(Length::Fixed(120.0)),
            text_input("tls_proxy.log", &state.config_inputs.log_file)
                .style(styles::text_input_primary())
                .on_input(Message::LogFileChanged)
                .width(Length::Fixed(300.0)),
        ]
        .align_items(iced::Alignment::Center);

        let verbose_checkbox = checkbox(
            "Verbose Mode",
            state.config_inputs.verbose_mode
        )
        .on_toggle(Message::VerboseModeToggled)
        .style(styles::checkbox_primary());

        let apply_button = button(text("Apply Configuration"))
            .style(styles::button_primary())
            .on_press(Message::SaveConfig);        let content = column![
            text("Proxy Configuration")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(15.0)),
            bind_address_input,
            Space::with_height(Length::Fixed(10.0)),
            port_input,
            Space::with_height(Length::Fixed(10.0)),
            log_file_input,
            Space::with_height(Length::Fixed(10.0)),
            verbose_checkbox,
            Space::with_height(Length::Fixed(15.0)),
            apply_button,
        ]
        .spacing(0);
          container(content)
            .style(styles::container_primary())
            .padding(15)
            .width(Length::Fill)
            .into()
    }

fn intercept_configuration(state: &AppState) -> Element<'_, Message> {
        let direction_options = vec![
            InterceptDirection::None,
            InterceptDirection::ClientToServer,
            InterceptDirection::ServerToClient,
            InterceptDirection::Both,
        ];

        let direction_picker = row![
            text("Intercept Direction:")
                .size(14)
                .style(styles::text_primary())
                .width(Length::Fixed(150.0)),
            pick_list(
                direction_options,
                Some(state.intercept_state.direction),
                Message::InterceptDirectionChanged
            )
            .width(Length::Fixed(200.0))
            .text_size(14),
        ]
        .align_items(iced::Alignment::Center);

        let content = column![
            text("Intercept Configuration")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(15.0)),
            direction_picker,
            Space::with_height(Length::Fixed(10.0)),
            text("Configure which traffic directions should be intercepted for manual review.")
                .size(12)
                .style(styles::text_secondary()),
        ]
        .spacing(0);

        container(content)
            .style(styles::container_primary())
            .padding(15)
            .width(Length::Fill)
            .into()
    }

fn proxy_control<'a>(state: &'a AppState, library: &'a Option<Arc<InterceptLibrary>>) -> Element<'a, Message> {
        let is_library_loaded = library.is_some();
          let start_button = button(text("Start Proxy"))
            .style(styles::button_success())
            .on_press_maybe(if is_library_loaded && !state.proxy_running {
                Some(Message::StartProxy)
            } else {
                None
            });        let stop_button = button(text("Stop Proxy"))
            .style(styles::button_danger())
            .on_press_maybe(if is_library_loaded && state.proxy_running {
                Some(Message::StopProxy)
            } else {
                None
            });

        let control_buttons = row![
            start_button,
            Space::with_width(Length::Fixed(10.0)),
            stop_button,
        ];

        let status_text = text(&state.proxy_status)
            .size(14)
            .style(if state.proxy_running {
                styles::text_success()
            } else {
                styles::text_secondary()
            });

        let content = column![
            text("Proxy Control")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(15.0)),
            control_buttons,
            Space::with_height(Length::Fixed(10.0)),
            status_text,
            Space::with_height(Length::Fixed(10.0)),
            text("Start the proxy to begin intercepting network traffic. Configure your applications to use SOCKS5 proxy.")
                .size(12)
                .style(styles::text_secondary()),
        ]
        .spacing(0);

        container(content)
            .style(styles::container_primary())
            .padding(15)            .width(Length::Fill)
            .into()
    }

impl std::fmt::Display for InterceptDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
