use iced::{Element, Length};
use iced::widget::{column, row, text, button, checkbox, container, Space, scrollable, text_input};

use crate::ui::messages::Message;
use crate::ui::state::AppState;
use crate::ui::styles;

#[derive(Debug)]
pub struct InterceptTab;

pub fn view(state: &AppState) -> Element<'_, Message> {
    let intercept_controls = intercept_controls(state);
    let connection_info = connection_info(state);
    let data_view = data_view(state);

    let content = column![
        intercept_controls,
        Space::with_height(Length::Fixed(20.0)),
        connection_info,
        Space::with_height(Length::Fixed(20.0)),
        data_view,
    ]
    .spacing(0);

    scrollable(content).into()
}

fn intercept_controls(state: &AppState) -> Element<'_, Message> {let intercept_toggle = checkbox(
            "Intercept is on",
            state.intercept_state.enabled
        )
        .on_toggle(Message::InterceptEnabledToggled);

        let status_text = if state.intercept_state.current_intercept.is_some() {
            "Intercept pending - review and take action"
        } else if state.intercept_state.enabled {
            "Intercept enabled - waiting for traffic"
        } else {
            "Intercept disabled"
        };
          let status = text(status_text)
            .size(14)
            .style(if state.intercept_state.current_intercept.is_some() {
                styles::text_warning()
            } else if state.intercept_state.enabled {
                styles::text_success()
            } else {
                styles::text_secondary()
            });
          let action_buttons = row![
            button(text("Forward"))
                .style(styles::button_success())
                .on_press_maybe(
                    if state.intercept_state.current_intercept.is_some() {
                        Some(Message::ForwardIntercept)
                    } else {
                        None
                    }
                ),
            Space::with_width(Length::Fixed(10.0)),
            button(text("Drop"))
                .style(styles::button_danger())
                .on_press_maybe(
                    if state.intercept_state.current_intercept.is_some() {
                        Some(Message::DropIntercept)
                    } else {
                        None
                    }
                ),
        ];
          let controls_content = column![
            text("Intercept Control")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(10.0)),
            intercept_toggle,
            Space::with_height(Length::Fixed(15.0)),
            text("Current Status")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(10.0)),
            status,
            Space::with_height(Length::Fixed(15.0)),
            text("Actions")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(10.0)),
            action_buttons,
        ]
        .spacing(0);
          container(controls_content)
            .style(styles::container_secondary())
            .padding(15)
            .width(Length::Fill)
            .into()
    }

fn connection_info(state: &AppState) -> Element<'_, Message> {
        let info_content = if let Some(intercept) = &state.intercept_state.current_intercept {            column![
                row![
                    text("Connection ID:").size(14).style(styles::text_secondary()),
                    Space::with_width(Length::Fixed(10.0)),
                    text(intercept.connection_id.to_string()).size(14).style(styles::text_primary()),
                    Space::with_width(Length::Fixed(30.0)),
                    text("Direction:").size(14).style(styles::text_secondary()),
                    Space::with_width(Length::Fixed(10.0)),
                    text(&intercept.direction).size(14).style(styles::text_primary()),
                ],
                Space::with_height(Length::Fixed(10.0)),
                row![
                    text("Endpoint:").size(14).style(styles::text_secondary()),
                    Space::with_width(Length::Fixed(10.0)),
                    text(format!("{}:{} → {}:{}",
                        intercept.src_ip,
                        "unknown", // We don't have src_port in InterceptData
                        intercept.dst_ip,
                        intercept.dst_port))
                        .size(14)
                        .style(styles::text_primary()),
                ],
                Space::with_height(Length::Fixed(10.0)),
                row![
                    text("Timestamp:").size(14).style(styles::text_secondary()),
                    Space::with_width(Length::Fixed(10.0)),
                    text(intercept.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .size(14)
                        .style(styles::text_primary()),
                ],
            ]        } else {
            column![
                text("No active intercept")
                    .size(14)
                    .style(styles::text_secondary()),
            ]
        };
          let content = column![
            text("Connection Information")
                .size(16)
                .style(styles::text_primary()),
            Space::with_height(Length::Fixed(10.0)),
            info_content,
        ];

        container(content)
            .style(styles::container_secondary())
            .padding(15)
            .width(Length::Fill)
            .into()
    }

fn data_view(state: &AppState) -> Element<'_, Message> {
    let data_content: Element<Message> = if state.intercept_state.current_intercept.is_some() {
        // Show the editable data field
        let placeholder = if state.intercept_state.edited_data.is_empty() {
            "No data to display"
        } else {
            "Edit intercepted data here..."
        };

        column![
            text("You can edit the intercepted data below before forwarding:")
                .size(12)
                .style(styles::text_secondary()),
            Space::with_height(Length::Fixed(5.0)),
            text_input(placeholder, &state.intercept_state.edited_data)
                .on_input(Message::InterceptDataEdited)
                .style(styles::text_input_primary())
                .size(12)
                .width(Length::Fill),
            Space::with_height(Length::Fixed(10.0)),
            row![
                button(text("Clear"))
                    .style(styles::button_secondary())
                    .on_press(Message::InterceptDataClear),
                Space::with_width(Length::Fill),
                text(format!("{} bytes", state.intercept_state.edited_data.len()))
                    .size(12)
                    .style(styles::text_secondary()),
            ],
        ]
        .into()
    } else {
        text("No intercepted data")
            .size(14)
            .style(styles::text_secondary())
            .into()
    };

    let content = column![
        text("Intercepted Data")
            .size(16)
            .style(styles::text_primary()),
        Space::with_height(Length::Fixed(10.0)),
        row![
            text("Format: Auto-detected (Text/Hex)").size(12).style(styles::text_secondary()),
            Space::with_width(Length::Fixed(20.0)),
            text("• Use spaces for hex (e.g., '48 65 6c 6c 6f') • Plain text otherwise")
                .size(12)
                .style(styles::text_secondary()),
        ],
        Space::with_height(Length::Fixed(10.0)),
        data_content,
    ];

    container(content)
        .style(styles::container_secondary())
        .padding(15)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
