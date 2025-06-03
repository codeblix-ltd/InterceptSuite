use iced::{Element, Length};
use iced::widget::{column, container, row, text, button, Space, scrollable, pane_grid};
use iced::theme;

use crate::ui::messages::Message;
use crate::ui::state::{AppState, PaneContent};
use crate::ui::styles;

// Main view function for proxy history tab
pub fn view(state: &AppState) -> Element<'_, Message> {
        let controls = history_controls();

        // Create the pane grid with resizable split
        let pane_grid = pane_grid::PaneGrid::new(&state.pane_state, |_pane, content, _is_maximized| {
            match content {
                PaneContent::HistoryTable => pane_grid::Content::new(history_table_pane(state)),
                PaneContent::DataView => pane_grid::Content::new(data_view_pane(state)),
            }
        })
        .on_resize(10, Message::PaneResized)
        .width(Length::Fill)
        .height(Length::Fill);
        // Create the main content layout
        let content = column![
            controls,
            Space::with_height(Length::Fixed(10.0)),
            pane_grid,
        ]
        .spacing(0);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)        .into()
}

fn history_controls() -> Element<'static, Message> {
    let buttons = row![
        button(text("Clear History"))
            .style(styles::button_secondary())
            .on_press(Message::ClearHistory),
        Space::with_width(Length::Fixed(10.0)),
        button(text("Export History"))
            .style(styles::button_primary())
            .on_press(Message::ExportHistory),
    ];

    container(buttons)
        .padding(10)
        .width(Length::Fill)
        .into()
}

fn history_table_pane(state: &AppState) -> Element<'_, Message> {
    let header = container(
        row![
            text("Timestamp").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(150.0)),
            text("Conn ID").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(70.0)),
            text("Source IP").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(100.0)),
            text("Destination IP").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(100.0)),
            text("Port").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(60.0)),
            text("Type").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(80.0)),
            text("Modified").size(12).style(theme::Text::Color([0.7,0.7,0.7].into())).width(Length::Fixed(60.0)),
        ]
        .spacing(10)
    )
    .padding(8)
    .width(Length::Fill)
    .style(theme::Container::Custom(Box::new(styles::HeaderContainerStyle)));

    let table_body = if state.history.is_empty() {
        let empty_container: Element<'_, Message> = container(
            text("No history entries")
                .size(14)
                .style(theme::Text::Color([0.6,0.6,0.6].into()))
        )
        .width(Length::Fill)
        .center_x()
        .padding(20)
        .style(theme::Container::Custom(Box::new(styles::TableBodyStyle)))
        .into();
        empty_container
    } else {
        let rows: Vec<Element<'_, Message>> = state.history
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let is_selected = state.selected_history_item == Some(index);
                let row_content = row![
                    text(entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(150.0)),
                    text(entry.connection_id.to_string())
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(70.0)),
                    text(&entry.src_ip)
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(100.0)),
                    text(&entry.dst_ip)
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(100.0)),
                    text(entry.dst_port.to_string())
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(60.0)),
                    text(&entry.message_type)
                        .size(11)
                        .style(styles::text_primary())
                        .width(Length::Fixed(80.0)),
                    text(if entry.modified { "Yes" } else { "No" })
                        .size(11)
                        .style(if entry.modified {
                            styles::text_warning()
                        } else {
                            styles::text_secondary()
                        })
                        .width(Length::Fixed(60.0)),
                ]
                .spacing(10);

                let styled_row = if is_selected {
                    container(row_content)
                        .style(theme::Container::Custom(Box::new(styles::SelectedRowStyle)))
                        .padding(4)
                        .width(Length::Fill)
                } else {
                    container(row_content)
                        .padding(4)
                        .width(Length::Fill)
                };

                button(styled_row)
                    .style(theme::Button::Custom(Box::new(styles::TableRowButtonStyle)))
                    .on_press(Message::HistoryItemSelected(index))
                    .width(Length::Fill)
                    .into()
            })
            .collect();

        scrollable(
            column(rows).spacing(1)
        )
        .into()
    };

    let content = column![
        header,
        container(table_body)
            .style(theme::Container::Custom(Box::new(styles::TableBodyStyle)))
            .width(Length::Fill)
            .height(Length::Fill)
    ];

    container(content)
        .style(theme::Container::Custom(Box::new(styles::PaneStyle)))
        .padding(5)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn data_view_pane(state: &AppState) -> Element<'_, Message> {
    // Helper function to create tab buttons with consistent styling
    fn create_data_view_tab_button(
        label: &str,
        tab: crate::ui::state::DataViewTab,
        current_tab: crate::ui::state::DataViewTab,
    ) -> Element<'_, Message> {
        let is_active = tab == current_tab;
        let button_style = if is_active {
            styles::button_active_tab()
        } else {
            styles::button_tab()
        };

        button(text(label).size(12))
            .style(button_style)
            .padding([6, 16]) // Slightly more horizontal padding for tab look
            .on_press(Message::DataViewTabSelected(tab))
            .into()
    }

    // Content for the selected tab
    let tab_content: Element<'_, Message> = if let Some(selected_index) = state.selected_history_item {
        if let Some(entry) = state.history.get(selected_index) {
            match state.current_data_view_tab {                crate::ui::state::DataViewTab::Original => {
                    // Display original data using helper method
                    let data_text = entry.get_data_as_string();

                    // Add packet info header
                    let packet_info = format!(
                        "Connection ID: {} | Packet ID: {} | Size: {} bytes",
                        entry.connection_id, entry.packet_id, entry.get_data_size());

                    scrollable(
                        column![
                            container(
                                text(packet_info)
                                    .size(12)
                                    .style(theme::Text::Color([0.7, 0.7, 0.7].into()))
                            )
                            .padding([8, 8])
                            .width(Length::Fill),
                            container(
                                text(data_text)
                                    .size(14)
                                    .style(theme::Text::Color([0.9, 0.9, 0.9].into()))
                                    .width(Length::Fill)
                            )
                            .padding([8, 8])
                            .width(Length::Fill)
                        ]
                    )
                    .style(theme::Scrollable::default())
                    .width(Length::Fill)
                    .into()
                },                crate::ui::state::DataViewTab::Modified => {
                    if !entry.modified {
                        // This case should not occur anymore since the tab is conditionally shown
                        container(text("No modified data available for this entry")
                            .size(14)
                            .style(theme::Text::Color([0.6,0.6,0.6].into())))
                            .width(Length::Fill)
                            .center_x()
                            .center_y()
                            .height(Length::Fill)
                            .into()
                    } else {
                        // Get modified data text using helper method
                        let data_text = if let Some(ref modified_data) = entry.modified_data {
                            // Use modified data if available
                            if modified_data.is_empty() {
                                "(no modified data)".to_string()
                            } else {
                                match String::from_utf8(modified_data.clone()) {
                                    Ok(text_data) => {
                                        if text_data.len() > 5000 {
                                            format!("{}... (truncated, {} total characters)", &text_data[..5000], text_data.len())
                                        } else {
                                            text_data
                                        }
                                    }
                                    Err(_) => {
                                        let hex_data: Vec<String> = modified_data.iter().take(500).map(|b| format!("{:02x}", b)).collect();
                                        let hex_text = hex_data.join(" ");
                                        if modified_data.len() > 500 {
                                            format!("{}... (truncated, {} total bytes)", hex_text, modified_data.len())
                                        } else {
                                            hex_text
                                        }
                                    }
                                }
                            }
                        } else {
                            // Fall back to original data
                            entry.get_data_as_string()
                        };

                        // Calculate data size for modified data
                        let data_size = if let Some(ref modified_data) = entry.modified_data {
                            modified_data.len()
                        } else {
                            entry.get_data_size()
                        };

                        // Add packet info header with modified status
                        let packet_info = format!(
                            "Connection ID: {} | Packet ID: {} | Size: {} bytes | Status: MODIFIED",
                            entry.connection_id, entry.packet_id, data_size);

                        scrollable(
                            column![
                                container(
                                    text(packet_info)
                                        .size(12)
                                        .style(theme::Text::Color([0.7, 0.7, 0.7].into()))
                                )
                                .padding([8, 8])
                                .width(Length::Fill),
                                container(
                                    text(data_text)
                                        .size(14)
                                        .style(theme::Text::Color([1.0, 0.9, 0.4].into()))
                                        .width(Length::Fill)
                                )
                                .padding([8, 8])
                                .width(Length::Fill)
                            ]
                        )
                        .style(theme::Scrollable::default())
                        .width(Length::Fill)
                        .into()
                    }
                }
            }
        } else {
            container(text("Invalid selection")
                .size(14)
                .style(theme::Text::Color([1.0,0.4,0.4].into())))
                .width(Length::Fill)
                .center_x()
                .center_y()
                .height(Length::Fill)
                .into()
        }
    } else {
        container(text("Select a history entry to view data")
            .size(14)
            .style(theme::Text::Color([0.6,0.6,0.6].into())))
            .width(Length::Fill)
            .center_x()
            .center_y()
            .height(Length::Fill)
            .into()
    };    // The tab bar should be inside the content area, not outside
    container(
        column![
            // Tab bar is now inside the content area, styled via container
            container({
                let mut tab_buttons = vec![
                    create_data_view_tab_button("Original", crate::ui::state::DataViewTab::Original, state.current_data_view_tab)
                ];

                // Only show Modified tab if the selected entry is actually modified
                if let Some(selected_index) = state.selected_history_item {
                    if let Some(entry) = state.history.get(selected_index) {
                        if entry.modified {
                            tab_buttons.push(create_data_view_tab_button("Modified", crate::ui::state::DataViewTab::Modified, state.current_data_view_tab));
                        }
                    }
                }

                row(tab_buttons)
                    .spacing(0)
                    .align_items(iced::Alignment::Start)
                    .width(Length::Fill)
                    .padding([6, 6, 0, 6])
            })
            .style(theme::Container::Custom(Box::new(styles::TabHeaderStyle)))
            .width(Length::Fill),
            // Add underline divider after tab bar
            container(Space::with_height(Length::Fixed(1.0)))
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(styles::TabHeaderUnderlineStyle))),
            tab_content
        ]
        .spacing(0)
        .width(Length::Fill)
        .height(Length::Fill)
    )
    .style(theme::Container::Custom(Box::new(styles::PaneStyle)))
    .padding([0, 0, 0, 0])
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
