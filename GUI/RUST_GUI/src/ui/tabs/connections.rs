use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Alignment, Element, Length,
};

use crate::ui::{
    messages::Message,
    state::{AppState, ConnectionEntry},
    styles,
};

/// Renders the Connections tab
pub fn view(state: &AppState) -> Element<'_, Message> {


    let controls = row![
        button(text("Clear All"))
            .style(styles::button_secondary())
            .on_press(Message::ClearConnections),
        Space::with_width(Length::Fixed(10.0)),
        button(text("Export"))
            .style(styles::button_secondary())
            .on_press(Message::ExportConnections),
        Space::with_width(Length::Fixed(10.0)),
        button(text("Refresh"))
            .style(styles::button_secondary())
            .on_press(Message::RefreshConnections),
    ]
    .align_items(Alignment::Center);

    let header = row![
        controls,
    ]
    .align_items(Alignment::Center);

    let connection_table = create_connection_table(state);

    let content = column![
        header,
        Space::with_height(Length::Fixed(20.0)),
        connection_table,
    ]
    .spacing(0);

    scrollable(content).into()
}

/// Creates the connection table with headers and data
fn create_connection_table(state: &AppState) -> Element<'_, Message> {
    let mut table_content = vec![];

    // Table header
    let header_row = row![
        text("Timestamp")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(140.0)),
        text("Event")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(100.0)),
        text("Connection ID")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(100.0)),
        text("Source IP")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(120.0)),
        text("Source Port")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(100.0)),
        text("Destination IP")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(120.0)),
        text("Destination Port")
            .size(14)
            .style(styles::text_primary())
            .width(Length::Fixed(120.0)),
    ]
    .spacing(10)
    .align_items(Alignment::Center);

    let header_container = container(header_row)
        .style(styles::container_secondary())
        .padding(10)
        .width(Length::Fill);

    table_content.push(header_container.into());

    // Table data rows
    if state.connections.is_empty() {
        let empty_message = container(
            text("No connections recorded yet")
                .size(16)
                .style(styles::text_secondary())
        )
        .center_x()
        .center_y()
        .padding(40)
        .width(Length::Fill);

        table_content.push(empty_message.into());
    } else {
        for (index, connection) in state.connections.iter().enumerate() {
            let data_row = create_connection_row(index, connection);
            table_content.push(data_row);
        }
    }

    let table = column(table_content).spacing(2);

    container(table)
        .style(styles::container_primary())
        .padding(15)
        .width(Length::Fill)
        .into()
}

/// Creates a single connection row in the table
fn create_connection_row(index: usize, connection: &ConnectionEntry) -> Element<'_, Message> {
    let event_style = match connection.event.as_str() {
        "Connected" => styles::text_success(),
        "Disconnected" => styles::text_danger(),
        _ => styles::text_secondary(),
    };

    let data_row = row![
        text(connection.timestamp.format("%H:%M:%S").to_string())
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(140.0)),
        text(&connection.event)
            .size(12)
            .style(event_style)
            .width(Length::Fixed(100.0)),
        text(connection.connection_id.to_string())
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(100.0)),
        text(&connection.src_ip)
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(120.0)),
        text(connection.src_port.to_string())
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(100.0)),
        text(&connection.dst_ip)
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(120.0)),
        text(connection.dst_port.to_string())
            .size(12)
            .style(styles::text_secondary())
            .width(Length::Fixed(120.0)),
    ]
    .spacing(10)
    .align_items(Alignment::Center);

    let row_container = container(data_row)
        .style(if index % 2 == 0 {
            styles::container_primary()
        } else {
            styles::container_secondary()
        })
        .padding(8)
        .width(Length::Fill);

    button(row_container)
        .style(styles::button_transparent())
        .on_press(Message::ConnectionSelected(index))
        .width(Length::Fill)
        .into()
}
