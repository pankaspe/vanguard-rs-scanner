// src/ui/widgets/log_view.rs

use crate::app::App;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation},
};

pub fn render_log_view(frame: &mut Frame, app: &mut App, area: Rect) {
    // CORREZIONE: Titolo aggiornato con le istruzioni corrette e solo per tastiera.
    let block = Block::default()
        .title("Logs (scroll with ← →)")
        .borders(Borders::ALL);
    
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let max_width = app.log_content.iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);

    app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.content_length(max_width);

    let log_text = Text::from(app.log_content.join("\n"));
    let log_paragraph = Paragraph::new(log_text)
        .scroll((0, app.log_horizontal_scroll as u16));
        
    frame.render_widget(log_paragraph, inner_area);

    let scrollbar = Scrollbar::new(ScrollbarOrientation::HorizontalBottom)
        .thumb_symbol("■");

    let scrollbar_area = Rect {
        x: inner_area.x,
        y: inner_area.y + inner_area.height.saturating_sub(1),
        width: inner_area.width,
        height: 1,
    };
    
    frame.render_stateful_widget(
        scrollbar,
        scrollbar_area,
        &mut app.log_horizontal_scroll_state,
    );
}