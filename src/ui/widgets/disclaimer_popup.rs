// src/ui/widgets/disclaimer_popup.rs

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    text::Line,
};

/// Renderizza il popup del disclaimer sopra la UI esistente.
pub fn render_disclaimer_popup(frame: &mut Frame, area: Rect) {
    let disclaimer_text = Text::from(vec![
        Line::from("IMPORTANT LEGAL DISCLAIMER".bold().yellow()),
        Line::from(""),
        Line::from("Vanguard RS is a powerful security analysis toolkit intended for educational purposes and for professionals to assess assets they are explicitly authorized to test."),
        Line::from(""),
        Line::from("Scanning systems you do not own or have explicit, written permission to test is ILLEGAL and UNETHICAL. Unauthorized scanning can be considered a criminal offense in many jurisdictions."),
        Line::from(""),
        Line::from("By using this software, you agree to the following:"),
        Line::from("1. You will only use it on systems you own or have explicit permission to scan."),
        Line::from("2. You will use this software responsibly and in accordance with all applicable laws."),
        Line::from("3. The author of this software assumes NO liability and is NOT responsible for any misuse or damage caused by this program."),
        Line::from(""),
        Line::from("Press ".bold() + "Enter".bold().yellow() + " to Acknowledge and Continue".bold()),

    ]);

    let block = Block::default()
        .title("Disclaimer")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    // Creiamo un'area per il popup che occupa il 60% della larghezza e il 50% dell'altezza
    let popup_area = centered_rect(70, 80, area);

    let popup = Paragraph::new(disclaimer_text)
        .block(block)
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center);

    // `Clear` è la magia: non cancella ciò che c'è sotto prima di disegnare.
    frame.render_widget(Clear, popup_area);
    frame.render_widget(popup, popup_area);
}

/// Funzione helper (dall'esempio di Ratatui) per creare un'area centrata.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}