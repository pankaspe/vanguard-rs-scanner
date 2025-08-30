// src/ui/mod.rs

use crate::app::{App, AppState};
use ratatui::prelude::*;

// Dichiariamo i moduli interni della UI. `layout` è pubblico perché `main.rs` ne ha bisogno.
pub mod layout;
// `widgets` è un modulo che a sua volta contiene tutti i nostri widget.
// Avrai bisogno di un file `src/ui/widgets/mod.rs` che dichiari `pub mod input;` etc.
mod widgets;

/// Funzione di rendering principale per l'intera interfaccia utente.
///
/// Questa funzione orchestra il disegno di tutti i widget sullo schermo.
/// Calcola il layout e poi chiama le funzioni di rendering per ogni componente.
/// Gestisce anche il rendering condizionale del pannello di log e del popup del disclaimer.
///
/// # Argomenti
/// * `app` - Riferimento mutabile allo stato dell'applicazione.
/// * `frame` - Riferimento mutabile al `Frame` su cui disegnare.
pub fn render(app: &mut App, frame: &mut Frame) {
    // 1. Calcola il layout dinamico in base allo stato `show_logs`.
    let app_layout = layout::create_layout(frame.area(), app.show_logs);

    // 2. Renderizza i widget principali nelle loro aree designate.
    // --- CORREZIONE: La chiamata a `render_input` è stata reinserita qui ---
    widgets::input::render_input(frame, app, app_layout.input);
    widgets::analysis_view::render_analysis_view(frame, app, app_layout.report);
    widgets::summary::render_summary(frame, app, app_layout.summary);
    widgets::footer::render_footer(frame, app, app_layout.footer);

    // 3. Renderizza il pannello di log solo se è visibile.
    if app.show_logs {
        widgets::log_view::render_log_view(frame, app, app_layout.log_panel);
    }

    // 4. Renderizza il popup del disclaimer in cima a tutto il resto se necessario.
    if matches!(app.state, AppState::Disclaimer) {
        widgets::disclaimer_popup::render_disclaimer_popup(frame, frame.area());
    }
}