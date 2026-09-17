use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    Enter,
    Esc,
    Backspace,
    F(u8),
    Ctrl(char),
}

impl Key {
    pub fn from_crossterm(event: KeyEvent) -> Option<Self> {
        if event.modifiers.contains(KeyModifiers::CONTROL) {
            return match event.code {
                KeyCode::Char(c) => Some(Self::Ctrl(c.to_ascii_lowercase())),
                _ => None,
            };
        }
        Some(match event.code {
            KeyCode::Char(c) => Self::Char(c),
            KeyCode::Up => Self::Up,
            KeyCode::Down => Self::Down,
            KeyCode::Left => Self::Left,
            KeyCode::Right => Self::Right,
            KeyCode::Tab => Self::Tab,
            KeyCode::BackTab => Self::BackTab,
            KeyCode::Enter => Self::Enter,
            KeyCode::Esc => Self::Esc,
            KeyCode::Backspace => Self::Backspace,
            KeyCode::F(n) => Self::F(n),
            _ => return None,
        })
    }
}
