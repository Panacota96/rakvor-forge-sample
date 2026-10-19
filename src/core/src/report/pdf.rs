//! A small, dependency-free PDF writer for print-ready reports.
//!
//! Uses the 14 standard fonts (Helvetica, Helvetica-Bold, Courier) with WinAnsiEncoding, which covers
//! English, Spanish and French (á é í ó ú ñ ü ç à è ê ë î ï ô œ « » € …). Characters outside WinAnsi
//! become '?'. Upgrade path for richer layout or other scripts: Typst or printpdf with embedded fonts.

use std::fmt::Write as _;

const PAGE_W: f32 = 595.0; // A4 in points
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 50.0;
const BOTTOM: f32 = 62.0;
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;
const KEY_W: f32 = 165.0;

#[derive(Clone, Debug)]
pub enum Block {
    Brand(String),
    Title(String),
    Subtitle(String),
    Heading(String),
    Para(String),
    Note(String),
    Mono(String),
    Bullet(String),
    Kv(Vec<(String, String)>),
    /// Small labelled box: (badge text, title, rows of key/value)
    Finding {
        badge: String,
        title: String,
        rows: Vec<(String, String)>,
    },
    Status(String),
    Space(f32),
}

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn res(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
        }
    }
}

// Advance widths (1/1000 em) for ASCII 32..=126 from the Adobe AFM files.
const HELV: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];
const HELV_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

fn char_width(c: char, font: Font, size: f32) -> f32 {
    let units = match font {
        Font::Mono => 600,
        Font::Regular | Font::Bold => {
            let table = if font == Font::Bold {
                &HELV_BOLD
            } else {
                &HELV
            };
            let base = match c {
                ' '..='~' => c,
                'á' | 'à' | 'â' | 'ä' | 'ã' => 'a',
                'é' | 'è' | 'ê' | 'ë' => 'e',
                'í' | 'ì' | 'î' | 'ï' => 'i',
                'ó' | 'ò' | 'ô' | 'ö' | 'õ' => 'o',
                'ú' | 'ù' | 'û' | 'ü' => 'u',
                'ñ' => 'n',
                'ç' => 'c',
                'Á' | 'À' | 'Â' => 'A',
                'É' | 'È' | 'Ê' => 'E',
                'Ó' | 'Ô' => 'O',
                'Ú' => 'U',
                'Ñ' => 'N',
                'Ç' => 'C',
                _ => 'W', // unknown: assume wide so text never overflows
            };
            table[(base as usize) - 32]
        }
    };
    units as f32 * size / 1000.0
}

fn text_width(s: &str, font: Font, size: f32) -> f32 {
    s.chars().map(|c| char_width(c, font, size)).sum()
}

/// Greedy word wrap; words longer than the line are broken by characters (hashes, paths).
fn wrap(text: &str, font: Font, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ') {
            let candidate = if line.is_empty() {
                word.to_string()
            } else {
                format!("{} {}", line, word)
            };
            if text_width(&candidate, font, size) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            let mut chunk = String::new();
            for c in word.chars() {
                if text_width(&chunk, font, size) + char_width(c, font, size) > width
                    && !chunk.is_empty()
                {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(c);
            }
            line = chunk;
        }
        lines.push(line);
    }
    lines
}

/// Encodes to WinAnsi and escapes for a PDF literal string.
fn pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('(');
    for c in s.chars() {
        let b: u8 = match c {
            '\u{20AC}' => 0x80,
            '\u{2026}' => 0x85,
            '\u{2018}' => 0x91,
            '\u{2019}' => 0x92,
            '\u{201C}' => 0x93,
            '\u{201D}' => 0x94,
            '\u{2022}' => 0x95,
            '\u{2013}' => 0x96,
            '\u{2014}' => 0x97,
            '\u{2122}' => 0x99,
            '\u{0152}' => 0x8C,
            '\u{0153}' => 0x9C,
            '\u{00A0}'..='\u{00FF}' => c as u32 as u8,
            ' '..='~' => c as u8,
            _ => b'?',
        };
        match b {
            b'(' | b')' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{:03o}", b);
            }
        }
    }
    out.push(')');
    out
}

struct Layout {
    pages: Vec<String>,
    cur: String,
    y: f32,
}

impl Layout {
    fn new() -> Layout {
        Layout {
            pages: Vec::new(),
            cur: String::new(),
            y: PAGE_H - MARGIN,
        }
    }

    fn ensure(&mut self, h: f32) {
        if self.y - h < BOTTOM {
            self.pages.push(std::mem::take(&mut self.cur));
            self.y = PAGE_H - MARGIN;
        }
    }

    fn text(&mut self, x: f32, y: f32, font: Font, size: f32, rgb: (f32, f32, f32), s: &str) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} rg BT /{} {} Tf {:.2} {:.2} Td {} Tj ET",
            rgb.0,
            rgb.1,
            rgb.2,
            font.res(),
            size,
            x,
            y,
            pdf_string(s)
        );
    }

    fn rule(&mut self, y: f32, w: f32, rgb: (f32, f32, f32)) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} RG {} w {} {:.2} m {} {:.2} l S",
            rgb.0,
            rgb.1,
            rgb.2,
            w,
            MARGIN,
            y,
            PAGE_W - MARGIN,
            y
        );
    }

    fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, rgb: (f32, f32, f32)) {
        let _ = writeln!(
            self.cur,
            "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f",
            rgb.0, rgb.1, rgb.2, x, y, w, h
        );
    }

    fn lines(
        &mut self,
        x: f32,
        width: f32,
        font: Font,
        size: f32,
        rgb: (f32, f32, f32),
        text: &str,
    ) {
        let lead = size * 1.35;
        for l in wrap(text, font, size, width) {
            self.ensure(lead);
            self.y -= lead;
            self.text(x, self.y, font, size, rgb, &l);
        }
    }

    fn kv(&mut self, x: f32, width: f32, rows: &[(String, String)]) {
        const SIZE: f32 = 9.0;
        let lead = SIZE * 1.35;
        for (k, v) in rows {
            let mono = looks_like_hash(v);
            let vf = if mono { Font::Mono } else { Font::Regular };
            let vs = if mono { 8.0 } else { SIZE };
            let kl = wrap(k, Font::Regular, SIZE, KEY_W - 10.0);
            let vl = wrap(v, vf, vs, width - KEY_W);
            let n = kl.len().max(vl.len());
            self.ensure(lead * n as f32 + 3.0);
            let top = self.y;
            for (i, l) in kl.iter().enumerate() {
                self.text(
                    x,
                    top - lead * (i as f32 + 1.0),
                    Font::Regular,
                    SIZE,
                    MUTED,
                    l,
                );
            }
            for (i, l) in vl.iter().enumerate() {
                self.text(x + KEY_W, top - lead * (i as f32 + 1.0), vf, vs, INK, l);
            }
            self.y = top - lead * n as f32 - 3.0;
        }
    }
}

const INK: (f32, f32, f32) = (0.063, 0.094, 0.157);
const MUTED: (f32, f32, f32) = (0.278, 0.329, 0.404);
const ACCENT: (f32, f32, f32) = (0.165, 0.361, 1.0);
const LINE: (f32, f32, f32) = (0.894, 0.906, 0.925);

/// Hashes and long paths (no spaces, 32+ characters) are set in monospace and wrapped by character.
fn looks_like_hash(v: &str) -> bool {
    v.chars().count() >= 32 && !v.contains(' ')
}

/// Renders blocks to a complete PDF. `footer` is printed on every page followed by "page n / m".
pub fn render(
    blocks: &[Block],
    title: &str,
    footer: &str,
    page_word: &str,
    of_word: &str,
    producer: &str,
) -> Vec<u8> {
    let mut l = Layout::new();
    for b in blocks {
        match b {
            Block::Brand(s) => {
                l.ensure(14.0);
                l.y -= 10.0;
                l.text(MARGIN, l.y, Font::Bold, 8.0, ACCENT, s);
            }
            Block::Title(s) => {
                l.y -= 6.0;
                l.lines(MARGIN, CONTENT_W, Font::Bold, 18.0, INK, s);
            }
            Block::Subtitle(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Regular, 10.0, MUTED, s);
                l.y -= 8.0;
                l.rule(l.y, 2.0, ACCENT);
                l.y -= 8.0;
            }
            Block::Heading(s) => {
                l.ensure(40.0);
                l.y -= 10.0;
                l.lines(MARGIN, CONTENT_W, Font::Bold, 12.0, INK, s);
                l.y -= 4.0;
                l.rule(l.y, 0.6, LINE);
                l.y -= 2.0;
            }
            Block::Para(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Regular, 9.5, INK, s);
                l.y -= 3.0;
            }
            Block::Note(s) => {
                l.y -= 2.0;
                l.lines(
                    MARGIN + 8.0,
                    CONTENT_W - 8.0,
                    Font::Bold,
                    9.5,
                    (0.71, 0.28, 0.03),
                    s,
                );
                l.y -= 4.0;
            }
            Block::Status(s) => {
                l.ensure(30.0);
                l.y -= 6.0;
                l.rect(MARGIN, l.y - 22.0, 4.0, 24.0, ACCENT);
                l.y -= 4.0;
                l.lines(MARGIN + 12.0, CONTENT_W - 12.0, Font::Bold, 14.0, INK, s);
                l.y -= 6.0;
            }
            Block::Mono(s) => {
                l.lines(MARGIN, CONTENT_W, Font::Mono, 8.0, INK, s);
            }
            Block::Bullet(s) => {
                let lead = 9.5 * 1.35;
                let lines = wrap(s, Font::Regular, 9.5, CONTENT_W - 14.0);
                for (i, line) in lines.iter().enumerate() {
                    l.ensure(lead);
                    l.y -= lead;
                    if i == 0 {
                        l.text(MARGIN + 2.0, l.y, Font::Regular, 9.5, INK, "\u{2022}");
                    }
                    l.text(MARGIN + 14.0, l.y, Font::Regular, 9.5, INK, line);
                }
            }
            Block::Kv(rows) => {
                l.y -= 2.0;
                l.kv(MARGIN, CONTENT_W, rows);
            }
            Block::Finding { badge, title, rows } => {
                l.ensure(50.0);
                l.y -= 8.0;
                l.lines(
                    MARGIN,
                    CONTENT_W,
                    Font::Bold,
                    10.0,
                    INK,
                    &format!("[{}]  {}", badge, title),
                );
                l.kv(MARGIN + 10.0, CONTENT_W - 10.0, rows);
            }
            Block::Space(h) => l.y -= h,
        }
    }
    l.pages.push(l.cur);
    let total = l.pages.len();

    // Assemble objects: 1 catalog, 2 pages, 3-5 fonts, 6 info, then (page, content) pairs.
    let mut objects: Vec<String> = Vec::new();
    let kids: Vec<String> = (0..total).map(|i| format!("{} 0 R", 7 + 2 * i)).collect();
    objects.push("<< /Type /Catalog /Pages 2 0 R >>".into());
    objects.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {} >>",
        kids.join(" "),
        total
    ));
    for name in ["Helvetica", "Helvetica-Bold", "Courier"] {
        objects.push(format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
            name
        ));
    }
    let date = chrono::Utc::now().format("D:%Y%m%d%H%M%SZ").to_string();
    objects.push(format!(
        "<< /Title {} /Producer {} /Creator {} /CreationDate ({}) >>",
        pdf_string(title),
        pdf_string(producer),
        pdf_string(producer),
        date
    ));
    for (i, content) in l.pages.iter().enumerate() {
        let mut c = content.clone();
        let foot = format!(
            "{}  \u{2014}  {} {} {} {}",
            footer,
            page_word,
            i + 1,
            of_word,
            total
        );
        let _ = writeln!(
            c,
            "{:.3} {:.3} {:.3} RG 0.6 w {} {} m {} {} l S",
            LINE.0,
            LINE.1,
            LINE.2,
            MARGIN,
            44,
            PAGE_W - MARGIN,
            44
        );
        let _ = writeln!(
            c,
            "{:.3} {:.3} {:.3} rg BT /F1 7.5 Tf {} 32 Td {} Tj ET",
            MUTED.0,
            MUTED.1,
            MUTED.2,
            MARGIN,
            pdf_string(&foot)
        );
        objects.push(format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {} 0 R >>", PAGE_W, PAGE_H, 8 + 2 * i));
        objects.push(format!("<< /Length {} >>\nstream\n{}endstream", c.len(), c));
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, o) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, o).as_bytes());
    }
    let xref = out.len();
    let mut x = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for off in offsets {
        let _ = writeln!(x, "{:010} 00000 n ", off);
    }
    let _ = write!(
        x,
        "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref
    );
    out.extend_from_slice(x.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_a_wellformed_multi_page_pdf() {
        let mut blocks = vec![Block::Title("Informe técnico — señal «ça»".into())];
        for i in 0..120 {
            blocks.push(Block::Kv(vec![(
                format!("Clé {}", i),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            )]));
        }
        let pdf = render(&blocks, "t", "foot", "Page", "of", "test");
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&pdf);
        assert!(
            text.contains("/Count 3") || text.contains("/Count 4"),
            "multi-page"
        );
        assert!(text.contains("\\351"), "é encoded as WinAnsi octal");
    }

    #[test]
    fn wrapping_breaks_long_tokens() {
        let lines = wrap(&"a".repeat(400), Font::Mono, 8.0, 100.0);
        assert!(
            lines.len() > 1
                && lines
                    .iter()
                    .all(|l| text_width(l, Font::Mono, 8.0) <= 100.0)
        );
    }
}
