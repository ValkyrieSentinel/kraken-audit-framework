use genpdf::elements::{Paragraph, TableLayout, Text, Break};
use genpdf::{style, Document, Element}; 
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeakEvent {
    pub timestamp: String,
    pub protocol: String,
    pub entropy: f32,
    pub data_preview: String,
}

pub fn generate_pdf_report(session_id: &str, leaks: &Vec<LeakEvent>) -> Result<(), Box<dyn std::error::Error>> {
    let font_dir = "./fonts";
    
    
    let font_family = genpdf::fonts::from_files(font_dir, "Roboto", None)
        .map_err(|e| format!("Font error: {}", e))?;
    
    let mut doc = Document::new(font_family);
    
    
    doc.set_title(format!("KRAKEN AUDIT: {}", session_id));
    
    let title_style = style::Style::new().bold().with_font_size(18);
    
    
    doc.push(Paragraph::new("KRAKEN STEALTH AUDIT REPORT")
    .aligned(genpdf::Alignment::Center) 
    .styled(title_style));              
    
    doc.push(Break::new(2));

    
    let mut table = TableLayout::new(vec![1, 1, 1, 3]);
    
    
    let header_style = style::Style::new().bold();
    
    
    table.push_row(vec![
        Box::new(Text::new("Time").styled(header_style)),
        Box::new(Text::new("Proto").styled(header_style)),
        Box::new(Text::new("Entropy").styled(header_style)),
        Box::new(Text::new("Evidence").styled(header_style)),
    ]);

    
    for leak in leaks {
        
        let time_str = if leak.timestamp.len() >= 19 {
            &leak.timestamp[11..19]
        } else {
            &leak.timestamp
        };

        table.push_row(vec![
            Box::new(Text::new(time_str)),
            Box::new(Text::new(&leak.protocol)),
            Box::new(Text::new(format!("{:.2}", leak.entropy))),
            Box::new(Text::new(leak.data_preview.clone())),
        ]);
    }

    doc.push(table);
    
    let filename = format!("{}.pdf", session_id);
    doc.render_to_file(&filename)?;
    
    Ok(())
}