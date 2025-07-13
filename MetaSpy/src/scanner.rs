use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use colored::Colorize;
use lopdf::Document;
use rexif::{ExifTag::*, TagValue};
use walkdir::WalkDir;

pub fn scan(path: &Path) {
    println!("{} {:?}", "📁 Scanning".green().bold(), path);

    for entry in WalkDir::new(path) {
        if let Ok(entry) = entry {
            let file_path = entry.path();
            if file_path.is_file() {
                let ext = file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                match ext.as_str() {
                    "jpg" | "jpeg" | "png" | "tiff" => scan_image(file_path),
                    "pdf" => scan_pdf(file_path),
                    _ => {}
                }
            }
        }
    }
}

fn scan_image(path: &Path) {
    match File::open(path) {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            let mut buffer = Vec::new();

            if reader.read_to_end(&mut buffer).is_ok() {
                println!("\n📷 {}", path.display());

                match rexif::parse_buffer(&buffer) {
                    Ok(exif_data) => {
                        let mut found_sensitive = false;
                        let sensitive_tags = [
                            GPSLatitude,
                            GPSLongitude,
                            GPSLatitudeRef,
                            GPSLongitudeRef,
                            Make,
                            Model,
                            DateTimeOriginal,
                            Software,
                            Copyright,
                        ];

                        for entry in &exif_data.entries {
                            println!("{}: {}", entry.tag, entry.value);

                            if sensitive_tags.contains(&entry.tag) {
                                found_sensitive = true;
                            }
                        }

                        let lat = exif_data.entries.iter().find(|e| e.tag == GPSLatitude);
                        let lon = exif_data.entries.iter().find(|e| e.tag == GPSLongitude);
                        let lat_ref = exif_data.entries.iter().find(|e| e.tag == GPSLatitudeRef);
                        let lon_ref = exif_data.entries.iter().find(|e| e.tag == GPSLongitudeRef);

                        if let (Some(lat), Some(lon), Some(lat_ref), Some(lon_ref)) =
                            (lat, lon, lat_ref, lon_ref)
                        {
                            println!("\nRaw GPS Data:");
                            println!("Latitude: {} {}", lat.value, lat_ref.value);
                            println!("Longitude: {} {}", lon.value, lon_ref.value);

                            match (
                                parse_gps_coordinate(&lat.value, &lat_ref.value),
                                parse_gps_coordinate(&lon.value, &lon_ref.value),
                            ) {
                                (Ok(lat_dec), Ok(lon_dec)) => {
                                    println!(
                                        "{} {}",
                                        "⚠ Found GPS location:".yellow(),
                                        format!("Lat: {:.6}", lat_dec)
                                    );
                                    println!(
                                        "{} {}",
                                        " ".repeat(20),
                                        format!("Lon: {:.6}", lon_dec)
                                    );
                                    println!(
                                        "{} {}",
                                        "🔗 Google Maps:".blue(),
                                        format!(
                                            "https://maps.google.com?q={:.6},{:.6}",
                                            lat_dec, lon_dec
                                        )
                                    );
                                }
                                (Err(e), _) | (_, Err(e)) => {
                                    println!(
                                        "{} {}",
                                        "⚠ Could not parse GPS coordinates:".yellow(),
                                        e
                                    );
                                }
                            }
                        } else if !found_sensitive {
                            println!("{}", "✅ No sensitive metadata found".green());
                        }
                    }
                    Err(e) => {
                        println!("{} {}", "⚠ Could not parse EXIF data:".yellow(), e);
                    }
                }
            } else {
                println!("{} {}", "⚠ Could not read file:".yellow(), path.display());
            }
        }
        Err(e) => {
            println!("{} {}", "❌ Could not open file:".red(), e);
        }
    }
}

fn parse_gps_coordinate(coord_val: &TagValue, ref_val: &TagValue) -> Result<f64, &'static str> {
    use TagValue::{Ascii, URational};

    let (degrees, minutes, seconds) = match coord_val {
        URational(parts) if parts.len() == 3 => {
            let d = parts[0].numerator as f64 / parts[0].denominator as f64;
            let m = parts[1].numerator as f64 / parts[1].denominator as f64;
            let s = parts[2].numerator as f64 / parts[2].denominator as f64;
            (d, m, s)
        }
        _ => return Err("Expected 3 URational parts (degrees, minutes, seconds)"),
    };

    if let Ascii(v) = ref_val {
        let direction = v;
        let decimal = degrees + (minutes / 60.0) + (seconds / 3600.0);

        if direction.contains('S') || direction.contains('W') {
            Ok(-decimal)
        } else {
            Ok(decimal)
        }
    } else {
        Err("Invalid direction format (expected ASCII)")
    }
}

fn scan_pdf(path: &Path) {
    match Document::load(path) {
        Ok(doc) => {
            println!("\n📄 {}", path.display());
            let mut found_metadata = false;
            let mut found_sensitive = false;

            let sensitive_fields = [
                b"Author".as_ref(),
                b"Creator".as_ref(),
                b"Producer".as_ref(),
                b"CreationDate".as_ref(),
                b"ModDate".as_ref(),
                b"Keywords".as_ref(),
                b"Subject".as_ref(),
                b"Title".as_ref(),
                b"Company".as_ref(),
            ];

            if let Ok(info_ref) = doc.trailer.get(b"Info") {
                if let Ok(info_dict) = doc.get_dictionary(info_ref.as_reference().unwrap()) {
                    for (key, value) in info_dict.iter() {
                        let key_str = String::from_utf8_lossy(key);
                        let value_str = format!("{:?}", value);

                        println!("{}: {}", key_str, value_str);
                        found_metadata = true;

                        if sensitive_fields.contains(&key.as_slice()) {
                            println!("{} {}", "⚠ Sensitive field:".yellow(), key_str);
                            found_sensitive = true;
                        }
                    }
                }
            }

            if !found_metadata {
                println!("{}", "✅ No metadata found".green());
            } else if !found_sensitive {
                println!("{}", "✅ No sensitive metadata found".green());
            }
        }
        Err(e) => {
            println!("{} {}", "❌ Could not read PDF:".red(), e);
        }
    }
}
