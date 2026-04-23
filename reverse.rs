/*
 * LEXOLEN Reverse Engineering Toolkit
 * ===================================
 *
 * This Rust program implements a comprehensive reverse engineering toolkit
 * for binary analysis, malware unpacking, and vulnerability research.
 * It provides utilities for parsing executable formats, signature scanning,
 * basic disassembly, and automated analysis workflows.
 *
 * Features:
 * - Multi-format binary parsing (ELF, PE, Mach-O)
 * - YARA-style signature scanning
 * - Basic disassembly simulation
 * - Entropy analysis for packed executables
 * - String extraction and analysis
 * - Integration with IDA/Ghidra workflows
 * - Automated unpacking detection
 *
 * Dependencies: Standard library only (for portability)
 *               Consider adding goblin crate for advanced binary parsing
 *
 * Compilation: rustc reverse.rs -o reverse_analyzer
 *              or cargo build (if part of a Cargo project)
 *
 * Usage: ./reverse_analyzer <binary_file> [options]
 *
 * Author: LEXOLEN Team
 * Version: 1.0.0
 * License: MIT
 */

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process;

// Constants
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB limit
const SIGNATURE_SCAN_WINDOW: usize = 4096;
const ENTROPY_THRESHOLD: f64 = 7.0; // High entropy indicates packing

// Data structures
#[derive(Debug, Clone)]
enum BinaryFormat {
    ELF,
    PE,
    MachO,
    Unknown,
}

#[derive(Debug)]
struct BinaryHeader {
    format: BinaryFormat,
    architecture: String,
    entry_point: u64,
    sections: Vec<SectionInfo>,
}

#[derive(Debug)]
struct SectionInfo {
    name: String,
    offset: u64,
    size: u64,
    entropy: f64,
    is_executable: bool,
}

#[derive(Debug)]
struct SignatureMatch {
    offset: u64,
    signature_name: String,
    confidence: f64,
}

#[derive(Debug)]
struct AnalysisReport {
    file_path: String,
    file_size: u64,
    header: Option<BinaryHeader>,
    signatures: Vec<SignatureMatch>,
    strings: Vec<String>,
    entropy_score: f64,
    is_packed: bool,
    recommendations: Vec<String>,
}

// Error handling
#[derive(Debug)]
enum AnalysisError {
    IoError(io::Error),
    InvalidFormat(String),
    FileTooLarge(u64),
    UnsupportedArchitecture(String),
}

impl From<io::Error> for AnalysisError {
    fn from(error: io::Error) -> Self {
        AnalysisError::IoError(error)
    }
}

type AnalysisResult<T> = Result<T, AnalysisError>;

/*
 * Binary format detection
 *
 * Pseudo-code for format detection:
 * 1. Read first 64 bytes of file
 * 2. Check magic bytes for known formats:
 *    a. ELF: 0x7F 'E' 'L' 'F'
 *    b. PE: 'M' 'Z' followed by PE header
 *    c. Mach-O: 0xFEEDFACE or 0xFEEDFACF
 * 3. If no match, classify as Unknown
 * 4. Extract basic header information
 * 5. Return format enum and confidence score
 */
fn detect_binary_format(data: &[u8]) -> BinaryFormat {
    if data.len() < 4 {
        return BinaryFormat::Unknown;
    }

    // ELF detection
    if data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        return BinaryFormat::ELF;
    }

    // PE detection (MZ header)
    if data[0] == b'M' && data[1] == b'Z' {
        // Check for PE signature at offset 0x3C
        if data.len() > 0x40 {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
            if pe_offset < data.len() - 4 {
                if &data[pe_offset..pe_offset+4] == b"PE\0\0" {
                    return BinaryFormat::PE;
                }
            }
        }
    }

    // Mach-O detection (32-bit or 64-bit)
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic == 0xFEEDFACE || magic == 0xFEEDFACF {
        return BinaryFormat::MachO;
    }

    BinaryFormat::Unknown
}

/*
 * Entropy calculation for packing detection
 *
 * Pseudo-code for entropy calculation:
 * 1. Count frequency of each byte value (0-255)
 * 2. Calculate Shannon entropy: H = -sum(p_i * log2(p_i))
 * 3. Normalize by maximum possible entropy (8 bits)
 * 4. High entropy (>7.0) suggests compression/encryption
 * 5. Return entropy score and packing probability
 */
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let data_len = data.len() as f64;
    let mut entropy = 0.0;

    for &freq in &frequencies {
        if freq > 0 {
            let p = freq as f64 / data_len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/*
 * Signature scanning implementation
 *
 * Pseudo-code for signature scanning:
 * 1. Load signature database (YARA-style patterns)
 * 2. For each signature:
 *    a. Convert pattern to byte sequence
 *    b. Scan file in windows of pattern length
 *    c. Use efficient string search algorithm (Boyer-Moore)
 *    d. Calculate match confidence based on context
 * 3. Return list of matches with offsets and confidence
 * 4. Optimize for large files using memory mapping
 */
fn scan_signatures(data: &[u8]) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();

    // Simple signature database - in practice, load from external file
    let signatures = vec![
        ("UPX_packed", vec![0x60, 0xE8, 0x00, 0x00, 0x00, 0x00]), // UPX header
        ("MZ_header", vec![0x4D, 0x5A]), // DOS MZ
        ("ELF_header", vec![0x7F, 0x45, 0x4C, 0x46]), // ELF magic
    ];

    for (name, pattern) in signatures {
        let mut offset = 0;
        while let Some(pos) = find_pattern(&data[offset..], &pattern) {
            let absolute_offset = offset + pos;
            matches.push(SignatureMatch {
                offset: absolute_offset as u64,
                signature_name: name.to_string(),
                confidence: 0.9, // Simplified confidence
            });
            offset = absolute_offset + 1; // Continue search after match
        }
    }

    matches
}

/*
 * Pattern matching helper function
 */
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }

    for i in 0..=data.len() - pattern.len() {
        if data[i..i + pattern.len()] == pattern[..] {
            return Some(i);
        }
    }
    None
}

/*
 * String extraction from binary
 *
 * Pseudo-code for string extraction:
 * 1. Scan binary data for printable ASCII sequences
 * 2. Minimum string length threshold (4+ characters)
 * 3. Stop at null terminator or non-printable character
 * 4. Filter out common false positives (code patterns)
 * 5. Return list of extracted strings with offsets
 */
fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= min_length {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
            }
            current_string.clear();
        }
    }

    // Handle string at end of file
    if current_string.len() >= min_length {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.push(s);
        }
    }

    strings
}

/*
 * Basic disassembly simulation
 *
 * Pseudo-code for disassembly:
 * 1. Identify code sections from binary header
 * 2. For each instruction:
 *    a. Read opcode byte(s)
 *    b. Decode instruction using architecture-specific rules
 *    c. Extract operands (registers, immediates, addresses)
 *    d. Calculate next instruction address
 * 3. Handle control flow (jumps, calls, returns)
 * 4. Generate assembly-like output
 * 5. Detect common patterns (function prologues, loops)
 */
fn simulate_disassembly(data: &[u8], start_offset: usize, num_instructions: usize) -> Vec<String> {
    let mut disassembly = Vec::new();
    let mut offset = start_offset;

    // Very simplified x86 disassembly simulation
    for _ in 0..num_instructions {
        if offset >= data.len() {
            break;
        }

        let opcode = data[offset];
        let instruction = match opcode {
            0x90 => "nop".to_string(),
            0xC3 => "ret".to_string(),
            0x55 => "push ebp".to_string(),
            0x89 => {
                if offset + 1 < data.len() {
                    match data[offset + 1] {
                        0xE5 => {
                            offset += 1;
                            "mov ebp, esp".to_string()
                        }
                        _ => format!("mov ??? (opcode: 0x{:02X})", opcode),
                    }
                } else {
                    format!("incomplete mov (opcode: 0x{:02X})", opcode)
                }
            }
            _ => format!("unknown (opcode: 0x{:02X})", opcode),
        };

        disassembly.push(format!("0x{:08X}: {}", offset, instruction));
        offset += 1;
    }

    disassembly
}

/*
 * Comprehensive binary analysis
 *
 * Pseudo-code for full analysis workflow:
 * 1. Validate input file and permissions
 * 2. Read file into memory with size limits
 * 3. Detect binary format and parse header
 * 4. Extract sections and calculate entropy
 * 5. Scan for known signatures
 * 6. Extract printable strings
 * 7. Perform basic disassembly on code sections
 * 8. Generate analysis report with findings
 * 9. Provide recommendations for further analysis
 */
fn analyze_binary(file_path: &str) -> AnalysisResult<AnalysisReport> {
    // Validate file
    let metadata = fs::metadata(file_path)?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(AnalysisError::FileTooLarge(metadata.len()));
    }

    // Read file
    let mut file = fs::File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Detect format
    let format = detect_binary_format(&data);

    // Calculate entropy
    let entropy = calculate_entropy(&data);
    let is_packed = entropy > ENTROPY_THRESHOLD;

    // Scan signatures
    let signatures = scan_signatures(&data);

    // Extract strings
    let strings = extract_strings(&data, 4);

    // Simulate basic header parsing (simplified)
    let header = Some(BinaryHeader {
        format: format.clone(),
        architecture: "x86_64".to_string(), // Simplified
        entry_point: 0x1000, // Placeholder
        sections: vec![], // Would parse actual sections
    });

    // Generate recommendations
    let mut recommendations = Vec::new();
    if is_packed {
        recommendations.push("File appears packed - consider unpacking before analysis".to_string());
    }
    if !signatures.is_empty() {
        recommendations.push("Known signatures detected - cross-reference with threat intelligence".to_string());
    }
    if strings.len() > 100 {
        recommendations.push("Large number of strings found - analyze for sensitive data leakage".to_string());
    }
    recommendations.push("Load in IDA/Ghidra for detailed reverse engineering".to_string());

    Ok(AnalysisReport {
        file_path: file_path.to_string(),
        file_size: data.len() as u64,
        header,
        signatures,
        strings,
        entropy_score: entropy,
        is_packed,
        recommendations,
    })
}

/*
 * Report generation and display
 */
fn display_report(report: &AnalysisReport) {
    println!("=== LEXOLEN Binary Analysis Report ===");
    println!("File: {}", report.file_path);
    println!("Size: {} bytes", report.file_size);
    println!("Entropy: {:.2f} (Packed: {})", report.entropy_score, report.is_packed);

    if let Some(header) = &report.header {
        println!("Format: {:?}", header.format);
        println!("Architecture: {}", header.architecture);
        println!("Entry Point: 0x{:X}", header.entry_point);
    }

    println!("\nSignatures Found: {}", report.signatures.len());
    for sig in &report.signatures {
        println!("  0x{:X}: {} (confidence: {:.1}%)",
                sig.offset, sig.signature_name, sig.confidence * 100.0);
    }

    println!("\nStrings Extracted: {}", report.strings.len());
    for (i, string) in report.strings.iter().enumerate() {
        if i >= 10 { // Limit display
            println!("  ... and {} more", report.strings.len() - 10);
            break;
        }
        println!("  {}", string);
    }

    println!("\nRecommendations:");
    for rec in &report.recommendations {
        println!("  - {}", rec);
    }
}

/*
 * Main function with argument parsing
 *
 * Pseudo-code for main workflow:
 * 1. Parse command-line arguments
 * 2. Validate input file exists and is readable
 * 3. Call binary analysis function
 * 4. Display results or handle errors
 * 5. Exit with appropriate status code
 */
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <binary_file>", args[0]);
        eprintln!("LEXOLEN Reverse Engineering Toolkit v1.0.0");
        process::exit(1);
    }

    let file_path = &args[1];

    if !Path::new(file_path).exists() {
        eprintln!("Error: File '{}' does not exist", file_path);
        process::exit(1);
    }

    match analyze_binary(file_path) {
        Ok(report) => {
            display_report(&report);
            println!("\nAnalysis completed successfully!");
        }
        Err(e) => {
            eprintln!("Analysis failed: {:?}", e);
            process::exit(1);
        }
    }
}
