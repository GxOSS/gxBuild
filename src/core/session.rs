/*
    session.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};

use crate::core::commands::{extract, extract_all};
use crate::builder::builder::NandSkeleton;
use crate::core::commands::pygg::{python_interpreter, python_shell, python_script};
use crate::core::commands::xeini::{parse_xe_ini, apply_xe_ini};


#[derive(Debug, Clone)]
pub enum InternalCommand { 
    ParseIni { content: String, target: String, ini_base: PathBuf, common: PathBuf },
    ParseImage { path: PathBuf, key: Option<[u8; 16]> },
    ParseKey { key: String },
    ParseKeybin { key: Option<[u8; 16]> },
    ParseFlashfs { path: PathBuf },

    ParsePatch { path: PathBuf },
    ApplyPatch { path: PathBuf, ptype: u8, target: Option<u8> },

    Extract { id: String },
    ExtractAll,
    Replace { id: u8, path: PathBuf },
    List,
    Delete { id: u8 },
    Clear,

    Compress,
    Decompress,
    Update { path: PathBuf },

    Build { output: PathBuf, target: u8 },

    SessionInit { base: Option<PathBuf>, common: Option<PathBuf> },
    SessionList,
    SessionDelete,
    SessionClear,
    SessionRun,
    SessionClose,
}

impl InternalCommand {
    /// Hardcoded sorting values. Higher values get popped first by the BinaryHeap.
    fn priority_score(&self) -> u8 {
        match self {
            Self::ParseIni { .. } => 100,
            Self::RunPythonScript { .. } => 90,
            Self::ExtractAll | Self::Extract { .. } => 80,
            Self::Build => 50,
            Self::Update => 40,
            Self::PythonShell => 10,
        }
    }
}

#[derive(Debug)]
pub struct QueuedCommand {
    sequence_id: usize,
    command: InternalCommand,
}

impl Ord for QueuedCommand {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare priority score (higher score = runs sooner = Should be ordered as 'Greater')
        let p_cmp = self.command.priority_score().cmp(&other.command.priority_score());
        if p_cmp != Ordering::Equal {
            return p_cmp;
        }
        // Then sequence_id tie breaker (lower ID = enqueued earlier = Should be chosen sooner)
        other.sequence_id.cmp(&self.sequence_id)
    }
}

impl PartialOrd for QueuedCommand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for QueuedCommand {
    fn eq(&self, other: &Self) -> bool {
        self.command.priority_score() == other.command.priority_score()
            && self.sequence_id == other.sequence_id
    }
}

impl Eq for QueuedCommand {}


pub struct Session {
    queue: BinaryHeap<QueuedCommand>,
    next_seq_id: usize,
    /// Dummy state object for passing over to extract commands
    pub active_nand: Option<NandSkeleton>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_seq_id: 0,
            active_nand: None,
        }
    }

    fn enqueue(&mut self, command: InternalCommand) {
        self.queue.push(QueuedCommand {
            sequence_id: self.next_seq_id,
            command,
        });
        self.next_seq_id += 1;
    }

    // ------------------------------------
    // Fixed public methods (Interface API)
    // ------------------------------------

    pub fn extract(&mut self, id: String) {
        self.enqueue(InternalCommand::Extract { id });
    }

    pub fn extract_all(&mut self) {
        self.enqueue(InternalCommand::ExtractAll);
    }
    
    pub fn build(&mut self) {
        self.enqueue(InternalCommand::Build);
    }

    pub fn update(&mut self) {
        self.enqueue(InternalCommand::Update);
    }
    
    pub fn parse_ini(&mut self, content: String, target: String, ini_base: impl AsRef<Path>, common: impl AsRef<Path>) {
        self.enqueue(InternalCommand::ParseIni { 
            content, 
            target, 
            ini_base: ini_base.as_ref().to_path_buf(), 
            common: common.as_ref().to_path_buf() 
        });
    }

    pub fn run_python_script(&mut self, path: impl AsRef<Path>) {
        self.enqueue(InternalCommand::RunPythonScript { path: path.as_ref().to_path_buf() });
    }

    pub fn open_python_shell(&mut self) {
        self.enqueue(InternalCommand::PythonShell);
    }

    // ------------------------------------
    // Execution core
    // ------------------------------------
    pub fn run(&mut self) -> Result<(), String> {
        println!("[Session] Running {} queued commands...", self.queue.len());
        
        while let Some(queued_cmd) = self.queue.pop() {
            let priority = queued_cmd.command.priority_score();
            println!("[Session] Executing (PriorityScore: {}, Seq: {}): {:?}", 
                     priority, queued_cmd.sequence_id, queued_cmd.command);
                     
            match queued_cmd.command {
                InternalCommand::ExtractAll => {
                    let _ = extract_all(&self.active_nand);
                }
                InternalCommand::Extract { id } => {
                    let _ = extract(&self.active_nand, id);
                }
                InternalCommand::Build => {
                    println!(" -> Building image...");
                }
                InternalCommand::Update => {
                    println!(" -> Updating patches...");
                }
                InternalCommand::ParseIni { content, target, ini_base, common } => {
                     match parse_xe_ini(&content, &target, ini_base, common) {
                         Ok(ini_data) => {
                             if let Some(nand) = self.active_nand.clone() {
                                 let _ = apply_xe_ini(nand, ini_data);
                             }
                         },
                         Err(e) => eprintln!(" -> INI Parse Error: {}", e),
                     }
                }
                InternalCommand::RunPythonScript { path } => {
                    let interp = python_interpreter();
                    if let Err(e) = python_script(&interp, &path) {
                        eprintln!(" -> Python Execution Error: {}", e);
                    }
                }
                InternalCommand::PythonShell => {
                    let interp = python_interpreter();
                    if let Err(e) = python_shell(&interp) {
                        eprintln!(" -> Python Shell Error: {}", e);
                    }
                }
            }
        }
        println!("[Session] Finished priority queue batch.");
        Ok(())
    }
}