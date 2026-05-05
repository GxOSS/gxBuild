/*
    gxscript.rs - Rhai-based scripting engine and REPL for gxBuild

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use rhai::{Engine, Scope, AST};
use rustyline::DefaultEditor;
use std::sync::{Arc, Mutex};
use crate::core::session::Session;
use log::{info, error};

pub struct GxScriptEngine {
    engine: Engine,
    scope: Scope<'static>,
    session: Arc<Mutex<Session>>,
}

impl GxScriptEngine {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        let mut engine = Engine::new();
        let scope = Scope::new();

        // Register Session methods
        let s_clone = session.clone();
        engine.register_fn("set_option", move |key: &str, val: &str| {
            let mut s = s_clone.lock().unwrap();
            s.set_option(key, val);
        });

        let s_clone = session.clone();
        engine.register_fn("prepare", move || {
            let mut s = s_clone.lock().unwrap();
            // Default paths if not set
            let ini = std::path::PathBuf::from(".");
            let data = std::path::PathBuf::from("data");
            let common = std::path::PathBuf::from("../common");
            if let Err(e) = s.prepare_build(ini, data, common, "updflash.bin") {
                error!("[script] Prepare failed: {}", e);
            }
        });

        let s_clone = session.clone();
        engine.register_fn("run", move || {
            let mut s = s_clone.lock().unwrap();
            if let Err(e) = s.run() {
                error!("[script] Run failed: {}", e);
            }
        });

        let s_clone = session.clone();
        engine.register_fn("extract_all", move || {
            let mut s = s_clone.lock().unwrap();
            s.extract_all();
        });

        GxScriptEngine {
            engine,
            scope,
            session,
        }
    }

    /// Run a script file
    pub fn run_file(&mut self, path: &str) -> Result<(), String> {
        info!("[script] Running script: {}", path);
        self.engine.run_file_with_scope(&mut self.scope, path.into())
            .map_err(|e| format!("Script error: {}", e))
    }

    /// Start an interactive REPL
    pub fn repl(&mut self) {
        let mut rl = DefaultEditor::new().expect("Failed to initialize terminal editor");
        println!("gxBuild Scripting Shell (Rhai Engine)");
        println!("Type 'exit' or press Ctrl+C to quit.");

        loop {
            let readline = rl.readline("gx> ");
            match readline {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed == "exit" || trimmed == "quit" {
                        break;
                    }
                    if trimmed.is_empty() {
                        continue;
                    }
                    
                    let _ = rl.add_history_entry(trimmed);

                    match self.engine.eval_with_scope::<rhai::Dynamic>(&mut self.scope, trimmed) {
                        Ok(result) => {
                            if !result.is_unit() {
                                println!("=> {:?}", result);
                            }
                        }
                        Err(e) => {
                            error!("[script] Error: {}", e);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
}
