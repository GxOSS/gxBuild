/*
  gxscript.rs - Rhai-based scripting engine and REPL for gxBuild

  Copyright (c) 2026 gxBuild Contributors and Developers

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

use crate::core::interface::data::Session;
use crate::core::interface::handler::{Executor, InternalCommand};
use log::{error, info};
use rhai::{Engine, Scope};
use rustyline::DefaultEditor;
use std::sync::{Arc, Mutex};

pub struct GxScriptEngine {
    engine: Engine,
    scope: Scope<'static>,
}

impl GxScriptEngine {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        let mut engine = Engine::new();
        let scope = Scope::new();

        // Register Session methods
        let s_clone = session.clone();
        engine.register_fn("set_option", move |key: &str, val: &str| {
            let mut s = s_clone.lock().unwrap();
            s.build_config.options.set_option(key, val);
        });

        let s_clone = session.clone();
        engine.register_fn("prepare", move || {
            let mut s = s_clone.lock().unwrap();
            if let Err(e) = Executor::prepare_build(&mut s) {
                error!("[script] Prepare failed: {}", e);
            }
        });

        let s_clone = session.clone();
        engine.register_fn("apply_ecc", move |path: &str| {
            let mut s = s_clone.lock().unwrap();
            if let Err(e) = Executor::execute_command(
                &mut s,
                InternalCommand::ApplyEcc {
                    path: std::path::PathBuf::from(path),
                },
            ) {
                error!("[script] apply_ecc failed: {}", e);
            }
        });

        let s_clone = session.clone();
        engine.register_fn("extract_all", move || {
            let mut s = s_clone.lock().unwrap();
            if let Err(e) = Executor::execute_command(
                &mut s,
                InternalCommand::ExtractAll {
                    output_dir: std::path::PathBuf::from("."),
                    all: true,
                    include_decrypted: false,
                },
            ) {
                error!("[script] extract_all failed: {}", e);
            }
        });

        let s_clone = session.clone();
        engine.register_fn("extract_all", move |dir: &str| {
            let mut s = s_clone.lock().unwrap();
            if let Err(e) = Executor::execute_command(
                &mut s,
                InternalCommand::ExtractAll {
                    output_dir: std::path::PathBuf::from(dir),
                    all: true,
                    include_decrypted: false,
                },
            ) {
                error!("[script] extract_all failed: {}", e);
            }
        });

        GxScriptEngine { engine, scope }
    }

    pub fn run_file(&mut self, path: &str) -> Result<(), String> {
        info!("[script] Running script: {}", path);
        self.engine
            .run_file_with_scope(&mut self.scope, path.into())
            .map_err(|e| format!("Script error: {}", e))
    }

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

                    match self
                        .engine
                        .eval_with_scope::<rhai::Dynamic>(&mut self.scope, trimmed)
                    {
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
