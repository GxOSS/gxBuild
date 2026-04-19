/*
    python.rs - rust-python interpreter

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

#![cfg(feature = "python")]

// This file is marked for review; Unsure if it will persist to release.

use std::path::Path;
use std::fs;
use log::info;
use rustpython_vm::Interpreter;

#[cfg(feature = "tui")]
use rustyline::DefaultEditor;

pub fn python_interpreter() -> Interpreter {
    Interpreter::without_stdlib(Default::default())
}

#[cfg(feature = "tui")]
pub fn python_shell(interpreter: &Interpreter) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new().unwrap();
    info!("[session] Entering PyGG interactive shell (Ctrl+D to exit)");

    interpreter.enter(|vm| {
        let scope = vm.new_scope_with_builtins();

        loop {
            // Read
            let readline = rl.readline(">>> ");
            match readline {
                Ok(line) => {
                    if line.trim().is_empty() { continue; }
                    rl.add_history_entry(line.as_str()).ok();

                    // Evaluate & Print
                    match vm.run_code_string(scope.clone(), &line, "shell".to_string()) {
                        Ok(_) => (), // Mode::Single handles printing
                        Err(err) => vm.print_exception(err),
                    }
                }
                Err(_) => break, // Exit on Ctrl+C or Ctrl+D
            }
        }
    });
    Ok(())
}

pub fn python_script(interpreter: &Interpreter, script_path: impl AsRef<Path>) -> anyhow::Result<()> {
    // Pass by reference so we can use script_path again later
    let script = fs::read_to_string(&script_path)?; 

    interpreter.enter(|vm| {
        let scope = vm.new_scope_with_builtins();
        let path_str = script_path.as_ref().display().to_string();

        match vm.run_code_string(scope, &script, path_str.clone()) {
            Ok(_) => info!("[session] Script {} finished", path_str),
            Err(err) => {
                log::error!("[session] Script {} raised an exception:", path_str);
                vm.print_exception(err);
            }
        }
    });
    Ok(())
}

