/*
    python.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

#![cfg(feature = "python")]



/// rust-python embedded interpreter

/// Input python script as arg
/// Expose GGX libraries, scripts, and inputted data (via cli and ffi) to the interpreter
/// Run the script and capture output
/// Actively output logs and return any returned data

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

