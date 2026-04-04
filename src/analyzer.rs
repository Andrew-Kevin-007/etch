use std::fs;
use std::path::Path;
use tree_sitter::{Parser, Language, Query, QueryCursor};
use streaming_iterator::StreamingIterator;

pub struct FileAnalysis {
    pub language: String,
    pub function_count: usize,
    pub new_abstractions: usize, // structs/enums/traits/interfaces
    pub cyclomatic_complexity: usize,
    pub has_new_control_flow: bool,
    pub is_test_only: bool,
    pub has_dead_code: bool,
}

pub fn parse_file(path: &str) -> Result<(FileAnalysis, tree_sitter::Tree, String), Box<dyn std::error::Error>> {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    let (language_name, ts_language) = match extension {
        "rs" => ("rust", tree_sitter_rust::LANGUAGE.into()),
        "py" => ("python", tree_sitter_python::LANGUAGE.into()),
        "js" => ("javascript", tree_sitter_javascript::LANGUAGE.into()),
        "ts" => ("typescript", tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => return Err(format!("Unsupported extension: {}", extension).into()),
    };

    let source_code = fs::read_to_string(path)?;
    let mut parser = Parser::new();
    parser.set_language(&ts_language)?;

    let tree = parser.parse(&source_code, None)
        .ok_or("Failed to parse file")?;

    let (function_query_str, abstraction_query_str, complexity_query_str, control_flow_query_str) = match language_name {
        "rust" => (
            "(function_item) @func",
            "(struct_item) @abs (enum_item) @abs (trait_item) @abs",
            "(if_expression) @comp (match_arm) @comp (for_expression) @comp (while_expression) @comp (loop_expression) @comp",
            "(if_expression) @cf (match_expression) @cf (for_expression) @cf (while_expression) @cf (loop_expression) @cf",
        ),
        "python" => (
            "(function_definition) @func",
            "(class_definition) @abs",
            "(if_statement) @comp (for_statement) @comp (while_statement) @comp (with_statement) @comp (except_clause) @comp",
            "(if_statement) @cf (for_statement) @cf (while_statement) @cf",
        ),
        "javascript" | "typescript" => (
            "(function_declaration) @func (method_definition) @func (arrow_function) @func",
            "(class_declaration) @abs (interface_declaration) @abs (enum_declaration) @abs",
            "(if_statement) @comp (for_statement) @comp (for_in_statement) @comp (for_of_statement) @comp (while_statement) @comp (do_statement) @comp (switch_case) @comp (catch_clause) @comp",
            "(if_statement) @cf (for_statement) @cf (while_statement) @cf (switch_statement) @cf",
        ),
        _ => unreachable!(),
    };

    let function_count = count_matches(&ts_language, &tree, &source_code, function_query_str);
    let new_abstractions = count_matches(&ts_language, &tree, &source_code, abstraction_query_str);
    let complexity_matches = count_matches(&ts_language, &tree, &source_code, complexity_query_str);
    let has_new_control_flow = count_matches(&ts_language, &tree, &source_code, control_flow_query_str) > 0;
    let has_dead_code = detect_dead_code(&tree, &source_code, language_name);

    // Detect test-only files: check for #[test] attributes or test_ prefixed functions
    let is_test_only = if function_count > 0 {
        let test_query_str = match language_name {
            "rust" => "(attribute_item (attribute (identifier) @attr)) @test_attr
                       (function_item name: (identifier) @fn_name)",
            "python" => "(function_definition name: (identifier) @fn_name)",
            "javascript" | "typescript" => "(function_declaration name: (identifier) @fn_name)",
            _ => "(function_definition name: (identifier) @fn_name)",
        };
        if let Ok(query) = Query::new(&ts_language, test_query_str) {
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());

            let mut total_functions = 0;
            let mut test_functions = 0;
            let mut has_test_attr = false;

            while let Some(m) = matches.next() {
                for capture in m.captures {
                    let name = query.capture_names()[capture.index as usize];
                    let node = capture.node;
                    let text = node.utf8_text(source_code.as_bytes()).unwrap_or("");

                    if name == "test_attr" && text == "test" {
                        has_test_attr = true;
                    } else if name == "fn_name" {
                        total_functions += 1;
                        if text.starts_with("test_") || text.contains("test") {
                            test_functions += 1;
                        }
                    }
                }
            }

            // Test-only if: has #[test] attr, OR all functions are test-prefixed
            has_test_attr || (total_functions > 0 && test_functions == total_functions)
        } else {
            false
        }
    } else {
        false
    };

    Ok((FileAnalysis {
        language: language_name.to_string(),
        function_count,
        new_abstractions,
        cyclomatic_complexity: 1 + complexity_matches,
        has_new_control_flow,
        is_test_only,
        has_dead_code,
    }, tree, source_code))
}

fn count_matches(language: &Language, tree: &tree_sitter::Tree, source_code: &str, query_str: &str) -> usize {
    let query = match Query::new(language, query_str) {
        Ok(q) => q,
        Err(_) => return 0,
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());
    let mut count = 0;
    while let Some(_) = matches.next() {
        count += 1;
    }
    count
}

pub fn detect_dead_code(tree: &tree_sitter::Tree, source: &str, language: &str) -> bool {
    let root = tree.root_node();
    let lang = tree.language();

    // 1. Detect functions defined but never called within the same file
    let mut defined_functions = Vec::new();
    let mut called_functions = Vec::new();

    let func_def_query_str = match language {
        "rust" => "(function_item name: (identifier) @name)",
        "python" => "(function_definition name: (identifier) @name)",
        "javascript" | "typescript" => "(function_declaration name: (identifier) @name)",
        _ => "(function_definition name: (identifier) @name)",
    };

    if let Ok(query) = Query::new(&lang, func_def_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let name = query.capture_names()[capture.index as usize];
                if name == "name" {
                    if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                        defined_functions.push(text.to_string());
                    }
                }
            }
        }
    }

    let func_call_query_str = match language {
        "rust" | "python" | "javascript" | "typescript" => "(call_expression function: (identifier) @name)",
        _ => "(call_expression function: (identifier) @name)",
    };

    if let Ok(query) = Query::new(&lang, func_call_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let name = query.capture_names()[capture.index as usize];
                if name == "name" {
                    if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                        called_functions.push(text.to_string());
                    }
                }
            }
        }
    }

    // Check for defined but uncalled functions (excluding main and common entry points)
    for func in &defined_functions {
        if func != "main" && func != "new" && func != "default" && !called_functions.contains(func) {
            return true;
        }
    }

    // 2. Detect branches that are always true/false (if true {}, if false {})
    let const_branch_query_str = match language {
        "rust" => "(if_expression condition: (boolean_literal) @const_bool)",
        "python" | "javascript" | "typescript" => "(if_statement condition: (boolean_literal) @const_bool)",
        _ => "(if_statement condition: (boolean_literal) @const_bool)",
    };

    if let Ok(query) = Query::new(&lang, const_branch_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        if matches.next().is_some() {
            return true;
        }
    }

    // 3. Detect code after a return statement inside a block
    let unreachable_query_str = match language {
        "rust" => "(block (expression_statement) @stmt (return_expression) @ret (_) @after)",
        "python" => "(block (expression_statement) @stmt (return_statement) @ret (_) @after)",
        "javascript" | "typescript" => "(statement_block (expression_statement) @stmt (return_statement) @ret (_) @after)",
        _ => "(block (expression_statement) @stmt (return_statement) @ret (_) @after)",
    };

    if let Ok(query) = Query::new(&lang, unreachable_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        if matches.next().is_some() {
            return true;
        }
    }

    // 4. Detect variables assigned but never read
    let var_assign_query_str = match language {
        "rust" => "[(let_declaration pattern: (identifier) @var) (let_statement pattern: (identifier) @var) (assignment_expression left: (identifier) @var)]",
        "python" => "(assignment left: (identifier) @var)",
        "javascript" | "typescript" => "[(lexical_declaration (variable_declarator name: (identifier) @var)) (variable_declaration (variable_declarator name: (identifier) @var)) (assignment_expression left: (identifier) @var)]",
        _ => "[(assignment_expression left: (identifier) @var)]",
    };

    let var_assign_query = Query::new(&lang, var_assign_query_str).ok();
    let var_read_query = Query::new(&lang, "(identifier) @var").ok();

    if let (Some(aq), Some(rq)) = (var_assign_query, var_read_query) {
        let mut assigned_vars: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut read_vars: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&aq, root, source.as_bytes());
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let name = aq.capture_names()[capture.index as usize];
                if name == "var" {
                    if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                        *assigned_vars.entry(text.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&rq, root, source.as_bytes());
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let name = rq.capture_names()[capture.index as usize];
                if name == "var" {
                    if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                        *read_vars.entry(text.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Check for assigned but unread variables
        for (var, assign_count) in &assigned_vars {
            let read_count = read_vars.get(var).copied().unwrap_or(0);
            // If assigned more times than read, likely dead code
            if assign_count > &read_count {
                return true;
            }
        }
    }

    false
}

pub struct LogicReport {
    pub high_complexity_functions: usize,  // functions with complexity > 3
    pub control_flow_count: usize,         // if/match/loop/while nodes
    pub error_handling_count: usize,       // Result/Option/try usage
    pub logic_present: bool,               // true if any of the above > 0
}

pub struct ArchitectureReport {
    pub new_structs_enums_traits: usize,   // struct/enum/trait/impl definitions
    pub new_modules: usize,                // mod declarations
    pub architecture_present: bool,        // true if any of the above > 0
}

pub fn detect_logic(tree: &tree_sitter::Tree, source: &str, language: &str) -> LogicReport {
    let root = tree.root_node();
    let mut high_complexity_functions = 0;
    let mut control_flow_count = 0;
    let mut error_handling_count = 0;

    // Count control flow nodes (if/match/loop/while)
    let control_flow_query_str = match language {
        "rust" => "(if_expression) @cf (match_expression) @cf (for_expression) @cf (while_expression) @cf (loop_expression) @cf",
        "python" => "(if_statement) @cf (for_statement) @cf (while_statement) @cf",
        "javascript" | "typescript" => "(if_statement) @cf (for_statement) @cf (while_statement) @cf (switch_statement) @cf",
        _ => "(if_statement) @cf (for_statement) @cf (while_statement) @cf",
    };

    if let Ok(query) = Query::new(&tree.language(), control_flow_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(_) = matches.next() {
            control_flow_count += 1;
        }
    }

    // Count error handling (Result/Option/try)
    let error_handling_query_str = match language {
        "rust" => "(generic_type (type_identifier) @t) @gt (primitive_type) @prim (try_expression) @try",
        "python" => "(try_statement) @try",
        "javascript" | "typescript" => "(try_statement) @try",
        _ => "(try_statement) @try",
    };

    if let Ok(query) = Query::new(&tree.language(), error_handling_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(m) = matches.next() {
            for capture in m.captures {
                let name = query.capture_names()[capture.index as usize];
                let node = capture.node;
                let text = node.utf8_text(source.as_bytes()).unwrap_or("");
                if name == "t" && (text == "Result" || text == "Option") {
                    error_handling_count += 1;
                } else if name == "try" {
                    error_handling_count += 1;
                }
            }
        }
    }

    // Count functions with complexity > 3
    let (function_query_str, body_name, cf_query_str) = match language {
        "rust" => (
            "(function_item name: (identifier) @fn_name body: (block) @fn_body)",
            "fn_body",
            "(if_expression) @if (match_expression) @match (for_expression) @for (while_expression) @while (loop_expression) @loop",
        ),
        "python" => (
            "(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
            "fn_body",
            "(if_statement) @if (for_statement) @for (while_statement) @while",
        ),
        "javascript" | "typescript" => (
            "(function_declaration name: (identifier) @fn_name body: (statement_block) @fn_body)",
            "fn_body",
            "(if_statement) @if (for_statement) @for (while_statement) @while (switch_statement) @switch",
        ),
        _ => (
            "(function_definition name: (identifier) @fn_name body: (block) @fn_body)",
            "fn_body",
            "(if_statement) @if (for_statement) @for (while_statement) @while",
        ),
    };

    if let Ok(query) = Query::new(&tree.language(), function_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(m) = matches.next() {
            let mut complexity = 1;
            for capture in m.captures {
                let name = query.capture_names()[capture.index as usize];
                if name == body_name {
                    let body = capture.node;
                    // Count control flow within function body
                    if let Ok(cf_query) = Query::new(&tree.language(), cf_query_str) {
                        let mut cf_cursor = QueryCursor::new();
                        let mut cf_matches = cf_cursor.matches(&cf_query, body, source.as_bytes());
                        while let Some(_) = cf_matches.next() {
                            complexity += 1;
                        }
                    }
                }
            }
            if complexity > 3 {
                high_complexity_functions += 1;
            }
        }
    }

    let logic_present = control_flow_count > 0 || high_complexity_functions > 0 || error_handling_count > 0;

    LogicReport {
        high_complexity_functions,
        control_flow_count,
        error_handling_count,
        logic_present,
    }
}

pub fn detect_architecture(tree: &tree_sitter::Tree, source: &str, language: &str) -> ArchitectureReport {
    let root = tree.root_node();
    let mut new_structs_enums_traits = 0;
    let mut new_modules = 0;

    // Count struct/enum/trait/impl definitions
    let architecture_query_str = match language {
        "rust" => "(struct_item) @struct (enum_item) @enum (trait_item) @trait (impl_item) @impl",
        "python" => "(class_definition) @class",
        "javascript" | "typescript" => "(class_declaration) @class (interface_declaration) @interface (enum_declaration) @enum",
        _ => "(class_definition) @class",
    };

    if let Ok(query) = Query::new(&tree.language(), architecture_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(_) = matches.next() {
            new_structs_enums_traits += 1;
        }
    }

    // Count mod declarations
    let module_query_str = match language {
        "rust" => "(mod_item) @mod",
        "python" => "(import_statement) @mod (import_from_statement) @mod",
        "javascript" | "typescript" => "(import_statement) @mod",
        _ => "(import_statement) @mod",
    };

    if let Ok(query) = Query::new(&tree.language(), module_query_str) {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, root, source.as_bytes());
        while let Some(_) = matches.next() {
            new_modules += 1;
        }
    }

    let architecture_present = new_structs_enums_traits > 0 || new_modules > 0;

    ArchitectureReport {
        new_structs_enums_traits,
        new_modules,
        architecture_present,
    }
}

pub struct ContributionVerdict {
    pub qualifies: bool,
    pub score: f32,
    pub reason: String,
}

pub fn score_contribution(
    analysis: &FileAnalysis,
    logic: &LogicReport,
    arch: &ArchitectureReport,
) -> ContributionVerdict {
    // Supported file extensions for etch contributions
    const SUPPORTED_EXTENSIONS: &[&str] = &["rust", "python", "javascript", "typescript", "go", "cpp", "c", "java"];

    // HARD DISQUALIFIER 1: Unsupported file extension
    if !SUPPORTED_EXTENSIONS.contains(&analysis.language.as_str()) {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "unsupported file type".to_string(),
        };
    }

    // HARD DISQUALIFIER 2: No logic or architecture detected
    if !logic.logic_present && !arch.architecture_present {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "no logic or architecture detected".to_string(),
        };
    }

    // HARD DISQUALIFIER 3: Abstraction spam without logic
    if arch.new_structs_enums_traits > 5 && !logic.logic_present {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "abstraction spam detected — no logic present".to_string(),
        };
    }

    // HARD DISQUALIFIER 4: Control flow inflation without complexity
    if logic.control_flow_count > 10 && logic.high_complexity_functions == 0 {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "control flow inflation detected".to_string(),
        };
    }

    // HARD DISQUALIFIER 5: Dead code / unreachable complexity
    if analysis.has_dead_code {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "unreachable or dead code detected — contribution must contain only executable logic".to_string(),
        };
    }

    // HARD DISQUALIFIER 6: Test-only contribution
    if analysis.is_test_only {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "test-only contribution does not qualify".to_string(),
        };
    }

    // HARD DISQUALIFIER 7: Refactoring laundering (structural reorg without logic)
    if arch.architecture_present && !logic.logic_present && arch.new_structs_enums_traits <= 3 {
        return ContributionVerdict {
            qualifies: false,
            score: 0.0,
            reason: "structural reorganization without new logic detected".to_string(),
        };
    }

    // SCORING (only reached if no hard disqualifiers)
    let mut base_score = 0.0;

    // Logic presence: +0.4
    if logic.logic_present {
        base_score += 0.4;
    }

    // Architecture presence with scaled abstraction score (no cliff)
    if arch.architecture_present {
        let arch_score = (0.3 - (arch.new_structs_enums_traits.saturating_sub(1) as f32 * 0.06)).max(0.0);
        base_score += arch_score;
    }

    // High complexity functions: +0.2
    if logic.high_complexity_functions > 0 {
        base_score += 0.2;
    }

    // Control flow with inflation penalty
    if logic.control_flow_count > 0 && logic.control_flow_count <= 5 {
        base_score += 0.1;
    }
    // control_flow_count > 5: +0.0 (penalize control flow inflation)

    // FINAL VERDICT
    let qualifies = base_score >= 0.6;
    let reason = if qualifies {
        "contribution meets etch authorship threshold".to_string()
    } else {
        let mut missing = Vec::new();
        if !logic.logic_present {
            missing.push("no substantive logic present");
        }
        if !arch.architecture_present {
            missing.push("no architectural contribution");
        } else if arch.new_structs_enums_traits > 3 {
            missing.push("excessive abstractions reduce score");
        }
        if logic.high_complexity_functions == 0 {
            missing.push("no high-complexity functions");
        }
        if logic.control_flow_count == 0 || logic.control_flow_count > 5 {
            missing.push("control flow contribution missing or inflated");
        }
        format!("contribution falls short: {}", missing.join(", "))
    };

    ContributionVerdict {
        qualifies,
        score: base_score,
        reason,
    }
}
