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
}

pub fn parse_file(path: &str) -> Result<FileAnalysis, Box<dyn std::error::Error>> {
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
            "(function_item) @func (impl_item (function_item) @func)",
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

    Ok(FileAnalysis {
        language: language_name.to_string(),
        function_count,
        new_abstractions,
        cyclomatic_complexity: 1 + complexity_matches,
        has_new_control_flow,
    })
}

fn count_matches(language: &Language, tree: &tree_sitter::Tree, source_code: &str, query_str: &str) -> usize {
    let query = Query::new(language, query_str).expect("Invalid query");
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source_code.as_bytes());
    let mut count = 0;
    while let Some(_) = matches.next() {
        count += 1;
    }
    count
}
