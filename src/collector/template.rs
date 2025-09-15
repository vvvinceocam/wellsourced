use color_eyre::Result;
use lazy_regex::regex_captures_iter;
use serde::Serialize;
use serde_json::Value;

/// Simple template rendering function. Use the common `{{ variable }}` syntax.
///
/// `context` must implement the `Serialize` trait and be serializable as JSON.
///
/// ## Errors
///
/// Returns an error if the template contains invalid placeholders or if the context cannot be serialized.
pub fn render<T: Serialize>(template: &str, context: &T) -> Result<String> {
    let context_value = serde_json::to_value(context)?;
    let mut result = template.to_string();

    for cap in regex_captures_iter!(r"\{\{\s*([^}]+)\s*\}\}", template) {
        let full_match = &cap[0];
        let field_path = cap[1].trim();

        let value = get_nested_value(&context_value, field_path);
        let replacement = match value {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Bool(b)) => b.to_string(),
            Some(Value::Null) => String::new(),
            Some(v) => v.to_string().trim_matches('"').to_string(),
            None => {
                return Err(color_eyre::eyre::eyre!(
                    "Template variable '{}' not found in context",
                    field_path
                ));
            }
        };

        result = result.replace(full_match, &replacement);
    }

    Ok(result)
}

/// Returns the value at the given path in the JSON object.
fn get_nested_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let parts = path.split('.');
    let mut current = value;

    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }

    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::report::LegacyReport;
    use serde_json::json;

    #[test]
    fn get_nested_value_simple() {
        let value = json!({
            "name": "John",
            "age": 30,
            "profile": {
                "email": "john@example.com"
            }
        });

        assert_eq!(
            get_nested_value(&value, "name"),
            Some(&json!("John")),
            "get string value",
        );
        assert_eq!(
            get_nested_value(&value, "age"),
            Some(&json!(30)),
            "get integer value",
        );
        assert_eq!(
            get_nested_value(&value, "profile.email"),
            Some(&json!("john@example.com")),
            "get nested string value",
        );
        assert_eq!(
            get_nested_value(&value, "nonexistent"),
            None,
            "get missing value",
        );
    }

    #[test]
    fn render_multiple_fields() {
        let context = json!({
            "first": "John",
            "last": "Doe",
            "age": 25,
            "profile": {
                "email": "john@example.com"
            }
        });

        let result = render(
            "{{first}} {{last}} is {{age}} years old is reachable at {{profile.email}}",
            &context,
        )
        .unwrap();
        assert_eq!(
            result,
            "John Doe is 25 years old is reachable at john@example.com"
        );
    }

    #[test]
    fn render_missing_field() {
        let context = json!({
            "name": "John"
        });

        assert!(render("Hello {{nonexistent}}!", &context).is_err());
    }

    #[test]
    fn render_whitespace_handling() {
        let context = json!({
            "name": "World"
        });

        let result = render(
            "Hello {{ name }} {{    name}}{{name    }}{{  name  }}!",
            &context,
        )
        .unwrap();
        assert_eq!(result, "Hello World WorldWorldWorld!");
    }

    #[test]
    fn render_no_templates() {
        let context = json!({
            "name": "World"
        });

        let result = render("Just plain text", &context).unwrap();
        assert_eq!(result, "Just plain text");
    }

    #[test]
    fn render_legacy_report() {
        let report = LegacyReport {
            blocked_uri: "https://example.com/script.js".to_string(),
            document_uri: "https://mysite.com".to_string(),
            effective_directive: "script-src".to_string(),
            original_policy: "script-src 'self'".to_string(),
            referrer: "https://referrer.com".to_string(),
            status_code: 200,
            violated_directive: "script-src 'self'".to_string(),
            source_file: "index.html".to_string(),
            line_number: 42,
            column_number: 10,
        };

        let template = "{ \"message\": \"CSP violation: {{blocked-uri}} on {{document-uri}} at line {{line-number}}\" }";
        let result = render(template, &report).unwrap();
        assert_eq!(
            result,
            "{ \"message\": \"CSP violation: https://example.com/script.js on https://mysite.com at line 42\" }"
        );
    }
}
