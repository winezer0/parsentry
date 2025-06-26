use parsentry::security_patterns::{
    Language, LanguagePatterns, PatternConfig, PatternQuery, PatternType, SecurityRiskPatterns,
};

#[test]
fn test_language_from_extension() {
    // Test known extensions
    assert_eq!(Language::from_extension("py"), Language::Python);
    assert_eq!(Language::from_extension("js"), Language::JavaScript);
    assert_eq!(Language::from_extension("rs"), Language::Rust);
    assert_eq!(Language::from_extension("ts"), Language::TypeScript);
    assert_eq!(Language::from_extension("java"), Language::Java);
    assert_eq!(Language::from_extension("go"), Language::Go);
    assert_eq!(Language::from_extension("rb"), Language::Ruby);
    assert_eq!(Language::from_extension("c"), Language::C);
    assert_eq!(Language::from_extension("h"), Language::C);
    assert_eq!(Language::from_extension("cpp"), Language::Cpp);
    assert_eq!(Language::from_extension("cxx"), Language::Cpp);
    assert_eq!(Language::from_extension("cc"), Language::Cpp);
    assert_eq!(Language::from_extension("hpp"), Language::Cpp);
    assert_eq!(Language::from_extension("hxx"), Language::Cpp);
    assert_eq!(Language::from_extension("tf"), Language::Terraform);
    assert_eq!(Language::from_extension("hcl"), Language::Terraform);
    // YAML support is available
    assert_eq!(Language::from_extension("yaml"), Language::Yaml);
    assert_eq!(Language::from_extension("yml"), Language::Yaml);
    assert_eq!(Language::from_extension("json"), Language::Other);

    assert_eq!(Language::from_extension("txt"), Language::Other);
    assert_eq!(Language::from_extension(""), Language::Other);
    assert_eq!(Language::from_extension("unknown"), Language::Other);
}

#[test]
fn test_language_equality() {
    assert_eq!(Language::Python, Language::Python);
    assert_ne!(Language::Python, Language::JavaScript);
    assert_ne!(Language::Rust, Language::TypeScript);
}

#[test]
fn test_language_debug() {
    let lang = Language::Python;
    let debug_str = format!("{:?}", lang);
    assert_eq!(debug_str, "Python");
}

#[test]
fn test_pattern_type_equality() {
    assert_eq!(PatternType::Principal, PatternType::Principal);
    assert_eq!(PatternType::Action, PatternType::Action);
    assert_eq!(PatternType::Resource, PatternType::Resource);

    assert_ne!(PatternType::Principal, PatternType::Action);
    assert_ne!(PatternType::Action, PatternType::Resource);
    assert_ne!(PatternType::Principal, PatternType::Resource);
}

#[test]
fn test_pattern_config_creation() {
    let config = PatternConfig {
        pattern_type: PatternQuery::Reference { 
            reference: "(call function: (identifier) @func (#eq? @func \"eval\"))".to_string() 
        },
        description: "Dynamic code execution".to_string(),
        attack_vector: vec!["T1059".to_string()],
    };

    match &config.pattern_type {
        PatternQuery::Reference { reference } => {
            assert!(reference.contains("eval"));
        }
        _ => panic!("Expected reference pattern"),
    }
    assert_eq!(config.description, "Dynamic code execution");
}

#[test]
fn test_language_patterns_creation() {
    let principals = vec![
        PatternConfig {
            pattern_type: PatternQuery::Reference { 
                reference: "(call function: (identifier) @func (#eq? @func \"input\"))".to_string() 
            },
            description: "User input".to_string(),
            attack_vector: vec!["T1059".to_string()],
        },
        PatternConfig {
            pattern_type: PatternQuery::Reference { 
                reference: "(member_expression object: (identifier) @obj (#eq? @obj \"request\") property: (property_identifier) @prop (#eq? @prop \"get\"))".to_string() 
            },
            description: "HTTP request parameter".to_string(),
            attack_vector: vec!["T1071".to_string()],
        },
    ];

    let resources = vec![PatternConfig {
        pattern_type: PatternQuery::Reference { 
            reference: "(call function: (identifier) @func (#eq? @func \"eval\"))".to_string() 
        },
        description: "Code execution".to_string(),
        attack_vector: vec!["T1059".to_string()],
    }];

    let patterns = LanguagePatterns {
        principals: Some(principals.clone()),
        actions: None,
        resources: Some(resources.clone()),
    };

    assert!(patterns.principals.is_some());
    assert!(patterns.resources.is_some());
    assert_eq!(patterns.principals.unwrap().len(), 2);
    assert_eq!(patterns.resources.unwrap().len(), 1);
}

#[test]
fn test_language_patterns_empty() {
    let patterns = LanguagePatterns {
        principals: None,
        actions: None,
        resources: None,
    };

    assert!(patterns.principals.is_none());
    assert!(patterns.actions.is_none());
    assert!(patterns.resources.is_none());
}

#[test]
fn test_language_patterns_partial() {
    let patterns = LanguagePatterns {
        principals: Some(vec![PatternConfig {
            pattern_type: PatternQuery::Reference { 
                reference: "(identifier) @name (#eq? @name \"test\")".to_string() 
            },
            description: "test description".to_string(),
            attack_vector: vec!["T1000".to_string()],
        }]),
        actions: None,
        resources: None,
    };

    assert!(patterns.principals.is_some());
    assert!(patterns.actions.is_none());
    assert!(patterns.resources.is_none());
}

#[test]
fn test_security_risk_patterns_new() {
    let _patterns = SecurityRiskPatterns::new(Language::Python);
    // The constructor doesn't return Result, it creates an instance directly
    assert!(true); // Just test that it doesn't panic
}

// Note: SecurityRiskPatterns tests are skipped because they depend on src/patterns.yml file
// which may not be available in the test environment. We focus on testing the basic types.

// Note: PatternConfig and LanguagePatterns only derive Deserialize, not Serialize
// So we skip serialization tests and focus on deserialization and basic functionality

#[test]
fn test_language_hash_and_equality() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(Language::Python);
    set.insert(Language::JavaScript);
    set.insert(Language::Python); // Duplicate

    assert_eq!(set.len(), 2); // Should only contain 2 unique languages
    assert!(set.contains(&Language::Python));
    assert!(set.contains(&Language::JavaScript));
    assert!(!set.contains(&Language::Rust));
}

#[test]
fn test_pattern_type_clone() {
    let original = PatternType::Principal;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_language_clone() {
    let original = Language::Rust;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_pattern_config_deserialization() {
    use serde_json;

    let json_data = r#"{"reference": "(identifier) @name", "description": "test description", "attack_vector": ["T1000"]}"#;
    let config: Result<PatternConfig, _> = serde_json::from_str(json_data);

    assert!(config.is_ok());
    let config = config.unwrap();
    match &config.pattern_type {
        PatternQuery::Reference { reference } => {
            assert_eq!(reference, "(identifier) @name");
        }
        _ => panic!("Expected reference pattern"),
    }
    assert_eq!(config.description, "test description");
}

#[test]
fn test_language_patterns_deserialization() {
    use serde_json;

    let json_data = r#"{
        "principals": [{"reference": "(call function: (identifier) @func (#eq? @func \"input\"))", "description": "User input", "attack_vector": ["T1059"]}],
        "actions": [{"reference": "(call function: (identifier) @func (#eq? @func \"validate\"))", "description": "Input validation", "attack_vector": ["T1070"]}],
        "resources": [{"reference": "(call function: (identifier) @func (#eq? @func \"eval\"))", "description": "Code execution", "attack_vector": ["T1059"]}]
    }"#;

    let patterns: Result<LanguagePatterns, _> = serde_json::from_str(json_data);
    assert!(patterns.is_ok());

    let patterns = patterns.unwrap();
    assert!(patterns.principals.is_some());
    assert!(patterns.actions.is_some());
    assert!(patterns.resources.is_some());
}
