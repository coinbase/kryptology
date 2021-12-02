//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// The name of the copyright owner
    pub copyright: String,
    /// The chosen license
    pub license: String,
    /// File extensions to comments to use
    /// For example
    /// yml: #
    /// python: #
    /// sh: #
    /// go: //
    /// rs: ///
    pub comments: HashMap<String, String>,
    /// Ignore files that match these patterns as regex's
    pub ignore: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut comments = HashMap::new();
        comments.insert("gitignore".to_string(), "#".to_string());
        comments.insert("dockerignore".to_string(), "#".to_string());
        comments.insert("sh".to_string(), "#".to_string());
        comments.insert("py".to_string(), "#".to_string());
        comments.insert("pl".to_string(), "#".to_string());
        comments.insert("rb".to_string(), "#".to_string());
        comments.insert("yml".to_string(), "#".to_string());
        comments.insert("yaml".to_string(), "#".to_string());
        comments.insert("go".to_string(), "//".to_string());
        comments.insert("rs".to_string(), "///".to_string());
        Config {
            copyright: "Copyright Coinbase, Inc. All Rights Reserved.".to_string(),
            license: "Apache-2.0".to_string(),
            comments,
            ignore: HashSet::new(),
        }
    }
}
