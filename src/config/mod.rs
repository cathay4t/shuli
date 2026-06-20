// SPDX-License-Identifier: Apache-2.0

mod schema;

use std::{fs, path::Path};

pub use schema::*;

use crate::ShuliResult;

pub fn load_config(path: &Path) -> ShuliResult<Config> {
    if !path.exists() {
        return Err(crate::ShuliError::ConfigNotFound(path.to_path_buf()));
    }
    let content = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| crate::ShuliError::InvalidConfig(e.to_string()))?;
    Ok(config)
}
