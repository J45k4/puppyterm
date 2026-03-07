use std::{fs, path::Path};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::domain::{HostProfile, ProfileSource, SessionRecord, StoredKey, TunnelSpec};

pub trait ProfileRepository: Send + Sync {
    fn load_app_profiles(&self) -> Result<Vec<HostProfile>>;
    fn upsert_profile(&self, profile: &HostProfile) -> Result<()>;
    fn duplicate_system_profile(&self, profile: &HostProfile) -> Result<HostProfile>;
    fn list_keys(&self) -> Result<Vec<StoredKey>>;
    fn upsert_key(&self, key: &StoredKey) -> Result<()>;
    fn list_tunnels(&self) -> Result<Vec<TunnelSpec>>;
    fn upsert_tunnel(&self, tunnel: &TunnelSpec) -> Result<()>;
    fn recent_sessions(&self) -> Result<Vec<SessionRecord>>;
    fn record_session(&self, session: &SessionRecord) -> Result<()>;
}

pub struct SqliteProfileRepository {
    connection: Mutex<Connection>,
}

impl SqliteProfileRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                display_name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS keys (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tunnels (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                data TEXT NOT NULL
            );
            "#,
        )?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn upsert_json<T: Serialize>(
        &self,
        table: &str,
        id: &str,
        first: &str,
        second: &str,
        sort_key: &str,
        value: &T,
    ) -> Result<()> {
        let payload = serde_json::to_string(value)?;
        let sql = format!(
            "INSERT INTO {table} (id, {first}, {second}, {sort_key}, data) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET {first}=excluded.{first}, {second}=excluded.{second}, {sort_key}=excluded.{sort_key}, data=excluded.data"
        );
        self.connection.lock().execute(
            &sql,
            params![
                id,
                extract_column(value, first)?,
                extract_column(value, second)?,
                extract_column(value, sort_key)?,
                payload
            ],
        )?;
        Ok(())
    }

    fn load_json<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut values = Vec::new();
        for row in rows {
            let payload = row?;
            values.push(serde_json::from_str(&payload)?);
        }
        Ok(values)
    }
}

impl ProfileRepository for SqliteProfileRepository {
    fn load_app_profiles(&self) -> Result<Vec<HostProfile>> {
        self.load_json(
            "SELECT data FROM profiles WHERE source = 'AppManaged' ORDER BY updated_at DESC, display_name ASC",
        )
    }

    fn upsert_profile(&self, profile: &HostProfile) -> Result<()> {
        self.upsert_json(
            "profiles",
            &profile.id,
            "source",
            "display_name",
            "updated_at",
            profile,
        )
    }

    fn duplicate_system_profile(&self, profile: &HostProfile) -> Result<HostProfile> {
        let mut duplicate = profile.clone();
        duplicate.id = Uuid::new_v4().to_string();
        duplicate.source = ProfileSource::AppManaged;
        duplicate.meta = profile.meta.clone();
        duplicate.meta.touch();
        duplicate.display_name = format!("{} (Imported)", profile.display_name);
        self.upsert_profile(&duplicate)?;
        Ok(duplicate)
    }

    fn list_keys(&self) -> Result<Vec<StoredKey>> {
        self.load_json("SELECT data FROM keys ORDER BY updated_at DESC, name ASC")
    }

    fn upsert_key(&self, key: &StoredKey) -> Result<()> {
        self.upsert_json("keys", &key.id, "source", "name", "updated_at", key)
    }

    fn list_tunnels(&self) -> Result<Vec<TunnelSpec>> {
        self.load_json("SELECT data FROM tunnels ORDER BY updated_at DESC, name ASC")
    }

    fn upsert_tunnel(&self, tunnel: &TunnelSpec) -> Result<()> {
        self.upsert_json(
            "tunnels",
            &tunnel.id,
            "profile_id",
            "name",
            "updated_at",
            tunnel,
        )
    }

    fn recent_sessions(&self) -> Result<Vec<SessionRecord>> {
        self.load_json("SELECT data FROM sessions ORDER BY started_at DESC LIMIT 25")
    }

    fn record_session(&self, session: &SessionRecord) -> Result<()> {
        let payload = serde_json::to_string(session)?;
        self.connection.lock().execute(
            "INSERT INTO sessions (id, profile_id, started_at, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET profile_id=excluded.profile_id, started_at=excluded.started_at, data=excluded.data",
            params![session.id, session.profile_id, session.started_at, payload],
        )?;
        Ok(())
    }
}

fn extract_column<T: Serialize>(value: &T, column: &str) -> Result<String> {
    let json = serde_json::to_value(value)?;
    let text = match json.get(column) {
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    Ok(text)
}

#[allow(dead_code)]
fn _exists(connection: &Connection, table: &str, id: &str) -> Result<bool> {
    let sql = format!("SELECT 1 FROM {table} WHERE id = ?1 LIMIT 1");
    Ok(connection
        .query_row(&sql, [id], |_| Ok(()))
        .optional()?
        .is_some())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::tempdir;

    use super::{ProfileRepository, SqliteProfileRepository};
    use crate::domain::HostProfile;

    #[test]
    fn stores_and_loads_app_profiles() -> Result<()> {
        let temp = tempdir()?;
        let repo = SqliteProfileRepository::open(temp.path().join("data.sqlite"))?;

        let profile = HostProfile::new_app("Prod", "prod.example.com");
        repo.upsert_profile(&profile)?;

        let profiles = repo.load_app_profiles()?;
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].display_name, "Prod");
        Ok(())
    }

    #[test]
    fn duplicates_system_profile_as_app_profile() -> Result<()> {
        let temp = tempdir()?;
        let repo = SqliteProfileRepository::open(temp.path().join("data.sqlite"))?;

        let mut profile = HostProfile::new_app("Staging", "staging.example.com");
        profile.source = crate::domain::ProfileSource::SystemDiscovered;
        let duplicate = repo.duplicate_system_profile(&profile)?;

        assert_eq!(duplicate.source, crate::domain::ProfileSource::AppManaged);
        assert!(duplicate.display_name.contains("Imported"));
        assert_ne!(duplicate.id, profile.id);
        Ok(())
    }
}
