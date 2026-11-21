//! Encrypted vault storage, placeholder resolution, and TTL cache management for D.U.M.E.R.

pub mod db;
pub mod error;
pub mod export_delete;
pub mod models;
pub mod placeholder;
pub mod schema;
pub mod ttl;
pub mod vault;

pub use db::EncryptedDatabase;
pub use error::VaultError;
pub use export_delete::{cascade_delete_memory_record, export_data, DeletionReport, ExportBundle};
pub use models::{
    ApprovalRecord, AuditEventRecord, CacheEntry, DeviceRecord, FreshnessClass, GrantRecord,
    MemoryClass, MemoryRecord, TaskRecord, VaultItem,
};
pub use placeholder::PlaceholderResolver;
pub use ttl::{FreshnessClassifier, TtlEngine};
pub use vault::VaultManager;
