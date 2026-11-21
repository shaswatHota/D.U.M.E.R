use crate::db::EncryptedDatabase;
use crate::error::VaultError;
use crate::models::FreshnessClass;

pub struct FreshnessClassifier;

impl FreshnessClassifier {
    /// Deterministically classifies web or knowledge snippets into freshness classes
    /// using keywords, headers, and explicit user-pinned signals.
    pub fn classify(
        url: &str,
        text: &str,
        cache_control: Option<&str>,
        user_pinned: bool,
    ) -> FreshnessClass {
        if user_pinned {
            return FreshnessClass::Static;
        }

        let cc = cache_control.unwrap_or("").to_lowercase();
        if cc.contains("no-store") || cc.contains("no-cache") {
            return FreshnessClass::Volatile;
        }

        let combined = format!("{url} {text}").to_lowercase();

        // 1. Volatile checks
        if combined.contains("live score")
            || combined.contains("right now")
            || combined.contains("real-time")
            || combined.contains("breaking news")
        {
            return FreshnessClass::Volatile;
        }

        // 2. Fast checks (minutes - hours)
        if combined.contains("weather")
            || combined.contains("stock price")
            || combined.contains("exchange rate")
            || combined.contains("traffic")
        {
            return FreshnessClass::Fast;
        }

        // 3. Static checks (months - permanent)
        if combined.contains("rfc-")
            || combined.contains("standard")
            || combined.contains("specification")
            || combined.contains("history of")
            || combined.contains("wikipedia.org")
        {
            return FreshnessClass::Static;
        }

        // 4. Slow checks (days - weeks)
        if combined.contains("docs")
            || combined.contains("api")
            || combined.contains("reference")
            || combined.contains("tutorial")
            || combined.contains("manual")
        {
            return FreshnessClass::Slow;
        }

        // Default to Slow for general knowledge
        FreshnessClass::Slow
    }
}

pub struct TtlEngine;

impl TtlEngine {
    /// Returns default TTL in seconds for a freshness class.
    pub fn default_ttl(class: FreshnessClass) -> u64 {
        match class {
            FreshnessClass::Volatile => 0,
            FreshnessClass::Fast => 3600,         // 1 hour
            FreshnessClass::Slow => 7 * 86400,    // 7 days
            FreshnessClass::Static => 90 * 86400, // 90 days
        }
    }

    /// Returns the maximum allowed TTL in seconds for a freshness class.
    pub fn max_ttl(class: FreshnessClass) -> u64 {
        match class {
            FreshnessClass::Volatile => 0,
            FreshnessClass::Fast => 12 * 3600,     // 12 hours
            FreshnessClass::Slow => 30 * 86400,    // 30 days
            FreshnessClass::Static => 365 * 86400, // 1 year
        }
    }

    /// Computes safe TTL clamped to the freshness class ceiling.
    pub fn compute_ttl(class: FreshnessClass, suggested: Option<u64>) -> u64 {
        let max = Self::max_ttl(class);
        let default = Self::default_ttl(class);

        match suggested {
            Some(s) => s.min(max),
            None => default,
        }
    }

    /// Purges all expired cache entries and memory records across the database.
    pub fn purge_all_expired(db: &EncryptedDatabase) -> Result<(usize, usize), VaultError> {
        let purged_records = db.purge_expired_memory_records()?;
        let purged_cache = db.purge_expired_cache()?;
        Ok((purged_records, purged_cache))
    }
}
