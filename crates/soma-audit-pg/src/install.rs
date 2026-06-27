use soma_schema::include_dir::include_dir;

use crate::error::InstallError;

static MIGRATIONS_DIR: soma_schema::include_dir::Dir =
    include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// Install the soma_audit schema and run migrations.
/// Idempotent — safe to call every time the host service starts.
///
/// # Pool requirements
/// The pool must have `max_connections >= 2`. One connection is held for the
/// advisory lock; at least one more is needed for migration queries.
pub async fn install(pool: &sqlx::PgPool) -> Result<(), InstallError> {
    if pool.options().get_max_connections() < 2 {
        return Err(InstallError::Env(
            "soma-audit requires a pool with max_connections >= 2".into(),
        ));
    }

    let driver = soma_schema::PostgresDriver::new(
        pool.clone(),
        soma_schema::PostgresConfig {
            schema: Some("soma_audit".into()),
            advisory_lock_key: 6020250626000001_i64,
            ..Default::default()
        },
    )
    .map_err(InstallError::Schema)?;

    soma_schema::Migrator::from_embedded(&MIGRATIONS_DIR)
        .map_err(InstallError::Schema)?
        .up(&driver)
        .await
        .map_err(InstallError::Schema)
}
