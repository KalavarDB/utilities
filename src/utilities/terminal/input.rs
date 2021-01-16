use tokio::sync::mpsc::channel;


use crate::utilities::terminal::output::{OutputManager, DisplayLine};
use crate::management::{
    versions::VersionManager,
    security::SecurityDatabase,
};

pub async fn parse_args(manifest: Option<&str>, recursion: usize, updates: bool) {
    let (mut sender, mut receiver) = channel::<DisplayLine>(10);

    tokio::spawn(async move {
        let visual_manager: OutputManager = OutputManager::new(0, 112);
        if updates {
            visual_manager.check_update().await;
        }
        loop {
            let incoming = receiver.recv().await;
            if let Some(payload) = incoming {
                visual_manager.render(payload)
            }
        }
    });

    let version_mgr = VersionManager::new();

    let mut advisory_db = SecurityDatabase::new();
    let update_result = advisory_db.update().await;
    if update_result.is_ok() {
        let fetch_result = if let Some(manpath) = manifest {
            version_mgr.fetch_dependencies(manpath, &mut sender, &advisory_db, recursion).await
        } else {
            version_mgr.fetch_dependencies("./Cargo.toml", &mut sender, &advisory_db, recursion).await
        };
        if let Ok((good, bad, insecure, warn)) = fetch_result {
            sender.send(DisplayLine::new_guide()).await;
            sender.send(DisplayLine::new_footer()).await;
            sender.send(DisplayLine::new_guide()).await;
            sender.send(DisplayLine::new_footer_content(good, bad, insecure, warn)).await;
            sender.send(DisplayLine::new_table_end()).await;
        } else {
            OutputManager::error(fetch_result.unwrap_err())
        }
    } else {
        OutputManager::error(update_result.unwrap_err())
    }
}