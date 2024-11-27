mod users;
mod security;

#[macro_use] extern crate rocket;

use std::sync::Arc;
use scylla::{ExecutionProfile, Session, SessionBuilder};
use scylla::statement::Consistency;
use users::{login, register};

type Db = Arc<Session>;

#[launch]
async fn rocket() -> _ {
    let profile = ExecutionProfile::builder()
        .consistency(Consistency::LocalOne)
        .request_timeout(None)
        .build();

    let handle = profile.into_handle();
    let db = SessionBuilder::new()
        .known_node("127.0.0.1:9042")
        .default_execution_profile_handle(handle)
        .build()
        .await
        .expect("failed to build database");

    rocket::build()
        .manage(Arc::new(db))
        .mount("/", routes![login::login, register::register])
}

