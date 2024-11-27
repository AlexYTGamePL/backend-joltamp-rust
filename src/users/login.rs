use std::sync::Arc;
use rocket::http::Status;
use rocket::response::status;
use serde::Deserialize;
use rocket::serde::json::Json;
use rocket::State;
use scylla::Session;
use serde::Serialize;

#[derive(Deserialize, Serialize)]
pub struct PostData {
    username: String,
    password: String,
    password2: String,
    email: String,
}
#[derive(Deserialize, Serialize)]
pub struct ResponseData {
    jwt: String,
    userId: String,
}

type Db = Arc<Session>;

#[post("/users/login", data = "<data>")]
pub fn login(db: &State<Db>, data: Json<PostData>) -> status::Custom<Json<ResponseData>> {
    status::Custom(Status::Ok, Json(ResponseData {
        jwt: String::new(),
        userId: String::new(),
    }))
    // db.query_unpaged("SELECT * FROM joltamp.users")
}