use std::error::Error;
use std::sync::Arc;
use rocket::futures::StreamExt;
use rocket::http::Status;
use rocket::response::status;
use serde::Deserialize;
use rocket::serde::json::Json;
use rocket::State;
use scylla::Session;
use serde::Serialize;
use uuid::Uuid;
use crate::security::hashing;
use crate::security::hashing::verify_password;

#[derive(Deserialize, Serialize)]
pub struct PostData {
    password: String,
    email: String,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseData{
    Success {
        jwt: String,
        user_id: String,
    },
    Error {
        message: String,
    }
}

type Db = Arc<Session>;
type DynError = Box<dyn Error + Send + Sync>;
#[post("/users/login", data = "<data>")]
pub async fn login(db: &State<Db>, data: Json<PostData>) -> status::Custom<Json<ResponseData>> {
    match get_user(db, &data.email.to_lowercase()).await {
        Ok((user_id, jwt, password)) => {
            match verify_password(&data.password, &password) {
                Ok(_) => status::Custom(Status::Ok, Json(ResponseData::Success {
                    user_id: String::from(user_id),
                    jwt: String::from(jwt),
                })),
                Err(_) => status::Custom(Status::Unauthorized, Json(ResponseData::Error {
                    message: "Invalid password".to_string(),
                }))
            }
        },
        Err(e) => {
            status::Custom(Status::BadRequest, Json(ResponseData::Error {
                message: e.to_string()
            }))
        }
    }
}

async fn get_user(db: &State<Db>, email: &String) -> Result<(Uuid, Uuid, String), DynError> {
    let mut res = db.query_iter("SELECT user_id, jwt, password FROM joltamp.users WHERE email = ? ALLOW FILTERING", (&email, ))
        .await?.rows_stream::<(Uuid, Uuid, String)>()?;
    for row in res.next().await {
        let row = row?;
        println!("{:?}", row);
        return Ok(row);
    }
    Err("User not found".into())
}