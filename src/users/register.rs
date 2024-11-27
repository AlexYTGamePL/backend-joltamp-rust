use std::error::Error;
use std::io;
use std::sync::Arc;
use rocket::futures::StreamExt;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket::{State};
use rocket::form::validate::Contains;
use rocket::http::hyper::body::HttpBody;
use scylla::{QueryResult, Session};
use scylla::transport::errors::QueryError;
use uuid::Uuid;
use scylla::frame::response::result::Row;

#[derive(Deserialize, Serialize)]
pub struct PostData {
    username: String,
    password: String,
    email: String,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseData{
    Success {
        jwt: String,
        userId: String,
    },
    Error {
        message: String,
    }
}
type DynError = Box<dyn Error + Send + Sync>;
type Db = Arc<Session>;

#[post("/users/register", data = "<body>")]
pub async fn register(db: &State<Db>, mut body: Json<PostData>) -> status::Custom<Json<ResponseData>> {
    body.email = body.email.to_lowercase();
    if body.username.len() <= 3{
        status::Custom(Status::BadRequest, Json(ResponseData::Error{ message: "Username is too short. Min 4".to_string() }))
    } else if body.password.len() <= 3 {
        status::Custom(Status::BadRequest, Json(ResponseData::Error{ message: "Password is too short. Min 4".to_string() }))
    } else if body.email.len() <= 3 || !body.email.contains("@") {
        status::Custom(Status::BadRequest, Json(ResponseData::Error { message: "Email is incorrect!".to_string() }))
    }else{
        match checkIfUsed(db, &body.username).await {
            Ok(val) => {
                if val {
                    status::Custom(Status::BadRequest, Json(ResponseData::Error{
                        message: String::from("Username is already used"),
                    }))
                }else{
                    match createUser(db, &body).await {
                        Ok((userId, jwt)) => {
                            status::Custom(Status::Ok, Json(ResponseData::Success {
                                jwt: jwt.to_string(),
                                userId: userId.to_string(),
                            }))
                        },
                        Err(_) => {
                            status::Custom(Status::InternalServerError, Json(ResponseData::Error {
                                message: String::from("Could not create user"),
                            }))
                        }
                    }
                }
            },
            Err(_) => {
                status::Custom(Status::InternalServerError, Json(ResponseData::Error {
                    message: String::from("Server error"),
                }))
            }
        }
    }

}

async fn createUser(db: &State<Db>, body: &PostData) -> Result<(Uuid, Uuid), DynError>{
    let userid = Uuid::new_v4();
    let jwt = Uuid::new_v4();

    let query = db.query_unpaged(
        "INSERT INTO joltamp.users (createdat, user_id, username, displayname, email, isadmin, jwt, password, status)
        VALUES ('25-11-2024', ?, ?, ?, ?, false, ?, ?, 0)",
        (userid, &body.username, &body.username, &body.email, jwt, &body.password),
    ).await;

    match query {
        Ok(_) => {
            Ok((userid, jwt))
        }
        Err(e) => {
            println!("error: {:?}", e);
            Err("Error creating user".into())
        }
    }
}

async fn checkIfUsed(db: &State<Db>, username: &String) -> Result<bool, DynError> {
    let mut res = db.query_iter("SELECT username, user_id FROM joltamp.users WHERE username = ? LIMIT 1 ALLOW FILTERING", (&username, ))
        .await?.rows_stream::<(String, Uuid)>()?;

    let mut used: bool = false;
    while let Some(row) = res.next().await {
        let (username, user_id) = row?;
        used = true;
        break;
    }
    Ok(used)
}