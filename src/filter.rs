use crate::token::Token;
use http_error::forbidden;
use warp::{filters, Filter};

pub fn authorization(
    secret: String,
) -> impl warp::Filter<Extract = (), Error = warp::Rejection> + Clone {
    cookie_authorization()
        .or(header_authorization())
        .unify()
        .and_then(move |token: String| {
            futures::future::ready(match Token::decode(&token, &secret) {
                Ok(token) => {
                    if token.sub() == "vro" {
                        Ok(())
                    } else {
                        Err(forbidden!())
                    }
                }
                Err(_) => Err(forbidden!()),
            })
        })
        .untuple_one()
}

fn cookie_authorization() -> impl warp::Filter<Extract = (String,), Error = warp::Rejection> + Clone
{
    filters::cookie::optional("vro").and_then(move |token: Option<String>| {
        futures::future::ready(if let Some(token) = token {
            Ok(token)
        } else {
            Err(forbidden!())
        })
    })
}

fn header_authorization() -> impl warp::Filter<Extract = (String,), Error = warp::Rejection> + Clone
{
    filters::header::optional::<String>("authorization").and_then(move |header: Option<String>| {
        futures::future::ready(if let Some(header) = header {
            if !header.starts_with("Bearer ") {
                Err(forbidden!())
            } else {
                Ok(header[7..].to_string())
            }
        } else {
            Err(forbidden!())
        })
    })
}
