use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use crate::token::Token;
use tide::http::headers::HeaderName;
use tide::http::StatusCode;
use tide::{Middleware, Next};
use tide::{Request, Response};

#[derive(Debug)]
pub struct AuthorizationMiddleware {
    secret: String,
}

pub fn middleware(secret: impl Into<String>) -> AuthorizationMiddleware {
    AuthorizationMiddleware {
        secret: secret.into(),
    }
}

impl AuthorizationMiddleware {
    async fn authorize<'a, State: Send + Sync + 'static>(
        &'a self,
        cx: Request<State>,
        next: Next<'a, State>,
    ) -> tide::Result {
        let token = from_header(&cx, &self.secret)
            .or_else(|| from_cookie(&cx, &self.secret))
            .and_then(|token| {
                if token.sub() == "vro" {
                    Some(token)
                } else {
                    None
                }
            });
        match token {
            Some(token) => next.run(cx.set_ext(token)).await,
            None => Ok(Response::new(StatusCode::Forbidden)),
        }
    }
}

fn from_header<State>(cx: &Request<State>, secret: &str) -> Option<Token> {
    // TODO: convert to typed header once it's available
    let authorization = HeaderName::from_str("authorization").unwrap();
    if let Some(headers) = cx.header(&authorization) {
        for value in headers {
            if value.as_str().starts_with("Bearer ") {
                return Token::decode(&value.as_str()[7..], &secret).ok();
            }
        }
    }

    None
}

fn from_cookie<State>(cx: &Request<State>, secret: &str) -> Option<Token> {
    cx.cookie("vro")
        .and_then(|c| Token::decode(c.value(), &secret).ok())
}

impl<State: Send + Sync + 'static> Middleware<State> for AuthorizationMiddleware {
    fn handle<'a>(
        &'a self,
        cx: Request<State>,
        next: Next<'a, State>,
    ) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
        Box::pin(async move { self.authorize(cx, next).await })
    }
}

trait RequestExt {
    fn token(&self) -> tide::Result<&Token>;
}

impl<State: Send + Sync + 'static> RequestExt for Request<State> {
    fn token(&self) -> tide::Result<&Token> {
        self.ext::<Token>()
            .ok_or_else(|| tide::Error::from_str(StatusCode::Forbidden, "unauthorized access"))
    }
}
