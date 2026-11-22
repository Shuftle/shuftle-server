//! Matchmaking: players queue for a table.

use shuftle_proto::shuftle::matchmaking::v1::{
    AcceptMatchRequest, AcceptMatchResponse, DeclineMatchRequest, DeclineMatchResponse,
    EnqueueRequest, EnqueueResponse, matchmaking_service_server::MatchmakingService,
};
use tonic::{Request, Response, Status, codegen::tokio_stream::Empty};

/// Answers matchmaking calls. Not implemented yet.
pub struct Matchmaking;

#[tonic::async_trait]
impl MatchmakingService for Matchmaking {
    type EnqueueStream = Empty<Result<EnqueueResponse, Status>>;

    async fn enqueue(
        &self,
        _request: Request<EnqueueRequest>,
    ) -> Result<Response<Self::EnqueueStream>, Status> {
        Err(Status::unimplemented("Enqueue is not implemented yet"))
    }

    async fn accept_match(
        &self,
        _request: Request<AcceptMatchRequest>,
    ) -> Result<Response<AcceptMatchResponse>, Status> {
        Err(Status::unimplemented("AcceptMatch is not implemented yet"))
    }

    async fn decline_match(
        &self,
        _request: Request<DeclineMatchRequest>,
    ) -> Result<Response<DeclineMatchResponse>, Status> {
        Err(Status::unimplemented("DeclineMatch is not implemented yet"))
    }
}
