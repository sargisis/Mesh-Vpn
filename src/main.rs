//! AraxMesh daemon entry point. All logic lives in the `araxmesh` library;
//! this binary just starts the async runtime and hands off to `run()`.
#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    araxmesh::run().await
}
