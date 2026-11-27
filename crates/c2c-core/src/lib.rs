//! Coeur de C2C : logique pure et testable (reveil, etat, plan d'ecran, audit, secrets).
//! Aucun effet reel sans backend explicite ; aucun secret en clair.
pub mod audit;
pub mod config;
pub mod agent;
pub mod display;
pub mod healthcheck;
pub mod hostkey;
pub mod nethealth;
pub mod proto;
pub mod runner;
pub mod secrets;
pub mod session;
pub mod status;
pub mod stream;
pub mod update;
pub mod sunshine_api;
pub mod wake;
pub mod watch;
