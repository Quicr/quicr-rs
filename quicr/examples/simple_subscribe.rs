// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    error::Error,
    io::{self, Write},
    thread,
    time::Duration,
};

use quicr::{
    ClientConfig, ClientSessionCallbacks, FullTrackName, GroupOrder, ObjectHeaders, Reply, Session,
    SessionManager, SessionStatus, SetupAttributes, SetupError, SubscribeTrackCallbacks,
    SubscribeTrackHandler, SubscribeTrackOptions, TrackNamespace,
};

struct SimpleClientCallbacks;

impl ClientSessionCallbacks for SimpleClientCallbacks {
    fn setup_received(
        &self,
        _session: &Session,
        attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        eprintln!(
            "Setup received from '{}'",
            String::from_utf8_lossy(attributes.endpoint_id())
        );
        Reply::ok(())
    }
}

struct SimpleSubscribeTrackCallbacks;

impl SubscribeTrackCallbacks for SimpleSubscribeTrackCallbacks {
    fn object_received(
        &self,
        _headers: ObjectHeaders,
        data: &[u8],
        _properties: Option<quicr::StreamHeaderProperties>,
    ) {
        eprintln!("Received data: {}", String::from_utf8_lossy(data));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut config = ClientConfig::default();
    config.transport_config.time_queue_max_duration = Duration::from_secs(5);
    config.connect_uri = prompt("Enter relay URI (prefixed with either moq:// or moqt://): ")?;

    let mut session_manager = SessionManager::new()?;
    let session = session_manager.add_transport(&config, SimpleClientCallbacks)?;
    loop {
        match session.status()? {
            SessionStatus::Ready => break,
            SessionStatus::NotReady
            | SessionStatus::InternalError
            | SessionStatus::InvalidParams
            | SessionStatus::NotConnected
            | SessionStatus::FailedToConnect => {
                return Err(io::Error::other("failed to connect").into());
            }
            _ => thread::sleep(Duration::from_millis(20)),
        }
    }

    let namespace = prompt("Enter track namespace entries delimited by / (e.g. test/track): ")?;
    let namespace = TrackNamespace::new(namespace.split('/'))?;
    let track_name = prompt("Enter a name for the track: ")?;
    let full_track_name = FullTrackName::new(namespace, track_name);

    let handler = SubscribeTrackHandler::new_with_callbacks(
        &full_track_name,
        SubscribeTrackOptions {
            priority: 127,
            group_order: Some(GroupOrder::Ascending),
            filter: None,
        },
        SimpleSubscribeTrackCallbacks,
    )?;
    session_manager.add_handler(&session, &handler)?;

    eprintln!("Waiting for data (Ctrl+C to stop)");
    loop {
        thread::sleep(Duration::from_millis(20));
    }
}

fn prompt(message: &str) -> io::Result<String> {
    eprint!("{message}");
    io::stderr().flush()?;

    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "standard input closed",
        ));
    }

    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}
