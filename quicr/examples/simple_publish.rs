// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    error::Error,
    io::{self, Write},
    thread,
    time::Duration,
};

use quicr::{
    ClientConfig, ClientSessionCallbacks, FullTrackName, Location, ObjectHeaders, ObjectStatus,
    PublishTrackHandler, PublishTrackOptions, PublishTrackStatus, Reply, Session, SessionManager,
    SessionStatus, SetupAttributes, SetupError, TrackMode, TrackNamespace,
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

    let mut handler = PublishTrackHandler::new(
        &full_track_name,
        PublishTrackOptions {
            track_mode: TrackMode::Stream,
            publisher_priority: 127,
            publish_object_priority: 127,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        },
    )?;
    session_manager.add_handler(&session, &handler)?;

    while !handler.can_publish() {
        match handler.status()? {
            PublishTrackStatus::PendingPublishOk
            | PublishTrackStatus::Paused
            | PublishTrackStatus::NoSubscribers => thread::sleep(Duration::from_millis(20)),
            _ => return Err(io::Error::other("publisher failed to become ready").into()),
        }
    }

    let mut headers = ObjectHeaders::default();
    loop {
        let text = prompt("Enter text (/quit to exit): ")?;
        if text == "/quit" {
            break;
        }

        headers.priority = Some(127);
        headers.status = ObjectStatus::Available;
        let _outcome = handler.publish_object(&headers, text.as_bytes())?;
        headers.group_id += 1;
    }

    eprintln!("Done publishing! Goodbye");
    Ok(())
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
