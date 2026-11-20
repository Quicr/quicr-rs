// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use quicr::{
    ClientConfig, ClientSessionCallbacks, ConnectionMetrics, ForwardingSubscribeTrackCallbacks,
    ForwardingSubscribeTrackHandler, FullTrackName, GroupOrder, Location, ObjectHeaders,
    PublishAttributes, PublishError, PublishErrorCode, PublishNamespaceError,
    PublishNamespaceHandler, PublishNamespaceStatus, PublishResponse, PublishTrackHandler,
    PublishTrackOptions, PublishTrackStatus, Reply, RequestError, ServerConfig,
    ServerSessionCallbacks, Session, SessionManager, SessionManagerCallbacks, SessionStatus,
    SetupAttributes, SetupError, StreamHeaderProperties, SubgroupIdType,
    SubscribeNamespaceCallbacks, SubscribeNamespaceHandler, SubscribeNamespaceMode,
    SubscribeNamespaceOptions, SubscribeResponse, SubscribeTrackCallbacks, SubscribeTrackHandler,
    SubscribeTrackOptions, TrackExtensions, TrackMode, TrackNamespace, TrackStatusHandler,
    TrackStatusHandlerStatus, TrackStatusResponse,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Peer {
    Client,
    Server,
}

#[derive(Clone, Eq, PartialEq)]
enum ManagerEvent {
    NewServerSession(Session),
    SessionRemoved(Session),
}

struct ManagerCallbacks(Sender<ManagerEvent>);

impl SessionManagerCallbacks for ManagerCallbacks {
    fn on_new_server_session(&self, session: &Session) {
        self.0
            .send(ManagerEvent::NewServerSession(session.clone()))
            .expect("test receiver must outlive the manager");
    }

    fn on_session_removed(&self, session: &Session) {
        self.0
            .send(ManagerEvent::SessionRemoved(session.clone()))
            .expect("test receiver must outlive the manager");
    }
}

struct SetupCallbacks {
    local: Peer,
    setup: Sender<(Peer, Vec<u8>)>,
    track_events: Option<Sender<TrackEvent>>,
    server_events: Option<Sender<ServerEvent>>,
    connection_metrics: Sender<(Peer, ConnectionMetrics)>,
}

impl SetupCallbacks {
    fn setup_received(&self, attributes: SetupAttributes<'_>) -> Reply<(), SetupError> {
        self.setup
            .send((self.local, attributes.endpoint_id().to_vec()))
            .expect("test receiver must outlive the session");

        Reply::ok(())
    }

    fn metrics_sampled(&self, metrics: ConnectionMetrics) {
        self.connection_metrics
            .send((self.local, metrics))
            .expect("test receiver must outlive the session");
    }
}

impl ClientSessionCallbacks for SetupCallbacks {
    fn setup_received(
        &self,
        _session: &Session,
        attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        self.setup_received(attributes)
    }

    fn metrics_sampled(&self, _session: &Session, metrics: ConnectionMetrics) {
        self.metrics_sampled(metrics);
    }
}

impl ServerSessionCallbacks for SetupCallbacks {
    fn setup_received(
        &self,
        _session: &Session,
        attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        self.setup_received(attributes)
    }

    fn metrics_sampled(&self, _session: &Session, metrics: ConnectionMetrics) {
        self.metrics_sampled(metrics);
    }

    fn publish_received(
        &self,
        _session: &Session,
        _request_id: u64,
        attributes: PublishAttributes,
        _namespace_handler: Option<quicr::SubscribeNamespaceHandlerRef<'_>>,
    ) -> Reply<PublishResponse, PublishError> {
        if attributes.track_full_name.name() == b"rejected" {
            return Reply::err(
                PublishError::new(PublishErrorCode::Rejected)
                    .expect("non-redirect publish error")
                    .with_reason("publish rejected")
                    .expect("valid rejection reason"),
            );
        }

        let Some(track_events) = self.track_events.clone() else {
            return Reply::err(
                PublishError::new(PublishErrorCode::NotSupported)
                    .expect("non-redirect publish error"),
            );
        };

        if attributes.track_full_name.name() == b"forwarding" {
            return match ForwardingSubscribeTrackHandler::new_with_callbacks(
                &attributes.track_full_name,
                SubscribeTrackOptions {
                    priority: 127,
                    group_order: Some(GroupOrder::Ascending),
                    filter: None,
                },
                ForwardReceiver(track_events),
            ) {
                Ok(handler) => Reply::ok(PublishResponse::new(handler)),
                Err(_) => Reply::err(
                    PublishError::new(PublishErrorCode::InternalError)
                        .expect("non-redirect publish error"),
                ),
            };
        }

        match SubscribeTrackHandler::new_with_callbacks(
            &attributes.track_full_name,
            SubscribeTrackOptions {
                priority: 127,
                group_order: Some(GroupOrder::Ascending),
                filter: None,
            },
            ObjectReceiver(track_events),
        ) {
            Ok(handler) => Reply::ok(PublishResponse::new(handler)),
            Err(_) => Reply::err(
                PublishError::new(PublishErrorCode::InternalError)
                    .expect("non-redirect publish error"),
            ),
        }
    }

    fn track_status_received(
        &self,
        _session: &Session,
        _full_track_name: FullTrackName,
    ) -> Reply<TrackStatusResponse, RequestError> {
        Reply::ok(TrackStatusResponse {
            largest_location: Some(Location {
                group: 12,
                object: 34,
            }),
            track_properties: TrackExtensions::new(),
        })
    }

    fn subscribe_namespace_received(
        &self,
        _session: &Session,
        prefix: TrackNamespace,
        _attributes: quicr::SubscribeNamespaceAttributes,
    ) -> Reply<Vec<TrackNamespace>, RequestError> {
        let mut entries: Vec<_> = prefix.entries().map(<[u8]>::to_vec).collect();
        entries.push(b"child".to_vec());

        Reply::ok(vec![
            TrackNamespace::new(entries).expect("valid namespace response"),
        ])
    }

    fn publish_namespace_received(
        &self,
        _session: &Session,
        _track_namespace: TrackNamespace,
        _attributes: quicr::PublishNamespaceAttributes,
    ) -> Reply<(), PublishNamespaceError> {
        Reply::ok(())
    }

    fn publish_done_received(&self, _session: &Session, request_id: u64) {
        if let Some(events) = &self.server_events {
            events
                .send(ServerEvent::PublishDone(request_id))
                .expect("test receiver must outlive the session");
        }
    }

    fn publish_namespace_done_received(&self, _session: &Session, request_id: u64) {
        if let Some(events) = &self.server_events {
            events
                .send(ServerEvent::PublishNamespaceDone(request_id))
                .expect("test receiver must outlive the session");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerEvent {
    PublishDone(u64),
    PublishNamespaceDone(u64),
}

#[derive(Debug, Eq, PartialEq)]
enum TrackEvent {
    Object {
        headers: ObjectHeaders,
        data: Vec<u8>,
        properties: Option<StreamHeaderProperties>,
    },
    SubgroupEnded {
        group_id: u64,
        subgroup_id: u64,
        reset: bool,
    },
    Datagram(Vec<u8>),
    SubgroupStarted {
        group_id: u64,
        subgroup_id: u64,
        properties: Option<StreamHeaderProperties>,
    },
    BytesForwarded {
        group_id: u64,
        subgroup_id: u64,
        data: Vec<u8>,
    },
}

struct ObjectReceiver(Sender<TrackEvent>);

impl SubscribeTrackCallbacks for ObjectReceiver {
    fn object_received(
        &self,
        headers: ObjectHeaders,
        data: &[u8],
        properties: Option<StreamHeaderProperties>,
    ) {
        self.0
            .send(TrackEvent::Object {
                headers,
                data: data.to_vec(),
                properties,
            })
            .expect("test receiver must outlive the handler");
    }

    fn subgroup_ended(&self, group_id: u64, subgroup_id: u64, reset: bool) {
        self.0
            .send(TrackEvent::SubgroupEnded {
                group_id,
                subgroup_id,
                reset,
            })
            .expect("test receiver must outlive the handler");
    }

    fn datagram_received(&self, data: &[u8]) {
        self.0
            .send(TrackEvent::Datagram(data.to_vec()))
            .expect("test receiver must outlive the handler");
    }
}

struct ForwardReceiver(Sender<TrackEvent>);

impl SubscribeTrackCallbacks for ForwardReceiver {
    fn subgroup_ended(&self, group_id: u64, subgroup_id: u64, reset: bool) {
        self.0
            .send(TrackEvent::SubgroupEnded {
                group_id,
                subgroup_id,
                reset,
            })
            .expect("test receiver must outlive the handler");
    }
}

impl ForwardingSubscribeTrackCallbacks for ForwardReceiver {
    fn subgroup_started(
        &self,
        group_id: u64,
        subgroup_id: u64,
        _priority: Option<u8>,
        properties: Option<StreamHeaderProperties>,
    ) {
        self.0
            .send(TrackEvent::SubgroupStarted {
                group_id,
                subgroup_id,
                properties,
            })
            .expect("test receiver must outlive the handler");
    }

    fn stream_bytes_forwarded(&self, group_id: u64, subgroup_id: u64, data: &[u8]) {
        self.0
            .send(TrackEvent::BytesForwarded {
                group_id,
                subgroup_id,
                data: data.to_vec(),
            })
            .expect("test receiver must outlive the handler");
    }
}

struct NamespaceReceiver(Sender<TrackNamespace>);

impl SubscribeNamespaceCallbacks for NamespaceReceiver {
    fn namespace_received(&self, track_namespace: TrackNamespace) {
        self.0
            .send(track_namespace)
            .expect("test receiver must outlive the handler");
    }
}

#[test]
fn client_and_server_complete_setup_and_disconnect() {
    let certificate = TestCertificate::generate();
    let port_reservation = ReservedUdpPort::new();
    let port = port_reservation.port();
    let (setup_tx, setup_rx) = mpsc::channel();
    let (track_event_tx, track_event_rx) = mpsc::channel();
    let (namespace_tx, namespace_rx) = mpsc::channel();
    let (manager_event_tx, manager_event_rx) = mpsc::channel();
    let (server_event_tx, server_event_rx) = mpsc::channel();
    let (connection_metrics_tx, connection_metrics_rx) = mpsc::channel();

    let mut manager = SessionManager::builder()
        .callbacks(ManagerCallbacks(manager_event_tx))
        .build()
        .expect("create session manager");

    let mut server_config = ServerConfig::default();
    server_config.endpoint_id = "rust-server".into();
    server_config.bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    server_config.transport_config.tls_cert_path = Some(certificate.cert.clone());
    server_config.transport_config.tls_key_path = Some(certificate.key.clone());
    server_config.transport_config.time_queue_max_duration = Duration::from_secs(10);
    server_config.transport_config.metrics_sample_interval = Duration::from_millis(50);
    server_config.transport_config.use_af_xdp = false;

    drop(port_reservation);
    manager
        .add_server(
            &server_config,
            SetupCallbacks {
                local: Peer::Server,
                setup: setup_tx.clone(),
                track_events: Some(track_event_tx),
                server_events: Some(server_event_tx),
                connection_metrics: connection_metrics_tx.clone(),
            },
        )
        .expect("start server");

    let mut client_config = ClientConfig::default();
    client_config.endpoint_id = "rust-client".into();
    client_config.connect_uri = format!("moq://127.0.0.1:{port}/relay");
    client_config.transport_config.time_queue_max_duration = Duration::from_secs(10);
    client_config.transport_config.metrics_sample_interval = Duration::from_millis(50);
    client_config.transport_config.use_af_xdp = false;

    let session = manager
        .add_transport(
            &client_config,
            SetupCallbacks {
                local: Peer::Client,
                setup: setup_tx,
                track_events: None,
                server_events: None,
                connection_metrics: connection_metrics_tx,
            },
        )
        .expect("start client");

    wait_until("client ready", Duration::from_secs(10), || {
        matches!(session.status(), Ok(SessionStatus::Ready))
    });
    assert!(matches!(
        manager_event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("new server session callback"),
        ManagerEvent::NewServerSession(_)
    ));

    let first = setup_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first setup callback");
    let second = setup_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second setup callback");

    let mut setups = [first, second];
    setups.sort_by_key(|(peer, _)| match peer {
        Peer::Client => 0,
        Peer::Server => 1,
    });

    assert_eq!(
        setups,
        [
            (Peer::Client, b"rust-server".to_vec()),
            (Peer::Server, b"rust-client".to_vec()),
        ]
    );

    let metrics_deadline = Instant::now() + Duration::from_secs(10);
    let mut client_metrics = false;
    let mut server_metrics = false;
    while !client_metrics || !server_metrics {
        let remaining = metrics_deadline
            .checked_duration_since(Instant::now())
            .expect("connection metrics timed out");
        let (peer, metrics) = connection_metrics_rx
            .recv_timeout(remaining)
            .expect("connection metrics callback");
        assert!(metrics.last_sample_time > 0);

        let has_transport_sample =
            metrics.quic.rtt_us.value_count > 0 || metrics.quic.srtt_us.value_count > 0;
        if !has_transport_sample {
            continue;
        }

        match peer {
            Peer::Client => client_metrics = true,
            Peer::Server => server_metrics = true,
        }
    }

    let full_track_name = FullTrackName::new(
        TrackNamespace::new(["integration"]).expect("track namespace"),
        "track",
    );
    let mut publisher = PublishTrackHandler::new(
        &full_track_name,
        PublishTrackOptions {
            track_mode: TrackMode::Stream,
            publisher_priority: 127,
            publish_object_priority: 127,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        },
    )
    .expect("create publisher");

    manager
        .add_handler(&session, &publisher)
        .expect("register publisher");
    wait_until("publisher ready", Duration::from_secs(10), || {
        publisher.can_publish()
    });

    let headers = ObjectHeaders {
        group_id: 1,
        object_id: 2,
        subgroup_id: 3,
        priority: Some(42),
        ttl: Some(Duration::from_secs(1)),
        track_mode: Some(TrackMode::Stream),
        ..ObjectHeaders::default()
    };
    let properties = StreamHeaderProperties {
        extensions: false,
        subgroup_id_type: SubgroupIdType::Explicit,
        end_of_group: false,
        default_priority: false,
        first_object: true,
    };
    let payload = b"hello from Rust";

    publisher
        .publish_object_with_properties(&headers, payload, Some(&properties))
        .expect("publish object");
    assert_eq!(
        track_event_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("receive published object"),
        TrackEvent::Object {
            headers: ObjectHeaders {
                payload_length: payload.len() as u64,
                priority: Some(127),
                ttl: None,
                ..headers
            },
            data: payload.to_vec(),
            properties: Some(properties),
        }
    );
    publisher.end_subgroup(1, 3, true).expect("end subgroup");
    assert_eq!(
        track_event_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("receive subgroup completion"),
        TrackEvent::SubgroupEnded {
            group_id: 1,
            subgroup_id: 3,
            reset: false,
        }
    );

    let datagram_name = FullTrackName::new(
        TrackNamespace::new(["integration"]).expect("datagram namespace"),
        "datagram",
    );
    let mut datagram_publisher = PublishTrackHandler::new(
        &datagram_name,
        PublishTrackOptions {
            track_mode: TrackMode::Datagram,
            publisher_priority: 127,
            publish_object_priority: 127,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        },
    )
    .expect("create datagram publisher");
    manager
        .add_handler(&session, &datagram_publisher)
        .expect("register datagram publisher");
    wait_until("datagram publisher ready", Duration::from_secs(10), || {
        datagram_publisher.can_publish()
    });
    datagram_publisher
        .publish_object(
            &ObjectHeaders {
                group_id: 4,
                object_id: 5,
                track_mode: Some(TrackMode::Datagram),
                ..ObjectHeaders::default()
            },
            b"datagram payload",
        )
        .expect("publish datagram");
    let TrackEvent::Datagram(datagram) = track_event_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("receive datagram")
    else {
        panic!("expected datagram callback");
    };
    assert!(
        datagram.ends_with(b"datagram payload"),
        "encoded datagram did not contain the published payload"
    );
    manager
        .remove_handler(&session, &datagram_publisher)
        .expect("remove datagram publisher");
    expect_publish_done(&server_event_rx);
    datagram_publisher
        .close()
        .expect("close datagram publisher");

    let forwarding_name = FullTrackName::new(
        TrackNamespace::new(["integration"]).expect("forwarding namespace"),
        "forwarding",
    );
    let mut forwarding_publisher = PublishTrackHandler::new(
        &forwarding_name,
        PublishTrackOptions {
            track_mode: TrackMode::Stream,
            publisher_priority: 127,
            publish_object_priority: 127,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        },
    )
    .expect("create forwarding publisher");
    manager
        .add_handler(&session, &forwarding_publisher)
        .expect("register forwarding publisher");
    wait_until(
        "forwarding publisher ready",
        Duration::from_secs(10),
        || forwarding_publisher.can_publish(),
    );
    let forwarding_properties = StreamHeaderProperties {
        extensions: false,
        subgroup_id_type: SubgroupIdType::Explicit,
        end_of_group: false,
        default_priority: false,
        first_object: true,
    };
    forwarding_publisher
        .publish_object_with_properties(
            &ObjectHeaders {
                group_id: 6,
                object_id: 0,
                subgroup_id: 7,
                track_mode: Some(TrackMode::Stream),
                ..ObjectHeaders::default()
            },
            b"forwarded payload",
            Some(&forwarding_properties),
        )
        .expect("publish forwarded object");
    assert_eq!(
        track_event_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("forwarding subgroup start"),
        TrackEvent::SubgroupStarted {
            group_id: 6,
            subgroup_id: 7,
            properties: Some(forwarding_properties),
        }
    );
    let mut forwarded = Vec::new();
    let TrackEvent::BytesForwarded {
        group_id,
        subgroup_id,
        data,
    } = track_event_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("forwarded stream bytes")
    else {
        panic!("expected forwarded bytes callback");
    };
    assert_eq!((group_id, subgroup_id), (6, 7));
    forwarded.extend_from_slice(&data);

    forwarding_publisher
        .end_subgroup(6, 7, true)
        .expect("end forwarding subgroup");

    loop {
        match track_event_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("forwarding subgroup completion")
        {
            TrackEvent::BytesForwarded {
                group_id,
                subgroup_id,
                data,
            } => {
                assert_eq!((group_id, subgroup_id), (6, 7));
                forwarded.extend_from_slice(&data);
            }
            TrackEvent::SubgroupEnded {
                group_id,
                subgroup_id,
                reset,
            } => {
                assert_eq!((group_id, subgroup_id, reset), (6, 7, false));
                break;
            }
            event => panic!("unexpected forwarding event: {event:?}"),
        }
    }
    assert!(
        forwarded
            .windows(b"forwarded payload".len())
            .any(|window| window == b"forwarded payload"),
        "forwarded stream did not contain the published payload"
    );

    manager
        .remove_handler(&session, &forwarding_publisher)
        .expect("remove forwarding publisher");
    expect_publish_done(&server_event_rx);
    forwarding_publisher
        .close()
        .expect("close forwarding publisher");

    let track_status = TrackStatusHandler::new(&full_track_name).expect("create track status");
    manager
        .add_handler(&session, &track_status)
        .expect("register track status");
    wait_until("track status response", Duration::from_secs(10), || {
        matches!(track_status.status(), Ok(TrackStatusHandlerStatus::Ok))
    });

    let response = track_status
        .response()
        .expect("read track status response")
        .expect("track status response");
    assert_eq!(
        response.largest_location,
        Some(Location {
            group: 12,
            object: 34,
        })
    );
    assert!(response.track_properties.is_empty());
    assert!(response.track_properties.is_immutable_empty());
    manager
        .remove_handler(&session, &track_status)
        .expect("remove track status");
    track_status.close().expect("close track status");

    let prefix = TrackNamespace::new(["integration"]).expect("namespace prefix");
    let namespace_handler = SubscribeNamespaceHandler::new_with_callbacks(
        &prefix,
        SubscribeNamespaceOptions {
            mode: SubscribeNamespaceMode::Namespaces,
            filter: None,
        },
        NamespaceReceiver(namespace_tx),
    )
    .expect("create namespace subscriber");
    manager
        .add_handler(&session, &namespace_handler)
        .expect("register namespace subscriber");
    let namespace = namespace_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("receive initial namespace");
    assert_eq!(
        namespace.entries().collect::<Vec<_>>(),
        vec![b"child".as_slice()]
    );
    manager
        .remove_handler(&session, &namespace_handler)
        .expect("remove namespace subscriber");
    namespace_handler
        .close()
        .expect("close namespace subscriber");

    let published_namespace =
        TrackNamespace::new(["integration", "published"]).expect("published namespace");
    let publish_namespace =
        PublishNamespaceHandler::new(&published_namespace).expect("create namespace publisher");
    manager
        .add_handler(&session, &publish_namespace)
        .expect("register namespace publisher");
    wait_until(
        "namespace publish accepted",
        Duration::from_secs(10),
        || matches!(publish_namespace.status(), Ok(PublishNamespaceStatus::Ok)),
    );
    manager
        .remove_handler(&session, &publish_namespace)
        .expect("remove namespace publisher");
    assert!(matches!(
        server_event_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("namespace publish completion"),
        ServerEvent::PublishNamespaceDone(_)
    ));
    publish_namespace
        .close()
        .expect("close namespace publisher");

    let rejected_name = FullTrackName::new(
        TrackNamespace::new(["integration"]).expect("rejected namespace"),
        "rejected",
    );
    let rejected = PublishTrackHandler::new(
        &rejected_name,
        PublishTrackOptions {
            track_mode: TrackMode::Stream,
            publisher_priority: 127,
            publish_object_priority: 127,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        },
    )
    .expect("create rejected publisher");
    manager
        .add_handler(&session, &rejected)
        .expect("register rejected publisher");
    wait_until("publish rejection", Duration::from_secs(10), || {
        matches!(rejected.status(), Ok(PublishTrackStatus::DoneByFin))
    });
    manager
        .remove_handler(&session, &rejected)
        .expect("remove rejected publisher");
    rejected.close().expect("close rejected publisher");

    manager
        .remove_handler(&session, &publisher)
        .expect("remove publisher");
    expect_publish_done(&server_event_rx);
    publisher.close().expect("close publisher");
    session.disconnect().expect("disconnect client");
    wait_until("client disconnected", Duration::from_secs(10), || {
        matches!(
            session.status(),
            Err(_) | Ok(SessionStatus::NotConnected | SessionStatus::Disconnecting)
        )
    });
    let removal_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = removal_deadline
            .checked_duration_since(Instant::now())
            .expect("client session removal callback timed out");
        match manager_event_rx
            .recv_timeout(remaining)
            .expect("session removal callback")
        {
            ManagerEvent::SessionRemoved(removed) if removed == session => break,
            ManagerEvent::SessionRemoved(_) | ManagerEvent::NewServerSession(_) => {}
        }
    }
    wait_until("session expired", Duration::from_secs(10), || {
        session.is_expired()
    });
}

struct MigrationManagerCallbacks(Sender<Session>);

impl SessionManagerCallbacks for MigrationManagerCallbacks {
    fn on_new_server_session(&self, session: &Session) {
        self.0
            .send(session.clone())
            .expect("test receiver must outlive the manager");
    }
}

struct MigrationServerCallbacks {
    endpoint: &'static str,
    subscriptions: Sender<MigrationSubscription>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MigrationSubscription {
    endpoint: &'static str,
    request_id: u64,
    full_track_name: FullTrackName,
    attributes: quicr::SubscribeAttributes,
}

impl ServerSessionCallbacks for MigrationServerCallbacks {
    fn setup_received(
        &self,
        _session: &Session,
        _attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        Reply::ok(())
    }

    fn subscribe_received(
        &self,
        _session: &Session,
        request_id: u64,
        full_track_name: FullTrackName,
        attributes: quicr::SubscribeAttributes,
    ) -> Reply<SubscribeResponse, RequestError> {
        self.subscriptions
            .send(MigrationSubscription {
                endpoint: self.endpoint,
                request_id,
                full_track_name,
                attributes,
            })
            .expect("test receiver must outlive the session");

        Reply::ok(SubscribeResponse {
            track_status: TrackStatusResponse {
                largest_location: None,
                track_properties: TrackExtensions::new(),
            },
            is_publisher_initiated: false,
            expires: None,
        })
    }
}

struct MigrationClientCallbacks(Sender<Vec<u8>>);

impl ClientSessionCallbacks for MigrationClientCallbacks {
    fn setup_received(
        &self,
        _session: &Session,
        attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        self.0
            .send(attributes.endpoint_id().to_vec())
            .expect("test receiver must outlive the session");

        Reply::ok(())
    }
}

#[test]
fn goaway_migrates_an_active_subscription() {
    let certificate = TestCertificate::generate();
    let old_port_reservation = ReservedUdpPort::new();
    let new_port_reservation = ReservedUdpPort::new();
    let old_port = old_port_reservation.port();
    let new_port = new_port_reservation.port();
    let (server_sessions_tx, server_sessions_rx) = mpsc::channel();
    let (subscriptions_tx, subscriptions_rx) = mpsc::channel();
    let (setups_tx, setups_rx) = mpsc::channel();
    let mut manager = SessionManager::builder()
        .callbacks(MigrationManagerCallbacks(server_sessions_tx))
        .build()
        .expect("create migration manager");

    for (endpoint, port, reservation) in [
        ("old-relay", old_port, old_port_reservation),
        ("new-relay", new_port, new_port_reservation),
    ] {
        let mut config = ServerConfig::default();
        config.endpoint_id = endpoint.into();
        config.bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        config.transport_config.tls_cert_path = Some(certificate.cert.clone());
        config.transport_config.tls_key_path = Some(certificate.key.clone());
        config.transport_config.time_queue_max_duration = Duration::from_secs(10);
        config.transport_config.use_af_xdp = false;

        drop(reservation);
        manager
            .add_server(
                &config,
                MigrationServerCallbacks {
                    endpoint,
                    subscriptions: subscriptions_tx.clone(),
                },
            )
            .expect("start migration server");
    }

    let mut client_config = ClientConfig::default();
    client_config.endpoint_id = "migrating-client".into();
    client_config.connect_uri = format!("moq://127.0.0.1:{old_port}/relay");
    client_config.transport_config.time_queue_max_duration = Duration::from_secs(10);
    client_config.transport_config.use_af_xdp = false;

    let session = manager
        .add_transport(&client_config, MigrationClientCallbacks(setups_tx))
        .expect("start migrating client");
    wait_until("migration client ready", Duration::from_secs(10), || {
        matches!(session.status(), Ok(SessionStatus::Ready))
    });
    assert_eq!(
        setups_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("old relay setup"),
        b"old-relay"
    );
    let old_server_session = server_sessions_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("old server session");

    let track_name = FullTrackName::new(
        TrackNamespace::new(["goaway"]).expect("GOAWAY namespace"),
        "track",
    );
    let subscriber = SubscribeTrackHandler::new(
        &track_name,
        SubscribeTrackOptions {
            priority: 127,
            group_order: Some(GroupOrder::Ascending),
            filter: None,
        },
    )
    .expect("create migrating subscriber");
    manager
        .add_handler(&session, &subscriber)
        .expect("register migrating subscriber");
    let old_subscription = subscriptions_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("old relay subscription");
    assert_eq!(old_subscription.endpoint, "old-relay");
    assert_eq!(old_subscription.full_track_name, track_name);

    old_server_session
        .goaway(
            &format!("moq://127.0.0.1:{new_port}/relay"),
            Duration::from_secs(5),
            None,
        )
        .expect("send GOAWAY");
    assert_eq!(
        setups_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("new relay setup"),
        b"new-relay"
    );
    let _new_server_session = server_sessions_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("new server session");
    let migrated_subscription = subscriptions_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("migrated subscription");
    assert_eq!(migrated_subscription.endpoint, "new-relay");
    assert_eq!(
        (
            migrated_subscription.request_id,
            &migrated_subscription.full_track_name,
            migrated_subscription.attributes,
        ),
        (
            old_subscription.request_id,
            &old_subscription.full_track_name,
            old_subscription.attributes,
        )
    );
    wait_until("migrated subscriber ready", Duration::from_secs(10), || {
        matches!(subscriber.status(), Ok(quicr::SubscribeTrackStatus::Ok))
    });

    drop(manager);
    subscriber.close().expect("close migrated subscriber");
    assert!(session.is_expired());
}

struct ReservedUdpPort(UdpSocket);

impl ReservedUdpPort {
    fn new() -> Self {
        Self(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve local UDP port"))
    }

    fn port(&self) -> u16 {
        self.0
            .local_addr()
            .expect("read reserved UDP address")
            .port()
    }
}

fn expect_publish_done(events: &Receiver<ServerEvent>) {
    assert!(matches!(
        events
            .recv_timeout(Duration::from_secs(10))
            .expect("publish completion"),
        ServerEvent::PublishDone(_)
    ));
}

struct TestCertificate {
    _directory: TestDirectory,
    cert: PathBuf,
    key: PathBuf,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(path: PathBuf) -> Self {
        fs::create_dir(&path).expect("create certificate directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TestCertificate {
    fn generate() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let directory = TestDirectory::new(std::env::temp_dir().join(format!(
            "quicr-rs-test-cert-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )));

        let cert = directory.0.join("server-cert.pem");
        let key = directory.0.join("server-key.pem");
        let output = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .expect("run openssl to generate a test certificate");
        assert!(
            output.status.success(),
            "openssl failed to generate test certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self {
            _directory: directory,
            cert,
            key,
        }
    }
}

fn wait_until(description: &str, timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;

    while !predicate() {
        assert!(Instant::now() < deadline, "{description} timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
