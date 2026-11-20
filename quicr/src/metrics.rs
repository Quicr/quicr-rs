// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

/// Integer summary of samples collected during a metrics period.
///
/// Units are determined by the containing field. An empty summary has the
/// all-zero [`Default`] value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MinMaxAvg {
    /// Minimum sampled value.
    pub min: u64,
    /// Maximum sampled value.
    pub max: u64,
    /// Arithmetic mean of sampled values.
    pub avg: u64,
    /// Sum of sampled values.
    pub value_sum: u64,
    /// Number of values included in the summary.
    pub value_count: u64,
}

impl From<quicr_sys::quicr_min_max_avg_t> for MinMaxAvg {
    fn from(value: quicr_sys::quicr_min_max_avg_t) -> Self {
        Self {
            min: value.min,
            max: value.max,
            avg: value.avg,
            value_sum: value.value_sum,
            value_count: value.value_count,
        }
    }
}

/// QUIC-level connection counters and period aggregates.
///
/// Counter fields are cumulative unless described as a period aggregate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicConnectionMetrics {
    /// Number of congestion-window congestion events.
    pub cwin_congested: u64,
    /// [`cwin_congested`](Self::cwin_congested) value at the previous sample.
    pub prev_cwin_congested: u64,
    /// Number of times transmission was considered congested.
    pub tx_congested: u64,
    /// Transmit-rate samples, in bits per second.
    pub tx_rate_bps: MinMaxAvg,
    /// Estimated receive-rate samples, in bits per second.
    pub rx_rate_bps: MinMaxAvg,
    /// Congestion-window-size samples, in bytes.
    pub tx_cwin_bytes: MinMaxAvg,
    /// In-flight-data samples, in bytes.
    pub tx_in_transit_bytes: MinMaxAvg,
    /// Round-trip-time samples, in microseconds.
    pub rtt_us: MinMaxAvg,
    /// Smoothed round-trip-time samples, in microseconds.
    pub srtt_us: MinMaxAvg,
    /// Number of retransmitted packets.
    pub tx_retransmits: u64,
    /// Number of transmitted packets declared lost.
    pub tx_lost_pkts: u64,
    /// Number of packet losses detected by timer expiry.
    pub tx_timer_losses: u64,
    /// Number of packets declared lost and subsequently acknowledged.
    pub tx_spurious_losses: u64,
    /// Number of received datagrams.
    pub rx_dgrams: u64,
    /// Total received datagram bytes.
    pub rx_dgrams_bytes: u64,
    /// Number of datagram-send-ready callbacks.
    pub tx_dgram_cb: u64,
    /// Number of acknowledged datagrams.
    pub tx_dgram_ack: u64,
    /// Number of lost datagrams.
    pub tx_dgram_lost: u64,
    /// Number of datagrams acknowledged after being declared lost.
    pub tx_dgram_spurious: u64,
}

impl From<quicr_sys::quicr_quic_connection_metrics_t> for QuicConnectionMetrics {
    fn from(value: quicr_sys::quicr_quic_connection_metrics_t) -> Self {
        Self {
            cwin_congested: value.cwin_congested,
            prev_cwin_congested: value.prev_cwin_congested,
            tx_congested: value.tx_congested,
            tx_rate_bps: value.tx_rate_bps.into(),
            rx_rate_bps: value.rx_rate_bps.into(),
            tx_cwin_bytes: value.tx_cwin_bytes.into(),
            tx_in_transit_bytes: value.tx_in_transit_bytes.into(),
            rtt_us: value.rtt_us.into(),
            srtt_us: value.srtt_us.into(),
            tx_retransmits: value.tx_retransmits,
            tx_lost_pkts: value.tx_lost_pkts,
            tx_timer_losses: value.tx_timer_losses,
            tx_spurious_losses: value.tx_spurious_losses,
            rx_dgrams: value.rx_dgrams,
            rx_dgrams_bytes: value.rx_dgrams_bytes,
            tx_dgram_cb: value.tx_dgram_cb,
            tx_dgram_ack: value.tx_dgram_ack,
            tx_dgram_lost: value.tx_dgram_lost,
            tx_dgram_spurious: value.tx_dgram_spurious,
        }
    }
}

/// Metrics sampled for one connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionMetrics {
    /// Sample timestamp in microseconds since the Unix epoch.
    pub last_sample_time: u64,
    /// QUIC transport metrics.
    pub quic: QuicConnectionMetrics,
    /// Datagrams received with an unknown track alias.
    pub rx_dgram_unknown_track_alias: u64,
    /// Datagrams received with an invalid object-datagram type.
    pub rx_dgram_invalid_type: u64,
    /// Datagrams that could not be decoded.
    pub rx_dgram_decode_failed: u64,
    /// Stream-buffer parsing failures.
    pub rx_stream_buffer_error: u64,
    /// Stream headers received with an unknown track alias.
    pub rx_stream_unknown_track_alias: u64,
    /// Stream messages received with an invalid type.
    pub rx_stream_invalid_type: u64,
    /// Invalid control-stream messages received.
    pub invalid_ctrl_stream_msg: u64,
}

impl From<quicr_sys::quicr_connection_metrics_t> for ConnectionMetrics {
    fn from(value: quicr_sys::quicr_connection_metrics_t) -> Self {
        Self {
            last_sample_time: value.last_sample_time,
            quic: value.quic.into(),
            rx_dgram_unknown_track_alias: value.rx_dgram_unknown_track_alias,
            rx_dgram_invalid_type: value.rx_dgram_invalid_type,
            rx_dgram_decode_failed: value.rx_dgram_decode_failed,
            rx_stream_buffer_error: value.rx_stream_buffer_error,
            rx_stream_unknown_track_alias: value.rx_stream_unknown_track_alias,
            rx_stream_invalid_type: value.rx_stream_invalid_type,
            invalid_ctrl_stream_msg: value.invalid_ctrl_stream_msg,
        }
    }
}

/// Subscriber-track counters for one metrics sample period.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubscribeTrackMetrics {
    /// Native implementation timestamp for the sample.
    ///
    /// Samples emitted together share this value; consumers should not assume
    /// it is a wall-clock timestamp.
    pub last_sample_time: u64,
    /// Payload bytes received during the period.
    pub bytes_received: u64,
    /// Objects received during the period.
    pub objects_received: u64,
}

impl From<quicr_sys::quicr_subscribe_track_metrics_t> for SubscribeTrackMetrics {
    fn from(value: quicr_sys::quicr_subscribe_track_metrics_t) -> Self {
        Self {
            last_sample_time: value.last_sample_time,
            bytes_received: value.bytes_received,
            objects_received: value.objects_received,
        }
    }
}

/// QUIC publishing counters and aggregates for one sample period.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublishTrackQuicMetrics {
    /// Objects dropped because the transmit buffer was full.
    pub tx_buffer_drops: u64,
    /// Objects discarded from the transmit queue.
    pub tx_queue_discards: u64,
    /// Objects that expired in the transmit queue.
    pub tx_queue_expired: u64,
    /// Delayed transmit callbacks.
    pub tx_delayed_callback: u64,
    /// Transmit-queue-size samples, in queued entries.
    pub tx_queue_size: MinMaxAvg,
    /// Transmit-callback-duration samples, in milliseconds.
    pub tx_callback_ms: MinMaxAvg,
    /// Object-transmission-duration samples, in microseconds.
    pub tx_object_duration_us: MinMaxAvg,
}

impl From<quicr_sys::quicr_publish_track_quic_metrics_t> for PublishTrackQuicMetrics {
    fn from(value: quicr_sys::quicr_publish_track_quic_metrics_t) -> Self {
        Self {
            tx_buffer_drops: value.tx_buffer_drops,
            tx_queue_discards: value.tx_queue_discards,
            tx_queue_expired: value.tx_queue_expired,
            tx_delayed_callback: value.tx_delayed_callback,
            tx_queue_size: value.tx_queue_size.into(),
            tx_callback_ms: value.tx_callback_ms.into(),
            tx_object_duration_us: value.tx_object_duration_us.into(),
        }
    }
}

/// Publisher-track counters for one metrics sample period.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublishTrackMetrics {
    /// Native implementation timestamp for the sample.
    ///
    /// Samples emitted together share this value; consumers should not assume
    /// it is a wall-clock timestamp.
    pub last_sample_time: u64,
    /// Payload bytes published during the period.
    pub bytes_published: u64,
    /// Objects published during the period.
    pub objects_published: u64,
    /// Objects dropped because their status was not
    /// [`ObjectStatus::Available`](crate::ObjectStatus::Available).
    pub objects_dropped_not_ok: u64,
    /// QUIC-specific publishing metrics for the period.
    pub quic: PublishTrackQuicMetrics,
}

impl From<quicr_sys::quicr_publish_track_metrics_t> for PublishTrackMetrics {
    fn from(value: quicr_sys::quicr_publish_track_metrics_t) -> Self {
        Self {
            last_sample_time: value.last_sample_time,
            bytes_published: value.bytes_published,
            objects_published: value.objects_published,
            objects_dropped_not_ok: value.objects_dropped_not_ok,
            quic: value.quic.into(),
        }
    }
}
