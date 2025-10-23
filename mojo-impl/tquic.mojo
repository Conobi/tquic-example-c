"""
TQUIC FFI Bindings for Mojo

This module provides Mojo bindings for the TQUIC C library, enabling
QUIC and HTTP/3 protocol support in Mojo applications.
"""

from sys.ffi import DLHandle, external_call
from memory import UnsafePointer
from sys import sizeof

# C type aliases
alias c_int = Int32
alias c_uint = UInt32
alias c_size_t = UInt
alias c_uint64 = UInt64
alias c_int64 = Int64
alias c_uint8 = UInt8
alias c_bool = Bool
alias c_char = Int8
alias c_void_ptr = UnsafePointer[NoneType]
alias socklen_t = UInt32

# TQUIC constants
alias MAX_CID_LEN = 20
alias MAX_DATAGRAM_SIZE = 1200
alias READ_BUF_SIZE = 4096

# Opaque pointer types for TQUIC structures
alias QuicConfig = UnsafePointer[NoneType]
alias QuicEndpoint = UnsafePointer[NoneType]
alias QuicConn = UnsafePointer[NoneType]
alias QuicTLSConfig = UnsafePointer[NoneType]
alias HTTP3Config = UnsafePointer[NoneType]
alias HTTP3Conn = UnsafePointer[NoneType]
alias HTTP3Headers = UnsafePointer[NoneType]


# sockaddr_storage structure (128 bytes on most systems)
@fieldwise_init
@register_passable("trivial")
struct SockaddrStorage:
    var data: SIMD[DType.uint8, 128]

    fn __init__(out self):
        self.data = SIMD[DType.uint8, 128](0)


# quic_packet_info_t structure
@fieldwise_init
@register_passable("trivial")
struct QuicPacketInfo:
    var src: UnsafePointer[NoneType]
    var src_len: socklen_t
    var dst: UnsafePointer[NoneType]
    var dst_len: socklen_t


# http3_header_t structure
@fieldwise_init
@register_passable("trivial")
struct HTTP3Header:
    var name: UnsafePointer[UInt8]
    var name_len: UInt
    var value: UnsafePointer[UInt8]
    var value_len: UInt


# Callback function type aliases
alias QuicTransportCallback = fn (c_void_ptr, QuicConn) -> None
alias QuicStreamCallback = fn (c_void_ptr, QuicConn, c_uint64) -> None
alias QuicPacketSendCallback = fn (c_void_ptr, c_void_ptr, c_uint) -> c_int
alias HTTP3StreamHeadersCallback = fn (
    c_void_ptr, c_uint64, HTTP3Headers, c_bool
) -> None
alias HTTP3StreamDataCallback = fn (c_void_ptr, c_uint64) -> None


# quic_transport_methods_t structure
@fieldwise_init
@register_passable("trivial")
struct QuicTransportMethods:
    var on_conn_created: UnsafePointer[NoneType]
    var on_conn_established: UnsafePointer[NoneType]
    var on_conn_closed: UnsafePointer[NoneType]
    var on_stream_created: UnsafePointer[NoneType]
    var on_stream_readable: UnsafePointer[NoneType]
    var on_stream_writable: UnsafePointer[NoneType]
    var on_stream_closed: UnsafePointer[NoneType]
    var on_new_token: UnsafePointer[NoneType]


# quic_packet_send_methods_t structure
@fieldwise_init
@register_passable("trivial")
struct QuicPacketSendMethods:
    var on_packets_send: UnsafePointer[NoneType]


# http3_methods_t structure
@fieldwise_init
@register_passable("trivial")
struct HTTP3Methods:
    var on_stream_headers: UnsafePointer[NoneType]
    var on_stream_data: UnsafePointer[NoneType]
    var on_stream_finished: UnsafePointer[NoneType]
    var on_stream_reset: UnsafePointer[NoneType]
    var on_stream_priority_update: UnsafePointer[NoneType]
    var on_conn_goaway: UnsafePointer[NoneType]


# TLS config select methods structure
@fieldwise_init
@register_passable("trivial")
struct QuicTLSConfigSelectMethods:
    var get_default: UnsafePointer[NoneType]
    var select: UnsafePointer[NoneType]


struct TQUICLib:
    """Wrapper for TQUIC library functions."""

    var handle: DLHandle

    fn __init__(
        out self, lib_path: String = "../deps/tquic/target/release/libtquic.a"
    ) raises:
        """Initialize TQUIC library handle.

        Args:
            lib_path: Path to the TQUIC library.
        """
        # For static library, we need the shared library version
        # We'll need to build TQUIC as a shared library
        var so_path = "../deps/tquic/target/release/libtquic.so"
        self.handle = DLHandle(so_path)

    # =================================================================================
    # QUIC Configuration Functions
    # =================================================================================

    fn quic_config_new(self) -> QuicConfig:
        """Create default QUIC configuration."""
        var func = self.handle.get_function[fn () -> QuicConfig](
            "quic_config_new"
        )
        return func()

    fn quic_config_free(self, config: QuicConfig):
        """Destroy a QUIC config instance."""
        var func = self.handle.get_function[fn (QuicConfig) -> None](
            "quic_config_free"
        )
        func(config)

    fn quic_config_set_max_idle_timeout(
        self, config: QuicConfig, timeout_ms: c_uint64
    ):
        """Set the max_idle_timeout transport parameter in milliseconds."""
        var func = self.handle.get_function[fn (QuicConfig, c_uint64) -> None](
            "quic_config_set_max_idle_timeout"
        )
        func(config, timeout_ms)

    fn quic_config_set_recv_udp_payload_size(
        self, config: QuicConfig, size: UInt16
    ):
        """Set the max_udp_payload_size transport parameter in bytes."""
        var func = self.handle.get_function[fn (QuicConfig, UInt16) -> None](
            "quic_config_set_recv_udp_payload_size"
        )
        func(config, size)

    fn quic_config_set_tls_selector(
        self,
        config: QuicConfig,
        methods: UnsafePointer[QuicTLSConfigSelectMethods],
        context: c_void_ptr,
    ):
        """Set TLS config selector."""
        var func = self.handle.get_function[
            fn (
                QuicConfig,
                UnsafePointer[QuicTLSConfigSelectMethods],
                c_void_ptr,
            ) -> None
        ]("quic_config_set_tls_selector")
        func(config, methods, context)

    # =================================================================================
    # TLS Configuration Functions
    # =================================================================================

    fn quic_tls_config_new_server_config(
        self,
        cert_file: UnsafePointer[c_char],
        key_file: UnsafePointer[c_char],
        protos: UnsafePointer[UnsafePointer[c_char]],
        proto_num: Int,
        enable_early_data: c_bool,
    ) -> QuicTLSConfig:
        """Create a new server side TLS config."""
        var func = self.handle.get_function[
            fn (
                UnsafePointer[c_char],
                UnsafePointer[c_char],
                UnsafePointer[UnsafePointer[c_char]],
                Int,
                c_bool,
            ) -> QuicTLSConfig
        ]("quic_tls_config_new_server_config")
        return func(cert_file, key_file, protos, proto_num, enable_early_data)

    fn quic_tls_config_free(self, config: QuicTLSConfig):
        """Destroy a TLS config instance."""
        var func = self.handle.get_function[fn (QuicTLSConfig) -> None](
            "quic_tls_config_free"
        )
        func(config)

    # =================================================================================
    # QUIC Endpoint Functions
    # =================================================================================

    fn quic_endpoint_new(
        self,
        config: QuicConfig,
        is_server: c_bool,
        handler_methods: UnsafePointer[QuicTransportMethods],
        handler_ctx: c_void_ptr,
        sender_methods: UnsafePointer[QuicPacketSendMethods],
        sender_ctx: c_void_ptr,
    ) -> QuicEndpoint:
        """Create a QUIC endpoint."""
        var func = self.handle.get_function[
            fn (
                QuicConfig,
                c_bool,
                UnsafePointer[QuicTransportMethods],
                c_void_ptr,
                UnsafePointer[QuicPacketSendMethods],
                c_void_ptr,
            ) -> QuicEndpoint
        ]("quic_endpoint_new")
        return func(
            config,
            is_server,
            handler_methods,
            handler_ctx,
            sender_methods,
            sender_ctx,
        )

    fn quic_endpoint_free(self, endpoint: QuicEndpoint):
        """Destroy a QUIC endpoint."""
        var func = self.handle.get_function[fn (QuicEndpoint) -> None](
            "quic_endpoint_free"
        )
        func(endpoint)

    fn quic_endpoint_recv(
        self,
        endpoint: QuicEndpoint,
        buf: UnsafePointer[UInt8],
        buf_len: c_size_t,
        info: UnsafePointer[QuicPacketInfo],
    ) -> c_int:
        """Process an incoming UDP datagram."""
        var func = self.handle.get_function[
            fn (
                QuicEndpoint,
                UnsafePointer[UInt8],
                c_size_t,
                UnsafePointer[QuicPacketInfo],
            ) -> c_int
        ]("quic_endpoint_recv")
        return func(endpoint, buf, buf_len, info)

    fn quic_endpoint_timeout(self, endpoint: QuicEndpoint) -> c_uint64:
        """Return the amount of time until the next timeout event."""
        var func = self.handle.get_function[fn (QuicEndpoint) -> c_uint64](
            "quic_endpoint_timeout"
        )
        return func(endpoint)

    fn quic_endpoint_on_timeout(self, endpoint: QuicEndpoint):
        """Process timeout events on the endpoint."""
        var func = self.handle.get_function[fn (QuicEndpoint) -> None](
            "quic_endpoint_on_timeout"
        )
        func(endpoint)

    fn quic_endpoint_process_connections(self, endpoint: QuicEndpoint) -> c_int:
        """Process internal events of all tickable connections."""
        var func = self.handle.get_function[fn (QuicEndpoint) -> c_int](
            "quic_endpoint_process_connections"
        )
        return func(endpoint)

    # =================================================================================
    # QUIC Connection Functions
    # =================================================================================

    fn quic_conn_set_context(self, conn: QuicConn, data: c_void_ptr):
        """Set user context for the connection."""
        var func = self.handle.get_function[fn (QuicConn, c_void_ptr) -> None](
            "quic_conn_set_context"
        )
        func(conn, data)

    fn quic_conn_context(self, conn: QuicConn) -> c_void_ptr:
        """Get user context for the connection."""
        var func = self.handle.get_function[fn (QuicConn) -> c_void_ptr](
            "quic_conn_context"
        )
        return func(conn)

    fn quic_conn_application_proto(
        self,
        conn: QuicConn,
        output: UnsafePointer[UnsafePointer[UInt8]],
        out_len: UnsafePointer[c_size_t],
    ):
        """Return the negotiated application level protocol."""
        var func = self.handle.get_function[
            fn (
                QuicConn,
                UnsafePointer[UnsafePointer[UInt8]],
                UnsafePointer[c_size_t],
            ) -> None
        ]("quic_conn_application_proto")
        func(conn, output, out_len)

    fn quic_conn_close(
        self,
        conn: QuicConn,
        app: c_bool,
        err: c_uint64,
        reason: UnsafePointer[UInt8],
        reason_len: c_size_t,
    ) -> c_int:
        """Close the connection."""
        var func = self.handle.get_function[
            fn (
                QuicConn, c_bool, c_uint64, UnsafePointer[UInt8], c_size_t
            ) -> c_int
        ]("quic_conn_close")
        return func(conn, app, err, reason, reason_len)

    fn quic_stream_wantwrite(
        self, conn: QuicConn, stream_id: c_uint64, want: c_bool
    ) -> c_int:
        """Set want write flag for a stream."""
        var func = self.handle.get_function[
            fn (QuicConn, c_uint64, c_bool) -> c_int
        ]("quic_stream_wantwrite")
        return func(conn, stream_id, want)

    # =================================================================================
    # HTTP/3 Configuration Functions
    # =================================================================================

    fn http3_config_new(self) -> HTTP3Config:
        """Create default config for HTTP/3."""
        var func = self.handle.get_function[fn () -> HTTP3Config](
            "http3_config_new"
        )
        return func()

    fn http3_config_free(self, config: HTTP3Config):
        """Destroy the HTTP/3 config."""
        var func = self.handle.get_function[fn (HTTP3Config) -> None](
            "http3_config_free"
        )
        func(config)

    # =================================================================================
    # HTTP/3 Connection Functions
    # =================================================================================

    fn http3_conn_new(
        self, quic_conn: QuicConn, config: HTTP3Config
    ) -> HTTP3Conn:
        """Create an HTTP/3 connection using the given QUIC connection."""
        var func = self.handle.get_function[
            fn (QuicConn, HTTP3Config) -> HTTP3Conn
        ]("http3_conn_new")
        return func(quic_conn, config)

    fn http3_conn_free(self, conn: HTTP3Conn):
        """Destroy the HTTP/3 connection."""
        var func = self.handle.get_function[fn (HTTP3Conn) -> None](
            "http3_conn_free"
        )
        func(conn)

    fn http3_conn_set_events_handler(
        self,
        conn: HTTP3Conn,
        methods: UnsafePointer[HTTP3Methods],
        context: c_void_ptr,
    ):
        """Set HTTP/3 connection events handler."""
        var func = self.handle.get_function[
            fn (HTTP3Conn, UnsafePointer[HTTP3Methods], c_void_ptr) -> None
        ]("http3_conn_set_events_handler")
        func(conn, methods, context)

    fn http3_conn_process_streams(
        self, conn: HTTP3Conn, quic_conn: QuicConn
    ) -> c_int:
        """Process internal events of all streams of the specified HTTP/3 connection.
        """
        var func = self.handle.get_function[fn (HTTP3Conn, QuicConn) -> c_int](
            "http3_conn_process_streams"
        )
        return func(conn, quic_conn)

    fn http3_send_headers(
        self,
        conn: HTTP3Conn,
        quic_conn: QuicConn,
        stream_id: c_uint64,
        headers: UnsafePointer[HTTP3Header],
        headers_len: c_size_t,
        fin: c_bool,
    ) -> c_int:
        """Send HTTP/3 request or response headers on the given stream."""
        var func = self.handle.get_function[
            fn (
                HTTP3Conn,
                QuicConn,
                c_uint64,
                UnsafePointer[HTTP3Header],
                c_size_t,
                c_bool,
            ) -> c_int
        ]("http3_send_headers")
        return func(conn, quic_conn, stream_id, headers, headers_len, fin)

    fn http3_send_body(
        self,
        conn: HTTP3Conn,
        quic_conn: QuicConn,
        stream_id: c_uint64,
        body: UnsafePointer[UInt8],
        body_len: c_size_t,
        fin: c_bool,
    ) -> c_int64:
        """Send HTTP/3 request or response body on the given stream."""
        var func = self.handle.get_function[
            fn (
                HTTP3Conn,
                QuicConn,
                c_uint64,
                UnsafePointer[UInt8],
                c_size_t,
                c_bool,
            ) -> c_int64
        ]("http3_send_body")
        return func(conn, quic_conn, stream_id, body, body_len, fin)

    fn http3_recv_body(
        self,
        conn: HTTP3Conn,
        quic_conn: QuicConn,
        stream_id: c_uint64,
        output: UnsafePointer[UInt8],
        out_len: c_size_t,
    ) -> c_int64:
        """Read request/response body from the given stream."""
        var func = self.handle.get_function[
            fn (
                HTTP3Conn, QuicConn, c_uint64, UnsafePointer[UInt8], c_size_t
            ) -> c_int64
        ]("http3_recv_body")
        return func(conn, quic_conn, stream_id, output, out_len)

    fn http3_for_each_header(
        self,
        headers: HTTP3Headers,
        callback: UnsafePointer[NoneType],
        argp: c_void_ptr,
    ) -> c_int:
        """Process HTTP/3 headers."""
        var func = self.handle.get_function[
            fn (HTTP3Headers, UnsafePointer[NoneType], c_void_ptr) -> c_int
        ]("http3_for_each_header")
        return func(headers, callback, argp)

    # =================================================================================
    # Logging Functions
    # =================================================================================

    fn quic_set_logger(
        self,
        callback: UnsafePointer[NoneType],
        argp: c_void_ptr,
        level: UnsafePointer[c_char],
    ):
        """Set logger callback."""
        var func = self.handle.get_function[
            fn (
                UnsafePointer[NoneType], c_void_ptr, UnsafePointer[c_char]
            ) -> None
        ]("quic_set_logger")
        func(callback, argp, level)
