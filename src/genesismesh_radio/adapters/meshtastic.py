"""Private application packets through an existing Meshtastic serial radio."""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Any

from .base import (
    AdapterError,
    Inbound,
    QueuedTransport,
    validate_budget,
    validate_command_id,
    validate_payload,
)

_NODE = re.compile(r"![0-9a-fA-F]{8}\Z")


def normalize_node(value: str) -> str:
    if not isinstance(value, str) or not _NODE.fullmatch(value):
        raise AdapterError("invalid_meshtastic_node")
    if value.lower() in {"!00000000", "!ffffffff"}:
        raise AdapterError("invalid_meshtastic_node")
    return value.lower()


def parse_meshtastic_packet(
    packet: dict[str, Any],
    *,
    nodes: Collection[str],
    channel: int = 0,
    app_port: int = 256,
    max_payload: int = 51,
) -> Inbound:
    """Parse routing metadata, not application authentication."""
    if not isinstance(packet, dict) or packet.get("channel", 0) != channel:
        raise AdapterError("meshtastic_channel_mismatch")
    source = packet.get("from")
    if type(source) is not int or not 0 < source < 0xFFFFFFFF:
        raise AdapterError("invalid_meshtastic_source")
    route = f"!{source:08x}"
    if route not in nodes:
        raise AdapterError("unconfigured_meshtastic_source")
    from_id = packet.get("fromId")
    if from_id is not None and normalize_node(from_id) != route:
        raise AdapterError("meshtastic_source_mismatch")
    decoded = packet.get("decoded")
    if not isinstance(decoded, dict):
        raise AdapterError("meshtastic_payload_not_decoded")
    port = decoded.get("portnum")
    if port == "PRIVATE_APP":
        port = 256
    if type(port) is not int or port != app_port:
        raise AdapterError("meshtastic_port_mismatch")
    payload = validate_payload(decoded.get("payload"), max_payload)
    return Inbound(route, payload)


class MeshtasticTransport(QueuedTransport):
    def __init__(
        self,
        port: str,
        *,
        nodes: Collection[str],
        channel: int = 0,
        app_port: int = 256,
        max_payload: int = 51,
        queue_size: int = 128,
        interface: Any = None,
        pubsub: Any = None,
    ) -> None:
        super().__init__(queue_size)
        self.nodes = frozenset(normalize_node(node) for node in nodes)
        if not self.nodes:
            raise AdapterError("meshtastic_nodes_required")
        if type(channel) is not int or not 0 <= channel <= 7:
            raise AdapterError("invalid_meshtastic_channel")
        if type(app_port) is not int or not 256 <= app_port <= 511:
            raise AdapterError("private_meshtastic_port_required")
        if not isinstance(port, str) or not port:
            raise AdapterError("serial_port_required")
        self.channel = channel
        self.app_port = app_port
        self.max_payload = validate_budget(max_payload, 200)
        if pubsub is None:
            from pubsub import pub

            pubsub = pub
        self._pubsub = pubsub
        self.interface = interface
        self._pubsub.subscribe(self._on_receive, "meshtastic.receive")
        try:
            if self.interface is None:
                from meshtastic.serial_interface import SerialInterface

                self.interface = SerialInterface(devPath=port)
        except Exception:
            self._pubsub.unsubscribe(self._on_receive, "meshtastic.receive")
            raise

    def _on_receive(self, packet: dict[str, Any], interface: Any) -> None:
        if self.closed or interface is not self.interface:
            return
        try:
            inbound = parse_meshtastic_packet(
                packet,
                nodes=self.nodes,
                channel=self.channel,
                app_port=self.app_port,
                max_payload=self.max_payload,
            )
        except (AdapterError, TypeError):
            self.rejected_count += 1
            return
        self._offer(inbound)

    def send(self, route: str, payload: bytes, command_id: str) -> str:
        if self.closed:
            raise AdapterError("transport_closed")
        route = normalize_node(route)
        if route not in self.nodes:
            raise AdapterError("unconfigured_meshtastic_destination")
        validate_command_id(command_id)
        validate_payload(payload, self.max_payload)
        try:
            packet = self.interface.sendData(
                payload,
                destinationId=route,
                portNum=self.app_port,
                channelIndex=self.channel,
                wantAck=True,
                wantResponse=False,
            )
            packet_id = packet.id
        except Exception as exc:
            raise AdapterError("meshtastic_send_ambiguous") from exc
        return f"meshtastic:{packet_id}"

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._pubsub.unsubscribe(self._on_receive, "meshtastic.receive")
            self.interface.close()
