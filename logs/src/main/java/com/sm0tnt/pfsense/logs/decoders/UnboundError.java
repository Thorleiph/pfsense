package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.node.ObjectNode;

public class UnboundError extends UnboundMessage {
	private String errorType;
	private String xx;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		return getObjectNode();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return super.toString();
	}
}
