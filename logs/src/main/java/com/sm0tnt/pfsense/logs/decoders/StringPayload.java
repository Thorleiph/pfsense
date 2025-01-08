package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class StringPayload implements RSysLogPayload {
	private String payload;

	/**
	 * Constructor.
	 * 
	 * @param payload The payload.
	 */
	public StringPayload(String payload) {
		this.payload = payload;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		n.put(RSysLogMessage.PAYLOAD, this.payload);

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		return this.payload;
	}
}
