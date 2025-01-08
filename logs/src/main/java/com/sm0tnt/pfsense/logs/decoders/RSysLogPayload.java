package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.node.ObjectNode;

public interface RSysLogPayload {

	/**
	 * @param n The ObjectNode to add data to. If none provided the function should create a new ObjectNode and add data to that.
	 * @return the provided ObjectNode or a newly created one.
	 */
	public ObjectNode toObjectNode(ObjectNode n);

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString();
}
