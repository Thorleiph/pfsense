package com.sm0tnt.pfsense.logs.decoders;

import java.util.ArrayList;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class FilterLogStack extends ArrayList<FilterLog> implements RSysLogPayload {
	private static final long serialVersionUID = 4715633971376861745L;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		for (FilterLog fl : this)
			fl.toObjectNode(n);

		return n;
	}
}
